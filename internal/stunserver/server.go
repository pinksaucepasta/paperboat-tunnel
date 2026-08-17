// Package stunserver owns the public Paperboat STUN binding service.
package stunserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/relaypmtu"
	"github.com/pion/stun/v3"
)

var ErrInvalid = errors.New("invalid STUN server configuration")

const stunHeaderSize = 20

type Config struct {
	Address                 string
	MaximumPacket           int
	Burst                   float64
	RequestsPerSecond       float64
	GlobalBurst             float64
	GlobalRequestsPerSecond float64
	MaximumSources          int
	SourceTTL               time.Duration
	WriteTimeout            time.Duration
	ListenPacket            func(context.Context, string, string) (net.PacketConn, error)
	Now                     func() time.Time
	AuthenticatePMTU        func(string, netip.AddrPort) bool
}

type Stats struct {
	Running  bool
	Accepted uint64
	Rejected uint64
	Errors   uint64
	Sources  int
}

type sourceBucket struct {
	tokens float64
	last   time.Time
}

type Server struct {
	config Config

	mu         sync.Mutex
	conn       net.PacketConn
	done       chan error
	finished   chan struct{}
	running    bool
	closed     bool
	sources    map[netip.Addr]sourceBucket
	global     sourceBucket
	stats      Stats
	finishOnce sync.Once
}

func New(config Config) (*Server, error) {
	if config.MaximumPacket == 0 {
		config.MaximumPacket = relaypmtu.MaximumSize
	}
	if config.Burst == 0 {
		config.Burst = 64
	}
	if config.RequestsPerSecond == 0 {
		config.RequestsPerSecond = 10
	}
	if config.GlobalBurst == 0 {
		config.GlobalBurst = 2000
	}
	if config.GlobalRequestsPerSecond == 0 {
		config.GlobalRequestsPerSecond = 1000
	}
	if config.MaximumSources == 0 {
		config.MaximumSources = 4096
	}
	if config.SourceTTL == 0 {
		config.SourceTTL = 5 * time.Minute
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = time.Second
	}
	if config.ListenPacket == nil {
		listener := net.ListenConfig{}
		config.ListenPacket = listener.ListenPacket
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Address == "" || config.MaximumPacket < stunHeaderSize || config.MaximumPacket > 64<<10 || config.Burst < 1 || config.RequestsPerSecond <= 0 || config.GlobalBurst < 1 || config.GlobalRequestsPerSecond <= 0 || config.MaximumSources < 1 || config.SourceTTL <= 0 || config.WriteTimeout <= 0 {
		return nil, ErrInvalid
	}
	return &Server{config: config, done: make(chan error, 1), finished: make(chan struct{}), sources: make(map[netip.Addr]sourceBucket)}, nil
}

func (s *Server) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.closed {
		return ErrInvalid
	}
	conn, err := s.config.ListenPacket(ctx, "udp", s.config.Address)
	if err != nil {
		return fmt.Errorf("open STUN listener: %w", err)
	}
	s.conn = conn
	s.running = true
	s.stats.Running = true
	go s.serve(conn)
	return nil
}

func (s *Server) Done() <-chan error {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	first := !s.closed
	s.closed = true
	conn := s.conn
	s.mu.Unlock()
	var closeErr error
	if first && conn != nil {
		closeErr = conn.Close()
	} else if conn == nil {
		s.closeFinished()
	}
	select {
	case <-s.finished:
		return closeErr
	case <-ctx.Done():
		return errors.Join(closeErr, ctx.Err())
	}
}

func (s *Server) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.stats
	result.Sources = len(s.sources)
	return result
}

func (s *Server) serve(conn net.PacketConn) {
	defer conn.Close()
	defer s.closeFinished()
	buffer := make([]byte, s.config.MaximumPacket+1)
	for {
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.finish(nil)
				return
			}
			s.finish(fmt.Errorf("read STUN datagram: %w", err))
			return
		}
		if n > s.config.MaximumPacket || !s.handle(conn, buffer[:n], remote) {
			s.recordRejected()
		}
	}
}

func (s *Server) closeFinished() {
	s.finishOnce.Do(func() { close(s.finished) })
}

func (s *Server) handle(conn net.PacketConn, raw []byte, remote net.Addr) bool {
	if s == nil || conn == nil {
		return false
	}
	address, ok := remoteAddress(remote)
	if !ok || !s.allow(address.Addr()) {
		return false
	}
	if len(raw) < stunHeaderSize || len(raw) > s.config.MaximumPacket {
		return false
	}
	if relaypmtu.IsRequest(raw) {
		return s.handlePMTU(conn, raw, remote, address)
	}
	attributeLength := int(binary.BigEndian.Uint16(raw[2:4]))
	if attributeLength%4 != 0 || stunHeaderSize+attributeLength != len(raw) {
		return false
	}
	message := &stun.Message{Raw: raw}
	if err := message.Decode(); err != nil || message.Type != stun.BindingRequest {
		return false
	}
	if _, err := message.Get(stun.AttrFingerprint); err == nil && stun.Fingerprint.Check(message) != nil {
		return false
	}
	response, err := stun.Build(
		stun.NewTransactionIDSetter(message.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.IP(address.Addr().AsSlice()), Port: int(address.Port())},
		stun.Fingerprint,
	)
	if err != nil || len(response.Raw) > len(raw)*3 {
		s.recordError()
		return false
	}
	if err := conn.SetWriteDeadline(s.config.Now().Add(s.config.WriteTimeout)); err != nil {
		s.recordError()
		return false
	}
	if _, err := conn.WriteTo(response.Raw, remote); err != nil {
		s.recordError()
		return false
	}
	s.mu.Lock()
	s.stats.Accepted++
	s.mu.Unlock()
	return true
}

func (s *Server) handlePMTU(conn net.PacketConn, raw []byte, remote net.Addr, address netip.AddrPort) bool {
	if s.config.AuthenticatePMTU == nil {
		return false
	}
	response, err := relaypmtu.Handle(raw, func(token string) bool {
		return s.config.AuthenticatePMTU(token, address)
	})
	if err != nil {
		return false
	}
	if err := conn.SetWriteDeadline(s.config.Now().Add(s.config.WriteTimeout)); err != nil {
		s.recordError()
		return false
	}
	if _, err := conn.WriteTo(response, remote); err != nil {
		s.recordError()
		return false
	}
	s.mu.Lock()
	s.stats.Accepted++
	s.mu.Unlock()
	return true
}

func (s *Server) allow(address netip.Addr) bool {
	now := s.config.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !takeToken(&s.global, now, s.config.GlobalBurst, s.config.GlobalRequestsPerSecond) {
		return false
	}
	if len(s.sources) >= s.config.MaximumSources {
		for key, bucket := range s.sources {
			if now.Sub(bucket.last) >= s.config.SourceTTL {
				delete(s.sources, key)
			}
		}
	}
	bucket, exists := s.sources[address]
	if !exists {
		if len(s.sources) >= s.config.MaximumSources {
			for key := range s.sources {
				delete(s.sources, key)
				break
			}
		}
		bucket = sourceBucket{tokens: s.config.Burst, last: now}
	}
	if !takeToken(&bucket, now, s.config.Burst, s.config.RequestsPerSecond) {
		s.sources[address] = bucket
		return false
	}
	s.sources[address] = bucket
	return true
}

func takeToken(bucket *sourceBucket, now time.Time, burst, rate float64) bool {
	if bucket.last.IsZero() {
		bucket.tokens = burst
		bucket.last = now
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens = min(burst, bucket.tokens+elapsed*rate)
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (s *Server) recordRejected() {
	s.mu.Lock()
	s.stats.Rejected++
	s.mu.Unlock()
}

func (s *Server) recordError() {
	s.mu.Lock()
	s.stats.Errors++
	s.mu.Unlock()
}

func (s *Server) finish(err error) {
	s.mu.Lock()
	s.running = false
	s.stats.Running = false
	s.mu.Unlock()
	select {
	case s.done <- err:
	default:
	}
}

func remoteAddress(value net.Addr) (netip.AddrPort, bool) {
	udp, ok := value.(*net.UDPAddr)
	if !ok || udp == nil || udp.Port < 1 || udp.Port > 65535 {
		return netip.AddrPort{}, false
	}
	address, ok := netip.AddrFromSlice(udp.IP)
	if !ok || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(address.Unmap(), uint16(udp.Port)), true
}
