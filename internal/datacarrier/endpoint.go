package datacarrier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// DataCarrierALPN is negotiated by both real carrier transports. TLS
// certificate and peer-identity validation remains the caller's trust
// boundary, but this package rejects configurations that do not authenticate
// both sides.
const DataCarrierALPN = "paperboat.connector.v1"

var (
	ErrInvalidEndpoint = errors.New("invalid data carrier endpoint configuration")
	ErrCarrierTLS      = errors.New("data carrier TLS authentication failed")
)

const maxTCPHandshakeWorkers = 8

// PeerBinding maps the verified peer certificate to the exact connector-v1
// control-session identity. A trusted certificate by itself cannot claim a
// different account, host, tunnel, or generation.
type PeerBinding func(tls.ConnectionState) (Identity, error)

// EndpointConfig describes a listener address and its mutual-TLS policy.
// TLS 1.3 is required. A caller may use normal RootCAs/ClientCAs validation or
// an explicit VerifyConnection/VerifyPeerCertificate policy.
type EndpointConfig struct {
	Address     string
	TLS         *tls.Config
	PeerBinding PeerBinding
}

func (e EndpointConfig) validateServer() error {
	if strings.TrimSpace(e.Address) == "" || e.TLS == nil || e.PeerBinding == nil {
		return ErrInvalidEndpoint
	}
	if err := validateEndpointTLS(e.TLS, true); err != nil {
		return err
	}
	return nil
}

func validateEndpointTLS(base *tls.Config, server bool) error {
	if base == nil {
		return ErrInvalidEndpoint
	}
	config := base.Clone()
	if config.MinVersion != 0 && config.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("%w: TLS 1.3 or newer is required", ErrCarrierTLS)
	}
	if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return fmt.Errorf("%w: TLS 1.3 is required", ErrCarrierTLS)
	}
	if !server {
		if len(config.Certificates) == 0 && config.GetClientCertificate == nil {
			return fmt.Errorf("%w: client certificate is required", ErrCarrierTLS)
		}
		if config.InsecureSkipVerify && config.VerifyConnection == nil && config.VerifyPeerCertificate == nil {
			return fmt.Errorf("%w: insecure server verification is not allowed", ErrCarrierTLS)
		}
		return nil
	}
	if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return fmt.Errorf("%w: server certificate is required", ErrCarrierTLS)
	}
	if config.ClientAuth < tls.RequireAnyClientCert || config.ClientAuth == tls.VerifyClientCertIfGiven {
		return fmt.Errorf("%w: mutual client authentication is required", ErrCarrierTLS)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert && config.VerifyConnection == nil && config.VerifyPeerCertificate == nil {
		return fmt.Errorf("%w: client certificate verification is required", ErrCarrierTLS)
	}
	return nil
}

func serverTLSConfig(base *tls.Config) (*tls.Config, error) {
	if err := validateEndpointTLS(base, true); err != nil {
		return nil, err
	}
	config := base.Clone()
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS13
	}
	config.NextProtos = appendEndpointALPN(config.NextProtos)
	return config, nil
}

func appendEndpointALPN(protocols []string) []string {
	_ = protocols
	return []string{DataCarrierALPN}
}

func bindEndpointPeer(endpoint EndpointConfig, state tls.ConnectionState) (Identity, error) {
	if endpoint.PeerBinding == nil {
		return Identity{}, fmt.Errorf("%w: peer binding is required", ErrCarrierTLS)
	}
	identity, err := endpoint.PeerBinding(state)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: peer binding rejected: %v", ErrCarrierTLS, err)
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, fmt.Errorf("%w: peer binding returned invalid identity", ErrCarrierTLS)
	}
	return identity, nil
}

// TCPMuxListener accepts mutually authenticated TLS TCP carrier sessions.
// Each accepted connection gets one yamux-backed datacarrier.Server.
type TCPMuxListener struct {
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
	tls      *tls.Config
	endpoint EndpointConfig
	config   Config
	done     chan struct{}
	accepted chan *Server
	workers  chan struct{}
	once     sync.Once
	closeErr error
}

func ListenTCPMux(ctx context.Context, endpoint EndpointConfig, config Config) (*TCPMuxListener, error) {
	if ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	config = config.withDefaults()
	if err := config.validateListener(); err != nil {
		return nil, err
	}
	if err := endpoint.validateServer(); err != nil {
		return nil, err
	}
	tlsConfig, err := serverTLSConfig(endpoint.TLS)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.Address) == "" {
		return nil, ErrInvalidEndpoint
	}
	listener, err := net.Listen("tcp", endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: TCP listener: %v", ErrInvalidEndpoint, err)
	}
	listenerContext, cancel := context.WithCancel(ctx)
	workerCount := config.QueueDepth
	if workerCount > maxTCPHandshakeWorkers {
		workerCount = maxTCPHandshakeWorkers
	}
	result := &TCPMuxListener{ctx: listenerContext, cancel: cancel, listener: listener, tls: tlsConfig, endpoint: endpoint, config: config, done: make(chan struct{}), accepted: make(chan *Server, config.QueueDepth), workers: make(chan struct{}, workerCount)}
	go result.watch()
	go result.serve()
	return result, nil
}

func (l *TCPMuxListener) watch() {
	select {
	case <-l.ctx.Done():
		_ = l.Close()
	case <-l.done:
	}
}

func (l *TCPMuxListener) serve() {
	for {
		select {
		case l.workers <- struct{}{}:
		case <-l.done:
			return
		}
		connection, err := l.listener.Accept()
		if err != nil {
			<-l.workers
			if l.closed() {
				return
			}
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			_ = l.Close()
			return
		}
		go l.handshake(connection)
	}
}

func (l *TCPMuxListener) handshake(connection net.Conn) {
	defer func() { <-l.workers }()
	tlsConnection := tls.Server(connection, l.tls)
	handshakeContext, cancel := context.WithTimeout(l.ctx, l.config.ConnectionWriteLimit)
	err := tlsConnection.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		_ = connection.Close()
		return
	}
	state := tlsConnection.ConnectionState()
	if state.NegotiatedProtocol != DataCarrierALPN {
		_ = connection.Close()
		return
	}
	identity, err := bindEndpointPeer(l.endpoint, state)
	if err != nil || l.config.Identity != (Identity{}) && identity != l.config.Identity {
		_ = connection.Close()
		return
	}
	serverConfig := l.config
	serverConfig.Identity = identity
	server, err := NewServer(l.ctx, tlsConnection, serverConfig)
	if err != nil {
		_ = connection.Close()
		return
	}
	select {
	case l.accepted <- server:
	case <-l.done:
		_ = server.Close()
	}
}

// Accept waits for one TLS handshake and returns its edge carrier server.
func (l *TCPMuxListener) Accept(ctx context.Context) (*Server, error) {
	if l == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case server := <-l.accepted:
		if server == nil {
			return nil, ErrCarrierClosed
		}
		return server, nil
	case <-l.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *TCPMuxListener) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

func (l *TCPMuxListener) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		close(l.done)
		l.cancel()
		l.closeErr = l.listener.Close()
	})
	return l.closeErr
}

func (l *TCPMuxListener) closed() bool {
	if l == nil || l.done == nil {
		return true
	}
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// QUICListener accepts mutually authenticated QUIC connections. Every QUIC
// bidirectional stream belongs directly to one transport-native Session and
// is therefore independently flow-controlled by QUIC.
type QUICListener struct {
	ctx      context.Context
	cancel   context.CancelFunc
	listener *quic.Listener
	config   Config
	endpoint EndpointConfig
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func ListenQUIC(ctx context.Context, endpoint EndpointConfig, config Config) (*QUICListener, error) {
	if ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	config = config.withDefaults()
	if err := config.validateListener(); err != nil {
		return nil, err
	}
	if err := endpoint.validateServer(); err != nil {
		return nil, err
	}
	tlsConfig, err := serverTLSConfig(endpoint.TLS)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpoint.Address) == "" {
		return nil, ErrInvalidEndpoint
	}
	listener, err := quic.ListenAddr(endpoint.Address, tlsConfig, endpointQUICConfig(config))
	if err != nil {
		return nil, fmt.Errorf("%w: QUIC listener: %v", ErrInvalidEndpoint, err)
	}
	listenerContext, cancel := context.WithCancel(ctx)
	result := &QUICListener{ctx: listenerContext, cancel: cancel, listener: listener, endpoint: endpoint, config: config, done: make(chan struct{})}
	go result.watch()
	return result, nil
}

func (l *QUICListener) watch() {
	select {
	case <-l.ctx.Done():
		_ = l.Close()
	case <-l.done:
	}
}

// Accept waits for one authenticated QUIC connection and creates its edge
// carrier. The returned Server opens native QUIC streams for edge requests.
func (l *QUICListener) Accept(ctx context.Context) (*Server, error) {
	if l == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	if l.closed() {
		return nil, ErrCarrierClosed
	}
	connection, err := l.listener.Accept(ctx)
	if err != nil {
		if l.closed() {
			return nil, ErrCarrierClosed
		}
		return nil, err
	}
	session := newQUICSession(connection)
	state := connection.ConnectionState().TLS
	if state.NegotiatedProtocol != DataCarrierALPN {
		_ = session.Close()
		return nil, ErrCarrierTLS
	}
	identity, err := bindEndpointPeer(l.endpoint, state)
	if err != nil || l.config.Identity != (Identity{}) && identity != l.config.Identity {
		_ = session.Close()
		return nil, ErrCarrierTLS
	}
	serverConfig := l.config
	serverConfig.Identity = identity
	server, err := NewServerWithSession(l.ctx, session, serverConfig)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return server, nil
}

func (l *QUICListener) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

func (l *QUICListener) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		close(l.done)
		l.cancel()
		l.closeErr = l.listener.Close()
	})
	return l.closeErr
}

func (l *QUICListener) closed() bool {
	if l == nil || l.done == nil {
		return true
	}
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func endpointQUICConfig(config Config) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 2 * time.Minute,
		KeepAlivePeriod:                config.KeepAliveInterval,
		MaxIncomingStreams:             int64(config.MaximumStreams + config.QueueDepth + 1),
		MaxIncomingUniStreams:          -1,
		InitialStreamReceiveWindow:     uint64(config.StreamWindow),
		MaxStreamReceiveWindow:         uint64(config.StreamWindow),
		InitialConnectionReceiveWindow: uint64(config.StreamWindow) * uint64(config.MaximumStreams+config.QueueDepth+1),
		MaxConnectionReceiveWindow:     uint64(config.StreamWindow) * uint64(config.MaximumStreams+config.QueueDepth+1),
	}
}

type quicSession struct {
	connection *quic.Conn
	done       chan struct{}
	doneOnce   sync.Once
	closeOnce  sync.Once
	closeErr   error
}

func newQUICSession(connection *quic.Conn) Session {
	session := &quicSession{connection: connection, done: make(chan struct{})}
	go func() {
		<-connection.Context().Done()
		session.signalDone()
	}()
	return session
}

func (s *quicSession) OpenStream(ctx context.Context) (StreamLink, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	stream, err := s.connection.OpenStreamSync(ctx)
	if err != nil {
		if s.closed() {
			return nil, ErrCarrierClosed
		}
		return nil, err
	}
	return &quicStreamLink{Stream: stream}, nil
}

func (s *quicSession) AcceptStream(ctx context.Context) (StreamLink, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	stream, err := s.connection.AcceptStream(ctx)
	if err != nil {
		if s.closed() {
			return nil, ErrCarrierClosed
		}
		return nil, err
	}
	return &quicStreamLink{Stream: stream}, nil
}

func (s *quicSession) Ping(ctx context.Context) error {
	if s == nil || s.connection == nil || ctx == nil {
		return ErrInvalidEndpoint
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrCarrierClosed
	case <-s.connection.HandshakeComplete():
		return nil
	case <-s.connection.Context().Done():
		return ErrCarrierClosed
	}
}

func (s *quicSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.signalDone()
		if s.connection != nil {
			s.closeErr = s.connection.CloseWithError(0, "carrier closed")
		}
	})
	return s.closeErr
}

func (s *quicSession) CloseChan() <-chan struct{} {
	if s == nil {
		return closedChannel()
	}
	return s.done
}

func (s *quicSession) signalDone() {
	if s == nil {
		return
	}
	s.doneOnce.Do(func() { close(s.done) })
}

func (s *quicSession) closed() bool {
	if s == nil || s.done == nil {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

type quicStreamLink struct {
	*quic.Stream
}

func (s *quicStreamLink) StreamID() uint32 {
	if s == nil || s.Stream == nil {
		return 0
	}
	return uint32(s.Stream.StreamID())
}
