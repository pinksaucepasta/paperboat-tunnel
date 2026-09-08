// Package datacarrier owns the edge half of the connector-v1 data carrier.
// The edge opens streams on an outbound host carrier. The connector-v1
// StreamOpen preface is written before any application byte and is checked by
// the connector against its authenticated control-session identity.
package datacarrier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

const (
	defaultMaximumStreams    = 64
	defaultAcceptBacklog     = 16
	defaultQueueDepth        = 16
	defaultStreamWindow      = 256 << 10
	defaultKeepAliveInterval = 30 * time.Second
	defaultWriteLimit        = 10 * time.Second
	defaultOpenLimit         = 10 * time.Second
	defaultCloseLimit        = 5 * time.Second
	maxMaximumStreams        = 1024
	maxAcceptBacklog         = 1024
	maxQueueDepth            = 1024
	maxStreamWindow          = 16 << 20
	maxOperationTimeout      = time.Minute
)

var (
	ErrInvalidConfig     = errors.New("invalid data carrier configuration")
	ErrCarrierClosed     = errors.New("data carrier closed")
	ErrStreamLimit       = errors.New("data carrier stream limit reached")
	ErrCarrierOverloaded = errors.New("data carrier overloaded")
	ErrIdentityMismatch  = errors.New("data carrier stream identity mismatch")
	ErrRouteDenied       = errors.New("data carrier route denied")
	ErrInvalidPreface    = errors.New("invalid data carrier stream preface")
	ErrRequestInUse      = errors.New("data carrier request already in use")
)

// StreamOpen is the canonical connector-v1 stream-open preface. It contains
// no bearer or reusable credential bytes.
type StreamOpen = connectorprotocol.StreamOpen

// Identity is copied from the authenticated connector-v1 control session.
// Every data stream must repeat this exact identity in its StreamOpen preface.
type Identity struct {
	AccountID         string
	HostID            string
	TunnelID          string
	ConnectorID       string
	SessionID         string
	ProcessGeneration uint64
	Generation        uint64
}

func (i Identity) Validate() error {
	if connectorprotocol.ValidateIdentifier(i.AccountID) != nil || connectorprotocol.ValidateIdentifier(i.HostID) != nil || connectorprotocol.ValidateIdentifier(i.TunnelID) != nil || connectorprotocol.ValidateIdentifier(i.ConnectorID) != nil || connectorprotocol.ValidateIdentifier(i.SessionID) != nil || i.ProcessGeneration == 0 || i.Generation == 0 {
		return ErrInvalidConfig
	}
	return nil
}

func (i Identity) matches(open StreamOpen) bool {
	return open.AccountID == i.AccountID && open.TunnelID == i.TunnelID && open.ConnectorID == i.ConnectorID && open.SessionID == i.SessionID && open.ProcessGeneration == i.ProcessGeneration && open.Generation == i.Generation
}

type Authorizer interface {
	AuthorizeStream(context.Context, Identity, StreamOpen) error
}

type AuthorizerFunc func(context.Context, Identity, StreamOpen) error

func (f AuthorizerFunc) AuthorizeStream(ctx context.Context, identity Identity, open StreamOpen) error {
	return f(ctx, identity, open)
}

type Config struct {
	MaximumStreams       int
	AcceptBacklog        int
	QueueDepth           int
	StreamWindow         uint32
	KeepAliveInterval    time.Duration
	ConnectionWriteLimit time.Duration
	StreamOpenLimit      time.Duration
	StreamCloseLimit     time.Duration
	Identity             Identity
	Authorize            Authorizer
}

func DefaultConfig() Config {
	return Config{
		MaximumStreams:       defaultMaximumStreams,
		AcceptBacklog:        defaultAcceptBacklog,
		QueueDepth:           defaultQueueDepth,
		StreamWindow:         defaultStreamWindow,
		KeepAliveInterval:    defaultKeepAliveInterval,
		ConnectionWriteLimit: defaultWriteLimit,
		StreamOpenLimit:      defaultOpenLimit,
		StreamCloseLimit:     defaultCloseLimit,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.MaximumStreams == 0 {
		c.MaximumStreams = d.MaximumStreams
	}
	if c.AcceptBacklog == 0 {
		c.AcceptBacklog = d.AcceptBacklog
	}
	if c.QueueDepth == 0 {
		c.QueueDepth = d.QueueDepth
	}
	if c.StreamWindow == 0 {
		c.StreamWindow = d.StreamWindow
	}
	if c.KeepAliveInterval == 0 {
		c.KeepAliveInterval = d.KeepAliveInterval
	}
	if c.ConnectionWriteLimit == 0 {
		c.ConnectionWriteLimit = d.ConnectionWriteLimit
	}
	if c.StreamOpenLimit == 0 {
		c.StreamOpenLimit = d.StreamOpenLimit
	}
	if c.StreamCloseLimit == 0 {
		c.StreamCloseLimit = d.StreamCloseLimit
	}
	return c
}

func (c Config) Validate() error {
	return c.validate(false)
}

// validateListener validates the shared listener policy without requiring a
// single identity. Endpoint peer binding supplies the exact identity for each
// authenticated connection; a non-zero identity remains a supported
// single-connector restriction for callers that explicitly want it.
func (c Config) validateListener() error {
	return c.validate(true)
}

func (c Config) validate(allowUnboundIdentity bool) error {
	c = c.withDefaults()
	if c.MaximumStreams <= 0 || c.MaximumStreams > maxMaximumStreams {
		return fmt.Errorf("%w: maximum streams must be in [1,%d]", ErrInvalidConfig, maxMaximumStreams)
	}
	if c.AcceptBacklog <= 0 || c.AcceptBacklog > maxAcceptBacklog || c.AcceptBacklog > c.MaximumStreams {
		return fmt.Errorf("%w: accept backlog must be in [1,%d] and no greater than maximum streams", ErrInvalidConfig, maxAcceptBacklog)
	}
	if c.QueueDepth <= 0 || c.QueueDepth > maxQueueDepth {
		return fmt.Errorf("%w: queue depth must be in [1,%d]", ErrInvalidConfig, maxQueueDepth)
	}
	if c.StreamWindow < defaultStreamWindow || c.StreamWindow > maxStreamWindow {
		return fmt.Errorf("%w: stream window must be in [%d,%d]", ErrInvalidConfig, defaultStreamWindow, maxStreamWindow)
	}
	if c.KeepAliveInterval <= 0 || c.KeepAliveInterval > time.Hour || !validTimeout(c.ConnectionWriteLimit) || !validTimeout(c.StreamOpenLimit) || !validTimeout(c.StreamCloseLimit) {
		return fmt.Errorf("%w: transport timeout is outside the supported range", ErrInvalidConfig)
	}
	if c.Identity == (Identity{}) {
		if !allowUnboundIdentity {
			return fmt.Errorf("%w: authenticated identity is required", ErrInvalidConfig)
		}
	} else if err := c.Identity.Validate(); err != nil {
		return fmt.Errorf("%w: authenticated identity is invalid", ErrInvalidConfig)
	}
	if c.Authorize == nil {
		return fmt.Errorf("%w: route authorizer is required", ErrInvalidConfig)
	}
	return nil
}

func validTimeout(timeout time.Duration) bool {
	return timeout > 0 && timeout <= maxOperationTimeout
}

type acceptResult struct {
	stream *Stream
	open   StreamOpen
	err    error
}

// StreamLink is one admitted bounded byte stream. TCP links use yamux
// streams; QUIC links use native bidirectional streams directly.
type StreamLink interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Session is the transport-specific multiplexing boundary. It keeps the
// carrier API independent from the wire substrate while preserving bounded
// stream and lifecycle semantics.
type Session interface {
	OpenStream(context.Context) (StreamLink, error)
	AcceptStream(context.Context) (StreamLink, error)
	Ping(context.Context) error
	Close() error
	CloseChan() <-chan struct{}
}

// Server is the edge endpoint. It never accepts data streams from a host;
// the host's outbound carrier is the only session on which Server opens work.
type Server struct {
	ctx            context.Context
	cancel         context.CancelFunc
	session        Session
	config         Config
	permits        chan struct{}
	openings       chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
	closeErr       error
	active         atomic.Int64
	controlMu      sync.Mutex
	control        *Stream
	controlOpening bool
}

func NewServer(ctx context.Context, link io.ReadWriteCloser, config Config) (*Server, error) {
	if ctx == nil || link == nil {
		return nil, ErrInvalidConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	session, err := newYamuxSession(link, config, false)
	if err != nil {
		_ = link.Close()
		return nil, err
	}
	serverContext, cancel := context.WithCancel(ctx)
	server := &Server{ctx: serverContext, cancel: cancel, session: session, config: config, permits: make(chan struct{}, config.MaximumStreams), openings: make(chan struct{}, config.QueueDepth), done: make(chan struct{})}
	go server.watch()
	return server, nil
}

// NewServerWithSession constructs an edge server over a transport-native
// session, such as a QUIC connection.
func NewServerWithSession(ctx context.Context, session Session, config Config) (*Server, error) {
	if ctx == nil || session == nil {
		return nil, ErrInvalidConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	serverContext, cancel := context.WithCancel(ctx)
	server := &Server{ctx: serverContext, cancel: cancel, session: session, config: config, permits: make(chan struct{}, config.MaximumStreams), openings: make(chan struct{}, config.QueueDepth), done: make(chan struct{})}
	go server.watch()
	return server, nil
}

func (s *Server) watch() {
	select {
	case <-s.ctx.Done():
		s.shutdown(s.ctx.Err())
	case <-s.session.CloseChan():
		s.shutdown(ErrCarrierClosed)
	}
}

func (s *Server) OpenStream(ctx context.Context, open StreamOpen) (*Stream, error) {
	return s.OpenStreamWithLifetime(ctx, ctx, open)
}

// OpenStreamWithLifetime bounds admission and stream creation with openCtx,
// while lifetimeCtx owns the established stream. This prevents an open
// timeout from canceling a successfully returned streaming response.
func (s *Server) OpenStreamWithLifetime(openCtx, lifetimeCtx context.Context, open StreamOpen) (*Stream, error) {
	if s == nil || openCtx == nil || lifetimeCtx == nil {
		return nil, ErrInvalidConfig
	}
	if err := open.Validate(); err != nil {
		return nil, ErrInvalidPreface
	}
	if !s.config.Identity.matches(open) {
		return nil, ErrIdentityMismatch
	}
	if err := s.config.Authorize.AuthorizeStream(openCtx, s.config.Identity, open); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRouteDenied, err)
	}
	raw, err := s.openRaw(openCtx)
	if err != nil {
		return nil, err
	}
	if err := writeStreamOpen(openCtx, raw, open, s.config.StreamOpenLimit); err != nil {
		_ = raw.Close()
		s.releasePermit()
		return nil, err
	}
	stream := wrapStream(raw, lifetimeCtx, s.releasePermit, open)
	return stream, nil
}

// OpenControlStream reserves a stream for connector-v1 control frames. The
// control protocol owns its framing and therefore does not use StreamOpen.
func (s *Server) OpenControlStream(ctx context.Context) (*Stream, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	raw, err := s.openRaw(ctx)
	if err != nil {
		return nil, err
	}
	return wrapStream(raw, ctx, s.releasePermit), nil
}

// AcceptControlStream accepts the one host-originated connector-v1 control
// stream. Control frames are already authenticated by the carrier's mutual
// TLS/QUIC session, so this stream intentionally has no data-stream preface.
// A second control stream is rejected until the first one is closed.
func (s *Server) AcceptControlStream(ctx context.Context) (*Stream, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	s.controlMu.Lock()
	if s.control != nil || s.controlOpening {
		s.controlMu.Unlock()
		return nil, ErrStreamLimit
	}
	s.controlOpening = true
	s.controlMu.Unlock()
	raw, err := s.acceptRaw(ctx)
	if err != nil {
		s.controlMu.Lock()
		s.controlOpening = false
		s.controlMu.Unlock()
		return nil, err
	}
	control := wrapStream(raw, ctx, s.clearControl)
	s.controlMu.Lock()
	if s.closed() || s.control != nil {
		s.controlOpening = false
		s.controlMu.Unlock()
		_ = control.Close()
		return nil, ErrCarrierClosed
	}
	s.control = control
	s.controlOpening = false
	s.controlMu.Unlock()
	return control, nil
}

func (s *Server) acceptRaw(ctx context.Context) (StreamLink, error) {
	if s.closed() {
		return nil, ErrCarrierClosed
	}
	select {
	case s.permits <- struct{}{}:
		s.active.Add(1)
	case <-s.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrStreamLimit
	}
	result := make(chan openResult, 1)
	go func() {
		raw, err := s.session.AcceptStream(ctx)
		result <- openResult{stream: raw, err: err}
	}()
	select {
	case accepted := <-result:
		if accepted.err != nil {
			s.releasePermit()
			if s.closed() {
				return nil, ErrCarrierClosed
			}
			return nil, accepted.err
		}
		if err := ctx.Err(); err != nil {
			_ = accepted.stream.Close()
			s.releasePermit()
			return nil, err
		}
		return accepted.stream, nil
	case <-s.done:
		go s.finishCanceledAccept(result)
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		go s.finishCanceledAccept(result)
		return nil, ctx.Err()
	}
}

func (s *Server) finishCanceledAccept(result <-chan openResult) {
	accepted := <-result
	if accepted.stream != nil {
		_ = accepted.stream.Close()
	}
	s.releasePermit()
}

func (s *Server) clearControl() {
	s.controlMu.Lock()
	s.control = nil
	s.controlMu.Unlock()
}

func (s *Server) openRaw(ctx context.Context) (StreamLink, error) {
	if s.closed() {
		return nil, ErrCarrierClosed
	}
	select {
	case s.permits <- struct{}{}:
		s.active.Add(1)
	case <-s.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrStreamLimit
	}
	select {
	case s.openings <- struct{}{}:
	case <-s.done:
		s.releasePermit()
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		s.releasePermit()
		return nil, ctx.Err()
	}
	result := make(chan openResult, 1)
	go func() {
		raw, err := s.session.OpenStream(ctx)
		result <- openResult{stream: raw, err: err}
	}()
	select {
	case opened := <-result:
		<-s.openings
		if opened.err != nil {
			s.releasePermit()
			if s.closed() {
				return nil, ErrCarrierClosed
			}
			return nil, opened.err
		}
		if err := ctx.Err(); err != nil {
			_ = opened.stream.Close()
			s.releasePermit()
			return nil, err
		}
		return opened.stream, nil
	case <-s.done:
		go s.finishCanceledOpen(result)
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		go s.finishCanceledOpen(result)
		return nil, ctx.Err()
	}
}

type openResult struct {
	stream StreamLink
	err    error
}

func (s *Server) finishCanceledOpen(result <-chan openResult) {
	opened := <-result
	<-s.openings
	if opened.stream != nil {
		_ = opened.stream.Close()
	}
	s.releasePermit()
}

func (s *Server) Ping(ctx context.Context) error {
	if s == nil || s.session == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if s.closed() {
		return ErrCarrierClosed
	}
	err := s.session.Ping(ctx)
	if err != nil && s.closed() {
		return ErrCarrierClosed
	}
	return err
}

func (s *Server) ActiveStreams() int {
	if s == nil || s.closed() {
		return 0
	}
	active := s.active.Load()
	if active <= 0 {
		return 0
	}
	return int(active)
}

func (s *Server) Done() <-chan struct{} {
	if s == nil {
		return closedChannel()
	}
	return s.done
}

func (s *Server) releasePermit() {
	if s == nil {
		return
	}
	s.active.Add(-1)
	select {
	case <-s.permits:
	default:
	}
}

func (s *Server) shutdown(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.done)
		s.cancel()
		_ = s.session.Close()
	})
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.shutdown(nil)
	return s.closeErr
}

func (s *Server) closed() bool {
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

// Client is the host-facing endpoint used by tests and by a connector
// integration. The host accepts edge-opened streams and validates their
// canonical preface before returning them.
type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	session   Session
	config    Config
	permits   chan struct{}
	openings  chan struct{}
	accepted  chan acceptResult
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	active    atomic.Int64
	mu        sync.Mutex
	requests  map[string]struct{}
}

func NewClient(ctx context.Context, link io.ReadWriteCloser, config Config) (*Client, error) {
	if ctx == nil || link == nil {
		return nil, ErrInvalidConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	session, err := newYamuxSession(link, config, true)
	if err != nil {
		_ = link.Close()
		return nil, err
	}
	clientContext, cancel := context.WithCancel(ctx)
	client := &Client{ctx: clientContext, cancel: cancel, session: session, config: config, permits: make(chan struct{}, config.MaximumStreams), openings: make(chan struct{}, config.QueueDepth), accepted: make(chan acceptResult, config.QueueDepth), done: make(chan struct{}), requests: make(map[string]struct{})}
	go client.watch()
	go client.acceptLoop()
	return client, nil
}

// NewClientWithSession constructs a host-facing client over a
// transport-native session, such as a QUIC connection.
func NewClientWithSession(ctx context.Context, session Session, config Config) (*Client, error) {
	if ctx == nil || session == nil {
		return nil, ErrInvalidConfig
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	clientContext, cancel := context.WithCancel(ctx)
	client := &Client{ctx: clientContext, cancel: cancel, session: session, config: config, permits: make(chan struct{}, config.MaximumStreams), openings: make(chan struct{}, config.QueueDepth), accepted: make(chan acceptResult, config.QueueDepth), done: make(chan struct{}), requests: make(map[string]struct{})}
	go client.watch()
	go client.acceptLoop()
	return client, nil
}

func (c *Client) watch() {
	select {
	case <-c.ctx.Done():
		c.shutdown(c.ctx.Err())
	case <-c.session.CloseChan():
		c.shutdown(ErrCarrierClosed)
	}
}

func (c *Client) acceptLoop() {
	defer close(c.accepted)
	for {
		raw, err := c.session.AcceptStream(c.ctx)
		if err != nil {
			if !c.closed() {
				c.shutdown(err)
			}
			return
		}
		select {
		case c.permits <- struct{}{}:
			c.active.Add(1)
		default:
			_ = raw.Close()
			c.publish(acceptResult{err: ErrCarrierOverloaded})
			continue
		}
		admissionContext, cancel := context.WithTimeout(c.ctx, c.config.StreamOpenLimit)
		deadline := time.Now().Add(c.config.StreamOpenLimit)
		if err := raw.SetReadDeadline(deadline); err != nil {
			cancel()
			_ = raw.Close()
			c.releasePermit()
			c.publish(acceptResult{err: ErrInvalidPreface})
			continue
		}
		open, err := connectorprotocol.ReadStreamOpen(raw)
		_ = raw.SetReadDeadline(time.Time{})
		if err == nil && !c.config.Identity.matches(open) {
			err = ErrIdentityMismatch
		}
		if err == nil {
			err = c.config.Authorize.AuthorizeStream(admissionContext, c.config.Identity, open)
			if err != nil {
				err = fmt.Errorf("%w: %v", ErrRouteDenied, err)
			}
		}
		cancel()
		if err != nil {
			_ = raw.Close()
			c.releasePermit()
			c.publish(acceptResult{err: err})
			continue
		}
		key := open.SessionID + "\x00" + open.RequestID
		if !c.reserveRequest(key) {
			_ = raw.Close()
			c.releasePermit()
			c.publish(acceptResult{err: ErrRequestInUse})
			continue
		}
		stream := wrapStream(raw, context.Background(), func() {
			c.releaseRequest(key)
			c.releasePermit()
		}, open)
		c.publish(acceptResult{stream: stream, open: open})
	}
}

func (c *Client) publish(result acceptResult) {
	select {
	case c.accepted <- result:
	case <-c.done:
		if result.stream != nil {
			_ = result.stream.Close()
		}
	}
}

func (c *Client) reserveRequest(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.requests[key]; exists {
		return false
	}
	c.requests[key] = struct{}{}
	return true
}

func (c *Client) releaseRequest(key string) {
	c.mu.Lock()
	delete(c.requests, key)
	c.mu.Unlock()
}

func (c *Client) AcceptStream(ctx context.Context) (*Stream, StreamOpen, error) {
	if c == nil || ctx == nil {
		return nil, StreamOpen{}, ErrInvalidConfig
	}
	if c.closed() {
		return nil, StreamOpen{}, ErrCarrierClosed
	}
	select {
	case result, ok := <-c.accepted:
		if !ok {
			return nil, StreamOpen{}, ErrCarrierClosed
		}
		return result.stream, result.open, result.err
	case <-c.done:
		return nil, StreamOpen{}, ErrCarrierClosed
	case <-ctx.Done():
		return nil, StreamOpen{}, ctx.Err()
	}
}

func (c *Client) OpenStream(ctx context.Context, open StreamOpen) (*Stream, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	if err := open.Validate(); err != nil {
		return nil, ErrInvalidPreface
	}
	if !c.config.Identity.matches(open) {
		return nil, ErrIdentityMismatch
	}
	if err := c.config.Authorize.AuthorizeStream(ctx, c.config.Identity, open); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRouteDenied, err)
	}
	raw, err := c.openRaw(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeStreamOpen(ctx, raw, open, c.config.StreamOpenLimit); err != nil {
		_ = raw.Close()
		c.releasePermit()
		return nil, err
	}
	stream := wrapStream(raw, ctx, c.releasePermit, open)
	return stream, nil
}

func (c *Client) OpenControlStream(ctx context.Context) (*Stream, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	raw, err := c.openRaw(ctx)
	if err != nil {
		return nil, err
	}
	return wrapStream(raw, ctx, c.releasePermit), nil
}

func (c *Client) openRaw(ctx context.Context) (StreamLink, error) {
	if c.closed() {
		return nil, ErrCarrierClosed
	}
	select {
	case c.permits <- struct{}{}:
		c.active.Add(1)
	case <-c.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrStreamLimit
	}
	select {
	case c.openings <- struct{}{}:
	case <-c.done:
		c.releasePermit()
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		c.releasePermit()
		return nil, ctx.Err()
	}
	result := make(chan openResult, 1)
	go func() {
		raw, err := c.session.OpenStream(ctx)
		result <- openResult{stream: raw, err: err}
	}()
	select {
	case opened := <-result:
		<-c.openings
		if opened.err != nil {
			c.releasePermit()
			if c.closed() {
				return nil, ErrCarrierClosed
			}
			return nil, opened.err
		}
		if err := ctx.Err(); err != nil {
			_ = opened.stream.Close()
			c.releasePermit()
			return nil, err
		}
		return opened.stream, nil
	case <-c.done:
		go c.finishCanceledOpen(result)
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		go c.finishCanceledOpen(result)
		return nil, ctx.Err()
	}
}

func (c *Client) finishCanceledOpen(result <-chan openResult) {
	opened := <-result
	<-c.openings
	if opened.stream != nil {
		_ = opened.stream.Close()
	}
	c.releasePermit()
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.session == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if c.closed() {
		return ErrCarrierClosed
	}
	err := c.session.Ping(ctx)
	if err != nil && c.closed() {
		return ErrCarrierClosed
	}
	return err
}

func (c *Client) ActiveStreams() int {
	if c == nil || c.closed() {
		return 0
	}
	active := c.active.Load()
	if active <= 0 {
		return 0
	}
	return int(active)
}

func (c *Client) Done() <-chan struct{} {
	if c == nil {
		return closedChannel()
	}
	return c.done
}

func (c *Client) releasePermit() {
	if !c.closed() {
		c.active.Add(-1)
	}
	select {
	case <-c.permits:
	default:
	}
}

func (c *Client) shutdown(err error) {
	c.closeOnce.Do(func() {
		c.closeErr = err
		close(c.done)
		c.cancel()
		_ = c.session.Close()
	})
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.shutdown(nil)
	return c.closeErr
}

func (c *Client) closed() bool {
	if c == nil || c.done == nil {
		return true
	}
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func newYamuxSession(link io.ReadWriteCloser, config Config, client bool) (Session, error) {
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.LogOutput = io.Discard
	yamuxConfig.AcceptBacklog = config.AcceptBacklog
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = config.KeepAliveInterval
	yamuxConfig.ConnectionWriteTimeout = config.ConnectionWriteLimit
	yamuxConfig.MaxStreamWindowSize = config.StreamWindow
	yamuxConfig.InitialStreamWindowSize = config.StreamWindow
	yamuxConfig.MaxIncomingStreams = uint32(config.MaximumStreams)
	connection := asCarrierNetConn(link)
	if client {
		session, err := yamux.Client(connection, yamuxConfig, nil)
		if err != nil {
			return nil, err
		}
		return &yamuxSession{session: session}, nil
	}
	session, err := yamux.Server(connection, yamuxConfig, nil)
	if err != nil {
		return nil, err
	}
	return &yamuxSession{session: session}, nil
}

type yamuxSession struct {
	session *yamux.Session
}

func (s *yamuxSession) OpenStream(ctx context.Context) (StreamLink, error) {
	if s == nil || s.session == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	return s.session.OpenStream(ctx)
}

type carrierNetConn struct{ io.ReadWriteCloser }

func asCarrierNetConn(link io.ReadWriteCloser) net.Conn {
	if connection, ok := link.(net.Conn); ok {
		return connection
	}
	return &carrierNetConn{ReadWriteCloser: link}
}
func (c *carrierNetConn) LocalAddr() net.Addr  { return carrierAddr("local") }
func (c *carrierNetConn) RemoteAddr() net.Addr { return carrierAddr("remote") }
func (c *carrierNetConn) SetDeadline(t time.Time) error {
	if v, ok := c.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return v.SetDeadline(t)
	}
	return nil
}
func (c *carrierNetConn) SetReadDeadline(t time.Time) error {
	if v, ok := c.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return v.SetReadDeadline(t)
	}
	return nil
}
func (c *carrierNetConn) SetWriteDeadline(t time.Time) error {
	if v, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return v.SetWriteDeadline(t)
	}
	return nil
}

func (s *yamuxSession) AcceptStream(ctx context.Context) (StreamLink, error) {
	if s == nil || s.session == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	result := make(chan openResult, 1)
	go func() {
		stream, err := s.session.AcceptStream()
		result <- openResult{stream: stream, err: err}
	}()
	select {
	case opened := <-result:
		return opened.stream, opened.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.session.CloseChan():
		return nil, ErrCarrierClosed
	}
}

func (s *yamuxSession) Ping(ctx context.Context) error {
	if s == nil || s.session == nil || ctx == nil {
		return ErrInvalidConfig
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.session.Ping()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.session.CloseChan():
		return ErrCarrierClosed
	}
}

func (s *yamuxSession) Close() error {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Close()
}

func (s *yamuxSession) CloseChan() <-chan struct{} {
	if s == nil || s.session == nil {
		return closedChannel()
	}
	return s.session.CloseChan()
}

func writeStreamOpen(ctx context.Context, stream StreamLink, open StreamOpen, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := connectorprotocol.WriteStreamOpen(stream, open)
	_ = stream.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return ctx.Err()
}

// Stream is an admitted request stream. Request and session identity are
// immutable metadata used by the route/origin owner.
type Stream struct {
	raw        StreamLink
	Open       StreamOpen
	release    func()
	cancelMu   sync.Mutex
	stopCancel func() bool
	closeOnce  sync.Once
	closeErr   error
}

func wrapStream(raw StreamLink, ctx context.Context, release func(), open ...StreamOpen) *Stream {
	stream := &Stream{raw: raw, release: release}
	if len(open) > 0 {
		stream.Open = open[0]
	}
	if ctx != nil && ctx != context.Background() {
		stream.cancelMu.Lock()
		stream.stopCancel = context.AfterFunc(ctx, func() { _ = stream.abort() })
		stream.cancelMu.Unlock()
	}
	return stream
}

func (s *Stream) Read(p []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrCarrierClosed
	}
	return s.raw.Read(p)
}

func (s *Stream) Write(p []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrCarrierClosed
	}
	return s.raw.Write(p)
}

func (s *Stream) Close() error {
	if s == nil || s.raw == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancelMu.Lock()
		stopCancel := s.stopCancel
		s.cancelMu.Unlock()
		if stopCancel != nil {
			stopCancel()
		}
		s.closeErr = s.raw.Close()
		if s.release != nil {
			s.release()
		}
	})
	return s.closeErr
}

func (s *Stream) abort() error {
	if s == nil || s.raw == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if resetter, ok := s.raw.(interface{ Reset() error }); ok {
			s.closeErr = resetter.Reset()
		} else {
			s.closeErr = s.raw.Close()
		}
		if s.release != nil {
			s.release()
		}
	})
	return s.closeErr
}

// CloseWrite sends a native stream FIN without releasing the stream permit;
// Close retains ownership of final cleanup and accounting.
func (s *Stream) CloseWrite() error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	if closer, ok := s.raw.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return s.raw.Close()
}

func (s *Stream) StreamID() uint32 {
	if s == nil || s.raw == nil {
		return 0
	}
	if identified, ok := s.raw.(interface{ StreamID() uint32 }); ok {
		return identified.StreamID()
	}
	return 0
}

func (s *Stream) SetDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	return s.raw.SetDeadline(deadline)
}

func (s *Stream) SetReadDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	return s.raw.SetReadDeadline(deadline)
}

func (s *Stream) SetWriteDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	return s.raw.SetWriteDeadline(deadline)
}

// ServeHTTPStream runs HTTP/1.1 and cleartext HTTP/2 directly on one admitted
// stream. net/http keeps body, SSE, WebSocket, gRPC, chunk, trailer, and
// cancellation semantics on the stream without a global body-size buffer.
func ServeHTTPStream(ctx context.Context, stream io.ReadWriteCloser, handler http.Handler, maxHeaderBytes int, readHeaderTimeout time.Duration) error {
	if ctx == nil || stream == nil || handler == nil || maxHeaderBytes < 1024 || maxHeaderBytes > 16<<20 || readHeaderTimeout <= 0 || readHeaderTimeout > maxOperationTimeout {
		return ErrInvalidConfig
	}
	connection := &streamConn{ReadWriteCloser: stream}
	listener := newSingleConnListener(connection)
	bridgeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: handlerWithContext(bridgeContext, handler), MaxHeaderBytes: maxHeaderBytes, ReadHeaderTimeout: readHeaderTimeout, Protocols: protocols, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			listener.Close()
		}
	}}
	go func() {
		<-bridgeContext.Done()
		listener.Close()
		_ = server.Close()
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func handlerWithContext(ctx context.Context, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestContext, cancel := context.WithCancel(ctx)
		requestDone := make(chan struct{})
		go func() {
			select {
			case <-request.Context().Done():
				cancel()
			case <-requestContext.Done():
			case <-requestDone:
			}
		}()
		handler.ServeHTTP(writer, request.WithContext(requestContext))
		close(requestDone)
		cancel()
	})
}

type streamConn struct{ io.ReadWriteCloser }

func (c *streamConn) LocalAddr() net.Addr  { return carrierAddr("connector") }
func (c *streamConn) RemoteAddr() net.Addr { return carrierAddr("edge") }
func (c *streamConn) SetDeadline(deadline time.Time) error {
	if setter, ok := c.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return setter.SetDeadline(deadline)
	}
	return nil
}
func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	if setter, ok := c.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return setter.SetReadDeadline(deadline)
	}
	return nil
}
func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	if setter, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return setter.SetWriteDeadline(deadline)
	}
	return nil
}

type carrierAddr string

func (a carrierAddr) Network() string { return "paperboat-carrier" }
func (a carrierAddr) String() string  { return string(a) }

type singleConnListener struct {
	conn      net.Conn
	mu        sync.Mutex
	accepted  bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr { return carrierAddr("single") }

func closedChannel() <-chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}
