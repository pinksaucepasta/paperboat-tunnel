package datacarrier

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const httpCarrierPath = "/_paperboat/connector-v1"

// HTTPService serves authenticated, full-duplex CONNECT carriers over real
// HTTP/2 and HTTP/3 listeners.
type HTTPService struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     Config
	tcp        net.Listener
	udp        net.PacketConn
	h2         *http.Server
	h3         *http3.Server
	accepted   chan *Server
	admissions chan struct{}
	done       chan struct{}
	once       sync.Once
	serversMu  sync.Mutex
	servers    map[*Server]struct{}
}

func NewHTTPService(ctx context.Context, config ServiceConfig) (*HTTPService, error) {
	if ctx == nil || (config.TCP == nil && config.QUIC == nil) {
		return nil, ErrInvalidEndpoint
	}
	carrier := config.Carrier.withDefaults()
	if err := carrier.validateListener(); err != nil {
		return nil, err
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	s := &HTTPService{ctx: serviceCtx, cancel: cancel, config: carrier, accepted: make(chan *Server, carrier.QueueDepth), admissions: make(chan struct{}, carrier.QueueDepth), done: make(chan struct{}), servers: make(map[*Server]struct{})}
	if config.TCP != nil {
		if err := config.TCP.validateServer(); err != nil {
			cancel()
			return nil, err
		}
		tlsConfig, err := serverTLSConfig(config.TCP.TLS)
		if err != nil {
			cancel()
			return nil, err
		}
		tlsConfig.NextProtos = []string{"h2"}
		listener, err := net.Listen("tcp", config.TCP.Address)
		if err != nil {
			cancel()
			return nil, err
		}
		s.tcp = listener
		handler := s.handler(*config.TCP, "h2")
		s.h2 = &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: carrier.StreamOpenLimit, MaxHeaderBytes: 16 << 10, ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, httpTLSConnectionKey{}, connection)
		}}
		if err := http2.ConfigureServer(s.h2, &http2.Server{MaxConcurrentStreams: uint32(carrier.MaximumStreams)}); err != nil {
			_ = listener.Close()
			cancel()
			return nil, err
		}
		go func() {
			if err := s.h2.Serve(tlsConfigListener(listener, tlsConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) && serviceCtx.Err() == nil {
				_ = s.Close()
			}
		}()
	}
	if config.QUIC != nil {
		if err := config.QUIC.validateServer(); err != nil {
			_ = s.Close()
			return nil, err
		}
		tlsConfig, err := serverTLSConfig(config.QUIC.TLS)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		tlsConfig.NextProtos = []string{"h3"}
		packet, err := net.ListenPacket("udp", config.QUIC.Address)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.udp = packet
		quicConfig := endpointQUICConfig(carrier)
		quicConfig.MaxIncomingUniStreams = 3
		s.h3 = &http3.Server{Handler: s.handler(*config.QUIC, "h3"), TLSConfig: tlsConfig, QUICConfig: quicConfig, MaxHeaderBytes: 16 << 10}
		go func() {
			if err := s.h3.Serve(packet); err != nil && !errors.Is(err, http.ErrServerClosed) && serviceCtx.Err() == nil {
				_ = s.Close()
			}
		}()
	}
	go func() {
		select {
		case <-serviceCtx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	return s, nil
}

// tlsConfigListener avoids importing TLS ownership into the HTTP link.
func tlsConfigListener(listener net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(listener, config.Clone())
}

func (s *HTTPService) handler(endpoint EndpointConfig, alpn string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "invalid carrier method", http.StatusMethodNotAllowed)
			return
		}
		state := r.TLS
		if state == nil {
			if connection, ok := r.Context().Value(httpTLSConnectionKey{}).(*tls.Conn); ok {
				connectionState := connection.ConnectionState()
				state = &connectionState
			}
		}
		if state == nil || state.NegotiatedProtocol != alpn {
			http.Error(w, "invalid carrier protocol", http.StatusUpgradeRequired)
			return
		}
		identity, err := bindEndpointPeer(endpoint, *state)
		if err != nil {
			http.Error(w, "carrier authentication failed", http.StatusForbidden)
			return
		}
		select {
		case s.admissions <- struct{}{}:
			defer func() { <-s.admissions }()
		default:
			http.Error(w, "carrier capacity reached", http.StatusServiceUnavailable)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "duplex unavailable", http.StatusInternalServerError)
			return
		}
		link := &httpServerLink{body: r.Body, writer: w, flush: flusher, ctx: r.Context(), done: make(chan struct{})}
		carrierConfig := s.config
		carrierConfig.Identity = identity
		server, err := NewServer(s.ctx, link, carrierConfig)
		if err != nil {
			_ = link.Close()
			return
		}
		s.serversMu.Lock()
		select {
		case <-s.done:
			s.serversMu.Unlock()
			_ = server.Close()
			return
		default:
		}
		s.servers[server] = struct{}{}
		s.serversMu.Unlock()
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		select {
		case s.accepted <- server:
		case <-s.done:
			_ = server.Close()
		}
		select {
		case <-server.Done():
		case <-r.Context().Done():
			_ = server.Close()
		case <-s.done:
			_ = server.Close()
		}
		_ = link.Close()
		s.serversMu.Lock()
		delete(s.servers, server)
		s.serversMu.Unlock()
	})
}

type httpTLSConnectionKey struct{}

func (s *HTTPService) Accept(ctx context.Context) (*Server, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	select {
	case server := <-s.accepted:
		return server, nil
	case <-s.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *HTTPService) TCPAddr() net.Addr {
	if s == nil || s.tcp == nil {
		return nil
	}
	return s.tcp.Addr()
}
func (s *HTTPService) QUICAddr() net.Addr {
	if s == nil || s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}
func (s *HTTPService) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.done)
		s.cancel()
		if s.h2 != nil {
			_ = s.h2.Close()
		}
		if s.h3 != nil {
			_ = s.h3.Close()
		}
		if s.tcp != nil {
			_ = s.tcp.Close()
		}
		if s.udp != nil {
			_ = s.udp.Close()
		}
		s.serversMu.Lock()
		for server := range s.servers {
			_ = server.Close()
		}
		s.serversMu.Unlock()
	})
	return nil
}

type httpServerLink struct {
	body    io.ReadCloser
	writer  io.Writer
	flush   http.Flusher
	ctx     context.Context
	done    chan struct{}
	once    sync.Once
	writeMu sync.Mutex
	closed  bool
}

func (l *httpServerLink) Read(p []byte) (int, error) { return l.body.Read(p) }
func (l *httpServerLink) Write(p []byte) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if l.closed {
		return 0, io.ErrClosedPipe
	}
	select {
	case <-l.ctx.Done():
		return 0, l.ctx.Err()
	default:
	}
	n, err := l.writer.Write(p)
	if err == nil {
		l.flush.Flush()
	}
	return n, err
}
func (l *httpServerLink) Close() error {
	var err error
	l.once.Do(func() {
		l.writeMu.Lock()
		defer l.writeMu.Unlock()
		l.closed = true
		close(l.done)
		err = l.body.Close()
	})
	return err
}
