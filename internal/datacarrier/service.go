package datacarrier

import (
	"context"
	"errors"
	"net"
	"sync"
)

// ServiceConfig describes the edge listener set for connector-v1 carriers.
// Either transport may be enabled independently; when both are configured
// they share the same authenticated identity and route admission policy while
// remaining separate failure domains.
type ServiceConfig struct {
	Carrier Config
	TCP     *EndpointConfig
	QUIC    *EndpointConfig
}

// Service owns the real edge carrier listeners. It only publishes a Server
// after the listener has completed mutual TLS/QUIC authentication, canonical
// ALPN negotiation, and exact peer-identity binding. FRPS may continue to run
// alongside this service because this package does not claim its listener or
// proxy lifecycle.
type Service struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    Config
	tcp       *TCPMuxListener
	quic      *QUICListener
	accepted  chan *Server
	done      chan struct{}
	once      sync.Once
	closeErr  error
	serversMu sync.Mutex
	servers   map[*Server]struct{}
}

// NewService binds the configured TCP and/or QUIC carrier listeners and
// starts bounded accept loops. At least one listener is required. Callers
// receive authenticated edge Server values through Accept.
func NewService(ctx context.Context, config ServiceConfig) (*Service, error) {
	if ctx == nil || (config.TCP == nil && config.QUIC == nil) {
		return nil, ErrInvalidEndpoint
	}
	carrierConfig := config.Carrier.withDefaults()
	if err := carrierConfig.validateListener(); err != nil {
		return nil, err
	}
	serviceContext, cancel := context.WithCancel(ctx)
	service := &Service{
		ctx:      serviceContext,
		cancel:   cancel,
		config:   carrierConfig,
		accepted: make(chan *Server, carrierConfig.QueueDepth),
		done:     make(chan struct{}),
		servers:  make(map[*Server]struct{}),
	}
	if config.TCP != nil {
		listener, err := ListenTCPMux(serviceContext, *config.TCP, carrierConfig)
		if err != nil {
			cancel()
			return nil, err
		}
		service.tcp = listener
	}
	if config.QUIC != nil {
		listener, err := ListenQUIC(serviceContext, *config.QUIC, carrierConfig)
		if err != nil {
			if service.tcp != nil {
				_ = service.tcp.Close()
			}
			cancel()
			return nil, err
		}
		service.quic = listener
	}
	if service.tcp != nil {
		go service.acceptTCP()
	}
	if service.quic != nil {
		go service.acceptQUIC()
	}
	return service, nil
}

func (s *Service) acceptTCP() {
	for {
		server, err := s.tcp.Accept(s.ctx)
		if err != nil {
			if s.closed() || errors.Is(err, ErrCarrierClosed) {
				return
			}
			continue
		}
		s.publish(server)
	}
}

func (s *Service) acceptQUIC() {
	for {
		server, err := s.quic.Accept(s.ctx)
		if err != nil {
			if s.closed() || errors.Is(err, ErrCarrierClosed) {
				return
			}
			continue
		}
		s.publish(server)
	}
}

func (s *Service) publish(server *Server) {
	if server == nil {
		return
	}
	if !s.track(server) {
		return
	}
	select {
	case s.accepted <- server:
	case <-s.done:
		_ = server.Close()
	}
}

func (s *Service) track(server *Server) bool {
	if s == nil || server == nil {
		return false
	}
	s.serversMu.Lock()
	if s.closed() {
		s.serversMu.Unlock()
		_ = server.Close()
		return false
	}
	s.servers[server] = struct{}{}
	s.serversMu.Unlock()
	go func() {
		<-server.Done()
		s.untrack(server)
	}()
	return true
}

func (s *Service) untrack(server *Server) {
	if s == nil || server == nil {
		return
	}
	s.serversMu.Lock()
	delete(s.servers, server)
	s.serversMu.Unlock()
}

// Accept returns the next authenticated carrier server. Invalid handshakes
// are discarded by the listeners and never reach this boundary.
func (s *Service) Accept(ctx context.Context) (*Server, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidEndpoint
	}
	select {
	case server := <-s.accepted:
		if server == nil {
			return nil, ErrCarrierClosed
		}
		return server, nil
	case <-s.done:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TCPAddr and QUICAddr expose the bound addresses, including dynamically
// selected test ports, without exposing listener ownership.
func (s *Service) TCPAddr() net.Addr {
	if s == nil || s.tcp == nil || s.tcp.Addr() == nil {
		return nil
	}
	return s.tcp.Addr()
}

func (s *Service) QUICAddr() net.Addr {
	if s == nil || s.quic == nil || s.quic.Addr() == nil {
		return nil
	}
	return s.quic.Addr()
}

func (s *Service) Done() <-chan struct{} {
	if s == nil {
		return closedChannel()
	}
	return s.done
}

// Close stops listener accepts and closes every carrier owned by the service,
// including servers already returned by Accept. This gives runtime shutdown a
// single leak-free ownership boundary; callers may still close a returned
// server independently.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.done)
		s.cancel()
		if s.tcp != nil {
			if err := s.tcp.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.quic != nil {
			if err := s.quic.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		s.serversMu.Lock()
		servers := make([]*Server, 0, len(s.servers))
		for server := range s.servers {
			servers = append(servers, server)
		}
		s.serversMu.Unlock()
		for _, server := range servers {
			_ = server.Close()
		}
	})
	return s.closeErr
}

func (s *Service) closed() bool {
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
