package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
)

type Component interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

type Service struct {
	cfg        config.Config
	node       *node.State
	components []Component

	mu       sync.Mutex
	started  []Component
	listener net.Listener
	health   *http.Server
	closed   bool
	listen   func(network, address string) (net.Listener, error)
	done     chan error
	handler  http.Handler
}

func New(cfg config.Config, state *node.State, components ...Component) *Service {
	return &Service{cfg: cfg, node: state, components: components, listen: net.Listen, done: make(chan error, 1), handler: state.HealthHandler()}
}

func (s *Service) SetHealthHandler(handler http.Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if handler == nil || s.listener != nil || s.closed {
		return errors.New("health handler cannot be changed")
	}
	s.handler = handler
	return nil
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil || s.closed {
		return errors.New("service cannot be started")
	}
	listener, err := s.listen("tcp", s.cfg.HealthAddress)
	if err != nil {
		return fmt.Errorf("open health listener: %w", err)
	}
	s.listener = listener
	s.health = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() { _ = s.health.Serve(listener) }()
	for _, component := range s.components {
		if err := component.Start(ctx); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
			defer cancel()
			cleanupErr := s.shutdownLocked(cleanupCtx)
			return errors.Join(fmt.Errorf("start component: %w", err), cleanupErr)
		}
		s.started = append(s.started, component)
		if source, ok := component.(interface{ Done() <-chan error }); ok {
			go func() {
				err := <-source.Done()
				select {
				case s.done <- err:
				default:
				}
			}()
		}
	}
	if !s.node.MarkReady() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		return errors.Join(errors.New("node refused ready transition"), s.shutdownLocked(cleanupCtx))
	}
	return nil
}

func (s *Service) Done() <-chan error { return s.done }

func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdownLocked(ctx)
}

func (s *Service) shutdownLocked(ctx context.Context) error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.node.BeginDrain(deadline(ctx))
	var errs []error
	for i := len(s.started) - 1; i >= 0; i-- {
		if err := s.started[i].Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown component: %w", err))
		}
	}
	s.started = nil
	if s.health != nil {
		if err := s.health.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown health server: %w", err))
		}
	}
	s.node.MarkStopped()
	return errors.Join(errs...)
}

func deadline(ctx context.Context) time.Time {
	if value, ok := ctx.Deadline(); ok {
		return value
	}
	return time.Now()
}
