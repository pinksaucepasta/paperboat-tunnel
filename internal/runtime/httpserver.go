package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var ErrHTTPServerInvalid = errors.New("private HTTP server configuration is invalid")

type HTTPServerSpec struct {
	Address           string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

type HTTPServer struct {
	spec     HTTPServerSpec
	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	done     chan error
	listen   func(string, string) (net.Listener, error)
	closed   bool
}

func NewHTTPServer(spec HTTPServerSpec) (*HTTPServer, error) {
	if err := validateHTTPServerSpec(spec); err != nil {
		return nil, err
	}
	return &HTTPServer{spec: spec, listen: net.Listen}, nil
}

func validateHTTPServerSpec(spec HTTPServerSpec) error {
	host, port, err := net.SplitHostPort(spec.Address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || spec.Handler == nil || spec.ReadHeaderTimeout <= 0 || spec.IdleTimeout <= 0 || spec.MaxHeaderBytes < 1024 {
		return ErrHTTPServerInvalid
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return ErrHTTPServerInvalid
	}
	return nil
}

func (s *HTTPServer) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil || s.closed {
		return ErrHTTPServerInvalid
	}
	listener, err := s.listen("tcp", s.spec.Address)
	if err != nil {
		return err
	}
	s.listener = listener
	s.server = &http.Server{Handler: s.spec.Handler, ReadHeaderTimeout: s.spec.ReadHeaderTimeout, IdleTimeout: s.spec.IdleTimeout, MaxHeaderBytes: s.spec.MaxHeaderBytes}
	s.done = make(chan error, 1)
	go func() {
		err := s.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		s.done <- err
	}()
	return nil
}

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	server, done := s.server, s.done
	s.mu.Unlock()
	if server == nil {
		return nil
	}
	shutdownErr := server.Shutdown(ctx)
	if shutdownErr != nil {
		_ = server.Close()
	}
	select {
	case serveErr := <-done:
		return errors.Join(shutdownErr, serveErr)
	case <-ctx.Done():
		_ = server.Close()
		return errors.Join(shutdownErr, ctx.Err())
	}
}

func (s *HTTPServer) Done() <-chan error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		return closedErrorChannel(ErrHTTPServerInvalid)
	}
	return s.done
}
