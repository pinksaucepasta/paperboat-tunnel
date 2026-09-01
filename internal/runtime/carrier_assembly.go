package runtime

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	edgetelemetry "github.com/pinksaucepasta/paperboat-tunnel/internal/telemetry"
)

var (
	ErrCarrierAssemblyInvalid = errors.New("invalid data carrier assembly")
	ErrCarrierAssemblyClosed  = errors.New("data carrier assembly is closed")
)

const (
	defaultCarrierHandlers = 64
	maxCarrierHandlers     = 1024
)

// CarrierService is the lifecycle boundary implemented by
// datacarrier.Service. Keeping the narrow interface here lets deterministic
// runtime tests exercise accept and shutdown without constructing certificates
// or binding a real listener.
type CarrierService interface {
	Accept(context.Context) (*datacarrier.Server, error)
	Close() error
}

// CarrierHandler receives a carrier only after datacarrier.Service has
// completed mutual TLS/QUIC authentication and peer identity binding. The
// handler owns control/routing admission; this assembly owns the peer
// lifetime and never invents an identity or route policy.
type CarrierHandler func(context.Context, *datacarrier.Server) error

type CarrierAssemblyConfig struct {
	Service         CarrierService
	Handle          CarrierHandler
	MaximumHandlers int
	ObserveError    func(error)
	Telemetry       *datacarrier.CarrierTelemetry
}

// CarrierAssembly owns the accepted datacarrier.Service peers and provides a
// bounded handler boundary for edge control and route ownership. The service
// is already listening when it is passed to this constructor, as required by
// datacarrier.NewService; Start only begins consumption of authenticated
// peers.
type CarrierAssembly struct {
	service         CarrierService
	handle          CarrierHandler
	observeError    func(error)
	telemetry       *datacarrier.CarrierTelemetry
	maximumHandlers int

	mu         sync.Mutex
	started    bool
	closed     bool
	cancel     context.CancelFunc
	acceptDone chan struct{}
	handlers   sync.WaitGroup
	done       chan error
	once       sync.Once
}

func NewCarrierAssembly(config CarrierAssemblyConfig) (*CarrierAssembly, error) {
	if config.Service == nil || config.Handle == nil {
		return nil, ErrCarrierAssemblyInvalid
	}
	if config.MaximumHandlers == 0 {
		config.MaximumHandlers = defaultCarrierHandlers
	}
	if config.MaximumHandlers < 1 || config.MaximumHandlers > maxCarrierHandlers {
		return nil, ErrCarrierAssemblyInvalid
	}
	return &CarrierAssembly{
		service: config.Service, handle: config.Handle, observeError: config.ObserveError,
		telemetry: config.Telemetry, maximumHandlers: config.MaximumHandlers, done: make(chan error, 1),
	}, nil
}

// NewDataCarrierAssembly makes the production ownership explicit while
// retaining NewCarrierAssembly's narrow interface for tests and adapters.
func NewDataCarrierAssembly(service *datacarrier.Service, handle CarrierHandler, maximumHandlers int, observeError func(error)) (*CarrierAssembly, error) {
	return NewDataCarrierAssemblyWithTelemetry(service, handle, maximumHandlers, observeError, nil)
}

// NewDataCarrierAssemblyWithTelemetry keeps the authenticated accept boundary
// in the runtime composition while leaving datacarrier's transport semantics
// unchanged. The legacy constructor delegates here with telemetry disabled.
func NewDataCarrierAssemblyWithTelemetry(service *datacarrier.Service, handle CarrierHandler, maximumHandlers int, observeError func(error), telemetry *datacarrier.CarrierTelemetry) (*CarrierAssembly, error) {
	return NewCarrierAssembly(CarrierAssemblyConfig{Service: service, Handle: handle, MaximumHandlers: maximumHandlers, ObserveError: observeError, Telemetry: telemetry})
}

func (a *CarrierAssembly) Start(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrCarrierAssemblyInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.service == nil || a.handle == nil || a.closed {
		return ErrCarrierAssemblyClosed
	}
	if a.started {
		return ErrCarrierAssemblyInvalid
	}
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.acceptDone = make(chan struct{})
	a.started = true
	go a.acceptLoop(runCtx)
	return nil
}

func (a *CarrierAssembly) acceptLoop(ctx context.Context) {
	defer close(a.acceptDone)
	limits := make(chan struct{}, a.maximumHandlers)
	for {
		server, err := a.service.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, datacarrier.ErrCarrierClosed) {
				return
			}
			a.report(err)
			return
		}
		if server == nil {
			continue
		}
		var accepted io.ReadWriteCloser
		if a.telemetry != nil {
			accepted, err = a.telemetry.Accept(ctx, carrierPeerStreamInfo(server.Identity()), func(context.Context) (io.ReadWriteCloser, error) {
				// The authenticated server is the lifetime owner at this
				// boundary. Its data streams remain owned by the existing
				// handler, so the adapter deliberately does not read, write, or
				// close the server itself.
				return carrierPeerLifetime{}, nil
			})
			if err != nil {
				_ = server.Close()
				if ctx.Err() == nil {
					a.report(err)
				}
				return
			}
		}
		select {
		case limits <- struct{}{}:
		case <-ctx.Done():
			if accepted != nil {
				_ = accepted.Close()
			}
			_ = server.Close()
			return
		}
		a.handlers.Add(1)
		go func() {
			defer a.handlers.Done()
			defer func() { <-limits }()
			if accepted != nil {
				defer accepted.Close()
			}
			defer server.Close()
			if err := a.handle(ctx, server); err != nil && ctx.Err() == nil {
				a.report(err)
			}
		}()
	}
}

func carrierPeerStreamInfo(identity datacarrier.Identity) datacarrier.StreamInfo {
	return datacarrier.StreamInfo{
		IDs: edgetelemetry.SafeIDs{
			AccountID:   identity.AccountID,
			HostID:      identity.HostID,
			TunnelID:    identity.TunnelID,
			ConnectorID: identity.ConnectorID,
			SessionID:   identity.SessionID,
		},
		Generations: edgetelemetry.Generations{
			Connector: identity.ProcessGeneration,
			Session:   identity.Generation,
		},
		CorrelationID:      "corr_edge_carrier",
		Kind:               "carrier",
		ReadDirection:      "ingress",
		WriteDirection:     "egress",
		CancellationReason: "shutdown",
	}
}

// carrierPeerLifetime is a zero-copy lifetime marker for an authenticated
// carrier peer. Actual stream I/O remains in the existing handlers; keeping
// this adapter inert avoids changing their ordering or cancellation behavior.
type carrierPeerLifetime struct{}

func (carrierPeerLifetime) Read([]byte) (int, error)  { return 0, io.EOF }
func (carrierPeerLifetime) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (carrierPeerLifetime) Close() error              { return nil }

func (a *CarrierAssembly) report(err error) {
	if err == nil {
		return
	}
	if a.observeError != nil {
		a.observeError(err)
	}
	a.once.Do(func() {
		select {
		case a.done <- err:
		default:
		}
	})
}

// Done reports a fatal accept or handler error. Per-peer handler failures do
// not stop accepting later authenticated carriers.
func (a *CarrierAssembly) Done() <-chan error {
	if a == nil || a.done == nil {
		ch := make(chan error)
		return ch
	}
	return a.done
}

func (a *CarrierAssembly) Shutdown(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrCarrierAssemblyInvalid
	}
	a.mu.Lock()
	if a.service == nil {
		a.mu.Unlock()
		return nil
	}
	cancel := a.cancel
	acceptDone := a.acceptDone
	service := a.service
	wasStarted := a.started
	a.closed = true
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	closeErr := service.Close()
	if !wasStarted {
		return closeErr
	}
	if err := waitCarrierAssembly(ctx, acceptDone); err != nil {
		return errors.Join(closeErr, err)
	}
	handlersDone := make(chan struct{})
	go func() {
		a.handlers.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
		return closeErr
	case <-ctx.Done():
		return errors.Join(closeErr, ctx.Err())
	}
}

func waitCarrierAssembly(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ Component = (*CarrierAssembly)(nil)
