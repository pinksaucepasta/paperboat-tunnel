package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

var ErrWorkerInvalid = errors.New("runtime worker configuration is invalid")

type UsageWorker struct {
	Queue    *usage.Queue
	Sink     control.UsageSink
	Prepare  interface{ Flush() error }
	Interval time.Duration
	Pulse    <-chan time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (w *UsageWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Queue == nil || w.Sink == nil || (w.Pulse == nil && w.Interval <= 0) || w.done != nil {
		return ErrWorkerInvalid
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done = cancel, make(chan struct{})
	go w.run(workerCtx)
	return nil
}

func (w *UsageWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-w.Pulse:
				if !ok {
					return
				}
				_, _, err := w.deliver(ctx)
				w.recordError(err)
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := w.deliver(ctx)
			w.recordError(err)
		}
	}
}

func (w *UsageWorker) deliver(ctx context.Context) (control.UsageResult, bool, error) {
	if w.Prepare != nil {
		if err := w.Prepare.Flush(); err != nil {
			return control.UsageResult{}, false, err
		}
	}
	return control.DeliverNext(ctx, w.Queue, w.Sink)
}

func (w *UsageWorker) recordError(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

func (w *UsageWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *UsageWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		_, delivered, err := w.deliver(ctx)
		if err != nil {
			return err
		}
		if !delivered {
			return nil
		}
	}
}

type NodeWorker struct {
	Manager      *node.Manager
	Sink         control.NodeSink
	Registration control.NodeRegistration
	Interval     time.Duration
	Pulse        <-chan time.Time
	Now          func() time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (w *NodeWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Manager == nil || w.Sink == nil || (w.Pulse == nil && w.Interval <= 0) || w.done != nil {
		return ErrWorkerInvalid
	}
	if err := w.Manager.RegisterAndHeartbeat(ctx, w.Sink, w.Registration, w.now()); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done = cancel, make(chan struct{})
	go w.run(workerCtx)
	return nil
}

func (w *NodeWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case at, ok := <-w.Pulse:
				if !ok {
					return
				}
				w.recordError(w.Sink.Heartbeat(ctx, w.Manager.Observation(w.Registration.NodeID, at)))
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			w.recordError(w.Sink.Heartbeat(ctx, w.Manager.Observation(w.Registration.NodeID, at)))
		}
	}
}

func (w *NodeWorker) recordError(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

func (w *NodeWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *NodeWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return w.Sink.Heartbeat(ctx, w.Manager.Observation(w.Registration.NodeID, w.now()))
}

func (w *NodeWorker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}

type RouteWorker struct {
	Registry *route.Registry
	Source   control.RouteSource
	State    *node.State
	NodeID   string
	Interval time.Duration
	Pulse    <-chan time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (w *RouteWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Registry == nil || w.Source == nil || w.State == nil || w.NodeID == "" || (w.Pulse == nil && w.Interval <= 0) || w.done != nil {
		return ErrWorkerInvalid
	}
	if err := w.reconcile(ctx); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done = cancel, make(chan struct{})
	go w.run(workerCtx)
	return nil
}

func (w *RouteWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-w.Pulse:
				if !ok {
					return
				}
				w.recordReconcile(w.reconcile(ctx))
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.recordReconcile(w.reconcile(ctx))
		}
	}
}

func (w *RouteWorker) recordReconcile(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
	w.State.SetControlAvailable(err == nil)
}

func (w *RouteWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *RouteWorker) reconcile(ctx context.Context) error {
	desired, err := w.Source.DesiredRoutes(ctx, w.NodeID)
	if err != nil {
		return err
	}
	attachments := make([]route.Attachment, 0, len(desired))
	for _, assignment := range desired {
		if assignment.NodeID != w.NodeID {
			return route.ErrInvalid
		}
		attachments = append(attachments, route.Attachment{ID: assignment.RouteID, Revision: assignment.Revision, Environment: assignment.Environment, Node: assignment.NodeID, Generation: assignment.Generation, Kind: route.Kind(assignment.Kind), Host: assignment.PublicHost, Target: net.JoinHostPort(assignment.TargetHost, strconv.Itoa(int(assignment.TargetPort)))})
	}
	return w.Registry.Replace(attachments)
}

func (w *RouteWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
