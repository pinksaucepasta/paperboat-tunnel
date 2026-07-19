package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type DataPlaneSpec struct {
	Persistence Component
	Control     Component
	Node        Component
	Routes      Component
	Hook        Component
	FRPS        Component
	Caddy       Component
	Usage       Component
}

type DataPlane struct {
	spec    DataPlaneSpec
	mu      sync.Mutex
	started []Component
	closed  bool
}

func NewDataPlane(spec DataPlaneSpec) (*DataPlane, error) {
	if spec.Persistence == nil || spec.Control == nil || spec.Node == nil || spec.Routes == nil || spec.Hook == nil || spec.FRPS == nil || spec.Caddy == nil || spec.Usage == nil {
		return nil, ErrProcessInvalid
	}
	return &DataPlane{spec: spec}, nil
}

func (d *DataPlane) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.started) != 0 || d.closed {
		return ErrProcessInvalid
	}
	for _, component := range []Component{d.spec.Persistence, d.spec.Control, d.spec.Node, d.spec.Routes, d.spec.Usage, d.spec.Hook, d.spec.FRPS, d.spec.Caddy} {
		if err := component.Start(ctx); err != nil {
			var cleanup []error
			for i := len(d.started) - 1; i >= 0; i-- {
				if stopErr := d.started[i].Shutdown(context.Background()); stopErr != nil {
					cleanup = append(cleanup, stopErr)
				}
			}
			d.started = nil
			d.closed = true
			return errors.Join(fmt.Errorf("start data-plane dependency: %w", err), errors.Join(cleanup...))
		}
		d.started = append(d.started, component)
	}
	return nil
}

func (d *DataPlane) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	// Public ingress and connector forwarding stop before the final accounting
	// flush. The private hook/control/store remain available for cleanup.
	order := []Component{d.spec.Caddy, d.spec.FRPS, d.spec.Routes, d.spec.Usage, d.spec.Node, d.spec.Hook, d.spec.Control, d.spec.Persistence}
	var failures []error
	for _, component := range order {
		if err := component.Shutdown(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	d.started = nil
	return errors.Join(failures...)
}
