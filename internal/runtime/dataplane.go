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
	Carrier     Component
	// CertificateBroker is the private Unix-socket bridge consumed by the
	// external Caddy process. It must start before Caddy and stop after it.
	CertificateBroker Component
	// Certificates owns the authenticated server-to-edge TLS certificate
	// distribution loop. It is optional for a legacy/static deployment, but
	// when supplied it must be stopped before carrier listeners are closed.
	Certificates Component
	Preview      Component
	Node         Component
	Routes       Component
	Hook         Component
	Gateway      Component
	FRPS         Component
	Caddy        Component
	CaddyReady   Component
	Usage        Component
}

type DataPlane struct {
	spec    DataPlaneSpec
	mu      sync.Mutex
	started []Component
	closed  bool
}

func NewDataPlane(spec DataPlaneSpec) (*DataPlane, error) {
	if spec.Persistence == nil || spec.Control == nil || spec.Node == nil || spec.Routes == nil || spec.Hook == nil || spec.Gateway == nil || spec.FRPS == nil || spec.Caddy == nil || spec.CaddyReady == nil || spec.Usage == nil {
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
	// Start the Caddy process before any control-plane publication. The process
	// can bind its public listener while the bootstrap control/node workers
	// register this edge as not-ready. Certificate distribution then has a live
	// broker and Caddy process to serve, and only after the explicit CaddyReady
	// probe may route/carrier workers publish readiness or accept assignments.
	components := []Component{d.spec.Persistence, d.spec.Hook, d.spec.Gateway, d.spec.FRPS}
	if d.spec.CertificateBroker != nil {
		components = append(components, d.spec.CertificateBroker)
	}
	components = append(components, d.spec.Caddy, d.spec.Control, d.spec.Node)
	if d.spec.Certificates != nil {
		components = append(components, d.spec.Certificates)
	}
	components = append(components, d.spec.CaddyReady)
	if d.spec.Preview != nil {
		// Publish and ACK the complete admission snapshot before opening the
		// carrier listener. Hosts are permitted to dial only after that ACK, and
		// the listener's PeerBinding therefore sees the admitted identity on the
		// first connection.
		components = append(components, d.spec.Preview)
	}
	if d.spec.Carrier != nil {
		components = append(components, d.spec.Carrier)
	}
	components = append(components, d.spec.Routes, d.spec.Usage)
	for _, component := range components {
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
	order := []Component{d.spec.Usage, d.spec.Routes}
	if d.spec.Preview != nil {
		// Reconcile and detach preview routes while authenticated carrier peers
		// are still alive. Carrier shutdown follows this component.
		order = append(order, d.spec.Preview)
	}
	if d.spec.Certificates != nil {
		// Stop pulling/acknowledging certificate actions before carrier
		// shutdown. The receiver drops private key material on close.
		order = append(order, d.spec.Certificates)
	}
	if d.spec.Carrier != nil {
		// Stop intake and close active carrier streams before route, gateway,
		// and process teardown. This preserves the connector drain boundary.
		order = append(order, d.spec.Carrier)
	}
	order = append(order, d.spec.CaddyReady, d.spec.Caddy)
	if d.spec.CertificateBroker != nil {
		order = append(order, d.spec.CertificateBroker)
	}
	order = append(order, d.spec.Node, d.spec.Control, d.spec.FRPS, d.spec.Gateway, d.spec.Hook, d.spec.Persistence)
	var failures []error
	for _, component := range order {
		if err := component.Shutdown(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	d.started = nil
	return errors.Join(failures...)
}
