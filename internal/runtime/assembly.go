package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type AssemblySpec struct {
	Persistence Component
	Control     Component
	// Carrier owns authenticated connector-v1 carrier listeners and accepted
	// peers. It is optional for deployments which have not supplied the
	// server-owned endpoint/certificate/authorizer material yet.
	Carrier Component
	// CertificateBroker is the cross-process Caddy certificate selector. It
	// must be started before the supervised Caddy process.
	CertificateBroker Component
	// Certificates is the optional live server-to-edge certificate
	// distribution worker. It owns only in-memory edge key material.
	Certificates Component
	// Preview reconciles server-issued preview carrier admissions and must stop
	// before Carrier so route detach observations can use live peer handles.
	Preview        Component
	Node           Component
	Routes         Component
	PublicTCP      Component
	Usage          Component
	CaddyReady     Component
	GatewayAddress string
	GatewayHandler http.Handler
	Bundle         Bundle
}

type Assembly struct {
	dataPlane *DataPlane
	Gateway   *HTTPServer
	Caddy     *SupervisedProcess
	done      chan error
}

func NewAssembly(spec AssemblySpec) (*Assembly, error) {
	if spec.Persistence == nil || spec.Control == nil || spec.Node == nil || spec.Routes == nil || spec.Usage == nil || spec.CaddyReady == nil {
		return nil, fmt.Errorf("assembly dependencies: %w", ErrProcessInvalid)
	}
	if spec.GatewayAddress == "" || spec.GatewayHandler == nil {
		return nil, fmt.Errorf("assembly gateway: %w", ErrProcessInvalid)
	}
	gateway, err := NewHTTPServer(HTTPServerSpec{Address: spec.GatewayAddress, Handler: spec.GatewayHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10})
	if err != nil {
		return nil, fmt.Errorf("assembly gateway: %w", err)
	}
	caddy, err := NewSupervisedProcess(spec.Bundle.CaddyProcess)
	if err != nil {
		return nil, fmt.Errorf("assembly Caddy: %w", err)
	}
	dataPlane, err := NewDataPlane(DataPlaneSpec{
		Persistence:       spec.Persistence,
		Control:           spec.Control,
		Carrier:           spec.Carrier,
		CertificateBroker: spec.CertificateBroker,
		Certificates:      spec.Certificates,
		Preview:           spec.Preview,
		Node:              spec.Node,
		Routes:            spec.Routes,
		PublicTCP:         spec.PublicTCP,
		Usage:             spec.Usage,
		Gateway:           gateway,
		Caddy:             caddy,
		CaddyReady:        spec.CaddyReady,
	})
	if err != nil {
		return nil, fmt.Errorf("assembly lifecycle: %w", err)
	}
	return &Assembly{dataPlane: dataPlane, Gateway: gateway, Caddy: caddy, done: make(chan error, 1)}, nil
}

func (a *Assembly) Start(ctx context.Context) error {
	if a == nil || a.dataPlane == nil {
		return ErrProcessInvalid
	}
	if err := a.dataPlane.Start(ctx); err != nil {
		return err
	}
	go a.watchChild("Caddy", a.Caddy)
	return nil
}

func (a *Assembly) watchChild(name string, process *SupervisedProcess) {
	<-process.Done()
	err := process.Err()
	if err == nil {
		err = errors.New("child exited")
	}
	select {
	case a.done <- fmt.Errorf("%s: %w", name, err):
	default:
	}
}

func (a *Assembly) Done() <-chan error { return a.done }

func (a *Assembly) Shutdown(ctx context.Context) error {
	if a == nil || a.dataPlane == nil {
		return nil
	}
	return a.dataPlane.Shutdown(ctx)
}
