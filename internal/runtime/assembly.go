package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgefrp"
)

type AssemblySpec struct {
	Persistence    Component
	Control        Component
	Node           Component
	Routes         Component
	Usage          Component
	CaddyReady     Component
	HookAddress    string
	GatewayAddress string
	GatewayHandler http.Handler
	HookPath       string
	Policy         edgefrp.Policy
	HookReject     func(operation, reason string)
	HookObserve    func(operation string, rejected bool)
	Bundle         Bundle
}

type Assembly struct {
	dataPlane *DataPlane
	Hook      *HTTPServer
	Gateway   *HTTPServer
	FRPS      *SupervisedProcess
	Caddy     *SupervisedProcess
	done      chan error
}

func NewAssembly(spec AssemblySpec) (*Assembly, error) {
	if spec.Persistence == nil || spec.Control == nil || spec.Node == nil || spec.Routes == nil || spec.Usage == nil || spec.CaddyReady == nil || spec.HookPath == "" || spec.Policy.Adapter == nil || spec.Policy.Resolver == nil || len(spec.Policy.InternalAuthToken) < 32 {
		return nil, fmt.Errorf("assembly dependencies: %w", ErrProcessInvalid)
	}
	hook, err := NewHTTPServer(HTTPServerSpec{
		Address:           spec.HookAddress,
		Handler:           edgefrp.Hook{Path: spec.HookPath, Handle: spec.Policy.Handle, SessionKey: spec.Policy.SessionKey, Reject: spec.HookReject, Observe: spec.HookObserve},
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("assembly hook: %w", err)
	}
	if spec.GatewayAddress == "" || spec.GatewayHandler == nil {
		return nil, fmt.Errorf("assembly gateway: %w", ErrProcessInvalid)
	}
	gateway, err := NewHTTPServer(HTTPServerSpec{Address: spec.GatewayAddress, Handler: spec.GatewayHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10})
	if err != nil {
		return nil, fmt.Errorf("assembly gateway: %w", err)
	}
	frps, err := NewSupervisedProcess(spec.Bundle.FRPSProcess)
	if err != nil {
		return nil, fmt.Errorf("assembly frps: %w", err)
	}
	caddy, err := NewSupervisedProcess(spec.Bundle.CaddyProcess)
	if err != nil {
		return nil, fmt.Errorf("assembly Caddy: %w", err)
	}
	dataPlane, err := NewDataPlane(DataPlaneSpec{
		Persistence: spec.Persistence,
		Control:     spec.Control,
		Node:        spec.Node,
		Routes:      spec.Routes,
		Usage:       spec.Usage,
		Hook:        hook,
		Gateway:     gateway,
		FRPS:        frps,
		Caddy:       caddy,
		CaddyReady:  spec.CaddyReady,
	})
	if err != nil {
		return nil, fmt.Errorf("assembly lifecycle: %w", err)
	}
	return &Assembly{dataPlane: dataPlane, Hook: hook, Gateway: gateway, FRPS: frps, Caddy: caddy, done: make(chan error, 1)}, nil
}

func (a *Assembly) Start(ctx context.Context) error {
	if a == nil || a.dataPlane == nil {
		return ErrProcessInvalid
	}
	if err := a.dataPlane.Start(ctx); err != nil {
		return err
	}
	go a.watchChild("frps", a.FRPS)
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
