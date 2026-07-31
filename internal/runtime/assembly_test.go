package runtime

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgefrp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type loginResolverFunc func(context.Context, edgefrp.LoginContent) (admission.Request, error)

func (f loginResolverFunc) ResolveLogin(ctx context.Context, login edgefrp.LoginContent) (admission.Request, error) {
	return f(ctx, login)
}

func TestAssemblyOwnsHookAndChildProcesses(t *testing.T) {
	address := freeLoopbackAddress(t)
	var events []string
	var lock sync.Mutex
	component := func(name string) Component { return orderedComponent{name: name, events: &events, mu: &lock} }
	process := ProcessSpec{Name: "test-process", Path: "/bin/sh", Args: []string{"-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}, MaxOutputBytes: 1024}
	adapter := edgefrp.NewAdapter(&admission.Service{}, route.NewRegistry("preview.example.test", "example.test"))
	assembly, err := NewAssembly(AssemblySpec{
		Persistence:    component("store"),
		Control:        component("control"),
		Node:           component("node"),
		Routes:         component("routes"),
		Usage:          component("usage"),
		CaddyReady:     component("caddy-ready"),
		HookAddress:    address,
		GatewayAddress: "127.0.0.1:19092",
		GatewayHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		HookPath:       "/private/paperboat-hook",
		Policy: edgefrp.Policy{Adapter: adapter, Resolver: loginResolverFunc(func(context.Context, edgefrp.LoginContent) (admission.Request, error) {
			return admission.Request{}, nil
		}), InternalAuthToken: "01234567890123456789012345678901"},
		Bundle: Bundle{FRPSProcess: process, CaddyProcess: ProcessSpec{Name: "test-caddy", Path: process.Path, Args: process.Args, MaxOutputBytes: process.MaxOutputBytes}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assembly.Hook.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	assembly.Gateway.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := assembly.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := events, []string{"start:store", "start:caddy-ready", "start:control", "start:node", "start:routes", "start:usage", "stop:caddy-ready", "stop:routes", "stop:usage", "stop:node", "stop:control", "stop:store"}; !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestAssemblyRejectsIncompletePolicyAndBundle(t *testing.T) {
	if _, err := NewAssembly(AssemblySpec{}); err == nil {
		t.Fatal("incomplete assembly accepted")
	}
}

func TestAssemblySurfacesExhaustedChildRestart(t *testing.T) {
	address := freeLoopbackAddress(t)
	var events []string
	var lock sync.Mutex
	component := func(name string) Component { return orderedComponent{name: name, events: &events, mu: &lock} }
	exiting := ProcessSpec{Name: "frps", Path: "/bin/sh", Args: []string{"-c", "exit 1"}, MaxOutputBytes: 1024, RestartLimit: 1, RestartBackoff: time.Millisecond, RestartMaxWait: time.Millisecond}
	running := ProcessSpec{Name: "caddy", Path: "/bin/sh", Args: []string{"-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}, MaxOutputBytes: 1024}
	adapter := edgefrp.NewAdapter(&admission.Service{}, route.NewRegistry("preview.example.test", "example.test"))
	assembly, err := NewAssembly(AssemblySpec{
		Persistence: component("store"), Control: component("control"), Node: component("node"), Routes: component("routes"), Usage: component("usage"),
		CaddyReady:  component("caddy-ready"),
		HookAddress: address, GatewayAddress: "127.0.0.1:19092", GatewayHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), HookPath: "/private/paperboat-hook",
		Policy: edgefrp.Policy{Adapter: adapter, Resolver: loginResolverFunc(func(context.Context, edgefrp.LoginContent) (admission.Request, error) {
			return admission.Request{}, nil
		}), InternalAuthToken: "01234567890123456789012345678901"},
		Bundle: Bundle{FRPSProcess: exiting, CaddyProcess: running},
	})
	if err != nil {
		t.Fatal(err)
	}
	assembly.Hook.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	assembly.Gateway.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-assembly.Done():
		if err == nil || !strings.Contains(err.Error(), "frps") {
			t.Fatalf("unexpected assembly error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("assembly did not surface exhausted child restart")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := assembly.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	return "127.0.0.1:19091"
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
