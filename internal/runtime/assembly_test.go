package runtime

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAssemblyOwnsHookAndChildProcesses(t *testing.T) {
	var events []string
	var lock sync.Mutex
	component := func(name string) Component { return orderedComponent{name: name, events: &events, mu: &lock} }
	process := ProcessSpec{Name: "test-process", Path: "/bin/sh", Args: []string{"-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}, MaxOutputBytes: 1024}
	assembly, err := NewAssembly(AssemblySpec{
		Persistence:    component("store"),
		Control:        component("control"),
		Node:           component("node"),
		Routes:         component("routes"),
		Usage:          component("usage"),
		CaddyReady:     component("caddy-ready"),
		GatewayAddress: "127.0.0.1:19092",
		GatewayHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Bundle:         Bundle{CaddyProcess: ProcessSpec{Name: "test-caddy", Path: process.Path, Args: process.Args, MaxOutputBytes: process.MaxOutputBytes}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assembly.Gateway.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := assembly.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := events, []string{"start:store", "start:control", "start:node", "start:caddy-ready", "start:routes", "start:usage", "stop:usage", "stop:routes", "stop:caddy-ready", "stop:node", "stop:control", "stop:store"}; !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestAssemblyRejectsIncompletePolicyAndBundle(t *testing.T) {
	if _, err := NewAssembly(AssemblySpec{}); err == nil {
		t.Fatal("incomplete assembly accepted")
	}
}

func TestAssemblySurfacesExhaustedChildRestart(t *testing.T) {
	var events []string
	var lock sync.Mutex
	component := func(name string) Component { return orderedComponent{name: name, events: &events, mu: &lock} }
	exiting := ProcessSpec{Name: "caddy", Path: "/bin/sh", Args: []string{"-c", "exit 1"}, MaxOutputBytes: 1024, RestartLimit: 1, RestartBackoff: time.Millisecond, RestartMaxWait: time.Millisecond}
	assembly, err := NewAssembly(AssemblySpec{
		Persistence: component("store"), Control: component("control"), Node: component("node"), Routes: component("routes"), Usage: component("usage"),
		CaddyReady:     component("caddy-ready"),
		GatewayAddress: "127.0.0.1:19092", GatewayHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Bundle: Bundle{CaddyProcess: exiting},
	})
	if err != nil {
		t.Fatal(err)
	}
	assembly.Gateway.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-assembly.Done():
		if err == nil || !strings.Contains(err.Error(), "Caddy") {
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
