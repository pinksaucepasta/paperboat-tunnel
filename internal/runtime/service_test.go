package runtime

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
)

type recordingComponent struct {
	mu       *sync.Mutex
	events   *[]string
	name     string
	startErr error
}

type failureComponent struct {
	recordingComponent
	done chan error
}

func (c failureComponent) Done() <-chan error { return c.done }

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener { return &blockingListener{closed: make(chan struct{})} }

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return testAddress("health") }

type testAddress string

func (a testAddress) Network() string { return "test" }
func (a testAddress) String() string  { return string(a) }

func (c recordingComponent) Start(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.events = append(*c.events, "start:"+c.name)
	return c.startErr
}

func (c recordingComponent) Shutdown(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.events = append(*c.events, "stop:"+c.name)
	return nil
}

func TestServiceOrdersStartupAndShutdown(t *testing.T) {
	var mu sync.Mutex
	var events []string
	cfg := config.Config{NodeID: "edge_test_01", HealthAddress: "127.0.0.1:1", ShutdownTimeout: time.Second}
	state := node.New(cfg.NodeID)
	service := New(cfg, state,
		recordingComponent{mu: &mu, events: &events, name: "store"},
		recordingComponent{mu: &mu, events: &events, name: "control"},
	)
	service.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !state.Snapshot().Ready {
		t.Fatal("node not ready after startup")
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"start:store", "start:control", "stop:control", "stop:store"}
	if len(events) != len(want) {
		t.Fatalf("events = %v", events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v", events)
		}
	}
	if state.Snapshot().Live {
		t.Fatal("node remains live after shutdown")
	}
}

func TestServiceCleansUpPartialStartup(t *testing.T) {
	var mu sync.Mutex
	var events []string
	cfg := config.Config{NodeID: "edge_test_01", HealthAddress: "127.0.0.1:1", ShutdownTimeout: time.Second}
	state := node.New(cfg.NodeID)
	service := New(cfg, state,
		recordingComponent{mu: &mu, events: &events, name: "store"},
		recordingComponent{mu: &mu, events: &events, name: "control", startErr: errors.New("unavailable")},
	)
	service.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := service.Start(context.Background()); err == nil {
		t.Fatal("startup succeeded")
	}
	want := []string{"start:store", "start:control", "stop:store"}
	if len(events) != len(want) {
		t.Fatalf("events = %v", events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v", events)
		}
	}
	if state.Snapshot().Live {
		t.Fatal("node remains live after failed startup")
	}
}

func TestServicePropagatesComponentFailure(t *testing.T) {
	var mu sync.Mutex
	var events []string
	failures := make(chan error, 1)
	component := failureComponent{recordingComponent: recordingComponent{mu: &mu, events: &events, name: "data-plane"}, done: failures}
	cfg := config.Config{NodeID: "edge_test_01", HealthAddress: "127.0.0.1:1", ShutdownTimeout: time.Second}
	service := New(cfg, node.New(cfg.NodeID), component)
	service.listen = func(_, _ string) (net.Listener, error) { return newBlockingListener(), nil }
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := errors.New("frps exited")
	failures <- want
	select {
	case got := <-service.Done():
		if !errors.Is(got, want) {
			t.Fatalf("failure = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("component failure was not propagated")
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
