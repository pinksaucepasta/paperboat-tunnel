package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

type trustControlSource struct {
	mu       sync.Mutex
	document []byte
	err      error
	calls    chan struct{}
}

func (s *trustControlSource) DesiredRoutes(context.Context, string) ([]control.RouteAssignment, error) {
	return []control.RouteAssignment{}, nil
}
func (s *trustControlSource) Revocations(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return append([]byte(nil), s.document...), s.err
}

func TestControlDependencyLoadsAndRefreshesRevocationsAtomically(t *testing.T) {
	source := &trustControlSource{document: []byte(`{"jtis":[]}`), calls: make(chan struct{}, 8)}
	var mu sync.Mutex
	current := ""
	dependency := &ControlDependency{Source: source, TrustSource: source, NodeID: "edge", Interval: time.Millisecond, ApplyTrust: func(document []byte) error {
		if string(document) == "invalid" {
			return errors.New("invalid snapshot")
		}
		mu.Lock()
		current = string(document)
		mu.Unlock()
		return nil
	}}
	if err := dependency.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-source.calls
	source.mu.Lock()
	source.document = []byte(`{"jtis":["revoked"]}`)
	source.mu.Unlock()
	<-source.calls
	time.Sleep(2 * time.Millisecond)
	mu.Lock()
	got := current
	mu.Unlock()
	if got != `{"jtis":["revoked"]}` {
		t.Fatalf("snapshot = %s", got)
	}
	source.mu.Lock()
	source.document = []byte("invalid")
	source.mu.Unlock()
	for dependency.LastError() == nil {
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got = current
	mu.Unlock()
	if got != `{"jtis":["revoked"]}` {
		t.Fatalf("invalid refresh replaced snapshot: %s", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dependency.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestControlDependencyFailsStartupWithoutValidRevocations(t *testing.T) {
	source := &trustControlSource{document: []byte("invalid"), calls: make(chan struct{}, 1)}
	dependency := &ControlDependency{Source: source, TrustSource: source, NodeID: "edge", Interval: time.Second, ApplyTrust: func([]byte) error { return errors.New("invalid snapshot") }}
	if err := dependency.Start(context.Background()); err == nil {
		t.Fatal("invalid initial revocations accepted")
	}
}
