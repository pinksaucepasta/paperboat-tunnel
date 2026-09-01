package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type recoveryRouteSource struct {
	mu          sync.Mutex
	assignments []control.RouteAssignment
	err         error
	calls       chan struct{}
}

func (s *recoveryRouteSource) DesiredRoutes(context.Context, string) ([]control.RouteAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls != nil {
		select {
		case s.calls <- struct{}{}:
		default:
		}
	}
	return append([]control.RouteAssignment(nil), s.assignments...), s.err
}

type recoveryAccessorSource struct {
	mu    sync.Mutex
	err   error
	calls chan struct{}
}

func (s *recoveryAccessorSource) PrivateAccessCarrierAdmissions(context.Context, string, string) ([]control.PrivateAccessCarrierAdmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls != nil {
		select {
		case s.calls <- struct{}{}:
		default:
		}
	}
	return nil, s.err
}

func (s *recoveryAccessorSource) setError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func TestRouteWorkerTransientInitialControlOutageStartsAndRetries(t *testing.T) {
	state := node.New("edge")
	state.MarkReady()
	pulse := make(chan time.Time, 1)
	source := &recoveryRouteSource{err: control.ErrControlUnavailable, calls: make(chan struct{}, 4)}
	worker := &RouteWorker{Registry: route.NewRegistry("preview.example.test", "example.test"), Source: source, State: state, NodeID: "edge", Pulse: pulse}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("start on transient outage = %v", err)
	}
	if got := state.Snapshot(); !got.Ready {
		t.Fatalf("transient initial outage withdrew ready state: %+v", got)
	}
	if !errors.Is(worker.LastError(), control.ErrControlUnavailable) {
		t.Fatalf("initial error = %v", worker.LastError())
	}
	select {
	case <-source.calls:
	default:
		t.Fatal("initial route reconcile was not observed")
	}
	source.mu.Lock()
	source.err = nil
	source.mu.Unlock()
	pulse <- time.Now()
	select {
	case <-source.calls:
	case <-time.After(time.Second):
		t.Fatal("route worker did not retry after pulse")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if worker.LastError() == nil && state.Snapshot().Ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry state = error:%v node:%+v", worker.LastError(), state.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRouteWorkerPrivateOutageDoesNotBlockPublicProgressOrEraseLKG(t *testing.T) {
	public := route.Attachment{ID: "public_route", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Kind: route.HelperHTTPSWSS, Host: "public.example.test", Target: "127.0.0.1:8080"}
	registry := route.NewRegistry("preview.example.test", "example.test")
	if _, err := registry.Attach(public); err != nil {
		t.Fatal(err)
	}
	publicKey, thumbprint := durableWorkerIdentity(t)
	existing := datacarrier.DurableAdmission{
		Identity:   datacarrier.Identity{AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 1, Generation: 1},
		EdgeNodeID: "edge", EdgeProcessEpoch: "edge_epoch", AssignmentID: "assignment_1", RouteID: "route_1", AssignmentGeneration: 1, RouteGeneration: 1,
		ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: thumbprint, State: "active",
	}
	accessorAdmissions, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge", ProcessEpoch: "edge_epoch"})
	if err != nil {
		t.Fatal(err)
	}
	if err := accessorAdmissions.Replace([]datacarrier.DurableAdmission{existing}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	source := &recoveryRouteSource{assignments: []control.RouteAssignment{{RouteID: public.ID, Revision: public.Revision, Environment: public.Environment, Generation: public.Generation, NodeID: public.Node, Kind: string(public.Kind), PublicHost: public.Host, TargetHost: "127.0.0.1", TargetPort: 8080}}, calls: make(chan struct{}, 4)}
	accessorSource := &recoveryAccessorSource{err: control.ErrControlUnavailable, calls: make(chan struct{}, 4)}
	state := node.New("edge")
	state.MarkReady()
	pulse := make(chan time.Time, 1)
	worker := &RouteWorker{Registry: registry, Source: source, State: state, NodeID: "edge", ProcessEpoch: "edge_epoch", AccessorSource: accessorSource, AccessorAdmissions: accessorAdmissions, Pulse: pulse}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("start with private outage = %v", err)
	}
	if _, err := registry.Match(public.Host, "/"); err != nil {
		t.Fatalf("public route was not reconciled: %v", err)
	}
	admissions := accessorAdmissions.Snapshot()
	if len(admissions) != 1 || admissions[0] != existing {
		t.Fatalf("private LKG changed: %+v", admissions)
	}
	if !errors.Is(worker.LastError(), control.ErrControlUnavailable) {
		t.Fatalf("degraded error = %v", worker.LastError())
	}
	if !state.Snapshot().Ready {
		t.Fatalf("private outage withdrew ready state: %+v", state.Snapshot())
	}
	select {
	case <-source.calls:
	default:
		t.Fatal("initial route reconcile was not observed")
	}
	select {
	case <-accessorSource.calls:
	default:
		t.Fatal("initial private admission reconcile was not observed")
	}
	accessorSource.setError(nil)
	pulse <- time.Now()
	select {
	case <-accessorSource.calls:
	case <-time.After(time.Second):
		t.Fatal("private admission retry did not run")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if worker.LastError() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery error = %v", worker.LastError())
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
