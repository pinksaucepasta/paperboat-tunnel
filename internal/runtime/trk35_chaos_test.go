package runtime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestTRK35RouteWorkerLostAckRestartAndIdempotentReconcile(t *testing.T) {
	publicKey, thumbprint := durableWorkerIdentity(t)
	assignment := durableWorkerAssignment(publicKey, thumbprint, "route_trk35", "assignment_trk35", route.TunnelHTTPSWSS)
	source := &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{assignment}, Complete: true, Canonical: true}}
	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	state := node.New("edge_1")
	state.MarkReady()
	observer := &trk35RouteObserver{failures: 1, failure: errors.New("lost route ACK")}
	worker := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{},
		DurableAdmissions: durable, Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := worker.Start(context.Background()); !errors.Is(err, observer.failure) {
		t.Fatalf("lost ACK start error = %v, want %v", err, observer.failure)
	}
	if canonical.HasActiveGeneration() || canonical.Generation() != 0 {
		t.Fatalf("lost ACK promoted a route generation: generation=%d active=%v", canonical.Generation(), canonical.HasActiveGeneration())
	}
	if got := len(durable.Snapshot()); got != 1 {
		t.Fatalf("lost ACK discarded durable admission: got %d", got)
	}

	// A restarted worker reuses the staged candidate, observes the same exact
	// assignment, and activates it once the durable ACK boundary succeeds.
	restarted := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{},
		DurableAdmissions: durable, Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := canonical.Generation(); got != 1 {
		t.Fatalf("restart generation = %d, want 1", got)
	}
	if _, err := canonical.Match(assignment.PublicHost, "/"); err != nil {
		t.Fatalf("restart did not activate canonical route: %v", err)
	}
	if got := observer.calls.Load(); got != 2 {
		t.Fatalf("route ACK calls after restart = %d, want 2", got)
	}

	// Replaying the unchanged complete snapshot is an idempotent reconciliation:
	// it refreshes admissions/observation but does not create another generation.
	if err := restarted.reconcile(context.Background()); err != nil {
		t.Fatalf("idempotent reconcile: %v", err)
	}
	if got := canonical.Generation(); got != 1 {
		t.Fatalf("idempotent reconcile changed generation to %d", got)
	}
	if got := observer.calls.Load(); got != 3 {
		t.Fatalf("route ACK calls after replay = %d, want 3", got)
	}
	if got := len(durable.Snapshot()); got != 1 || durable.Snapshot()[0].AssignmentID != assignment.AssignmentID {
		t.Fatalf("idempotent reconcile changed admissions: %+v", durable.Snapshot())
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := restarted.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
}

type trk35RouteObserver struct {
	mu       sync.Mutex
	observed []control.RouteObservation
	failures int
	failure  error
	calls    atomic.Int32
}

func (o *trk35RouteObserver) ObserveRoutes(_ context.Context, _ string, observations []control.RouteObservation) error {
	o.calls.Add(1)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failures > 0 {
		o.failures--
		return o.failure
	}
	o.observed = append(o.observed, observations...)
	return nil
}
