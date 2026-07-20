package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/testedge"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

type routeSourceFunc func(context.Context, string) ([]control.RouteAssignment, error)

func (f routeSourceFunc) DesiredRoutes(ctx context.Context, nodeID string) ([]control.RouteAssignment, error) {
	return f(ctx, nodeID)
}

type routeObserver struct {
	observations []control.RouteObservation
	nodeID       string
	err          error
}

func (o *routeObserver) ObserveRoutes(_ context.Context, nodeID string, observations []control.RouteObservation) error {
	o.nodeID = nodeID
	o.observations = append([]control.RouteObservation(nil), observations...)
	return o.err
}

type toggledRouteSource struct {
	mu     sync.Mutex
	err    error
	called chan struct{}
}

func (s *toggledRouteSource) DesiredRoutes(context.Context, string) ([]control.RouteAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.called != nil {
		s.called <- struct{}{}
	}
	return nil, s.err
}

func TestUsageWorkerRetriesAndFlushesOnShutdown(t *testing.T) {
	queue, _ := usage.NewQueue(2, 1024)
	report := usage.Report{OperationID: "op_1", Key: usage.Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Revision: 1, Direction: "egress"}, Bytes: 10, Interval: [2]time.Time{time.Unix(1, 0), time.Unix(2, 0)}, Payload: []byte("test")}
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	sink := &usageSink{failures: 1, signal: make(chan struct{}, 2)}
	pulse := make(chan time.Time, 2)
	worker := &UsageWorker{Queue: queue, Sink: sink, Pulse: pulse}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pulse <- time.Unix(3, 0)
	select {
	case <-sink.signal:
	case <-time.After(time.Second):
		t.Fatal("worker did not attempt delivery")
	}
	if worker.LastError() == nil {
		t.Fatal("uncertain delivery not exposed")
	}
	pulse <- time.Unix(4, 0)
	select {
	case <-sink.signal:
	case <-time.After(time.Second):
		t.Fatal("worker did not retry delivery")
	}
	if worker.LastError() != nil {
		t.Fatalf("delivery error not cleared: %v", worker.LastError())
	}
	if err := worker.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	calls := sink.calls
	sink.mu.Unlock()
	if queue.Len() != 0 || calls != 2 {
		t.Fatalf("queue=%d calls=%d", queue.Len(), calls)
	}
}

type usageSink struct {
	mu       sync.Mutex
	calls    int
	failures int
	signal   chan struct{}
}

func (s *usageSink) ReportUsage(context.Context, control.UsageReport) (control.UsageResult, error) {
	s.mu.Lock()
	s.calls++
	if s.signal != nil {
		s.signal <- struct{}{}
	}
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return control.UsageResult{}, errors.New("uncertain")
	}
	s.mu.Unlock()
	return control.UsageResult{Delta: 10}, nil
}

func TestNodeWorkerReportsReadyAndDrain(t *testing.T) {
	state := node.New("edge")
	state.MarkReady()
	manager, _ := node.NewManager(state, 2)
	fake := testedge.New()
	pulse := make(chan time.Time, 1)
	now := time.Unix(10, 0)
	worker := &NodeWorker{Manager: manager, Sink: fake, Registration: control.NodeRegistration{NodeID: "edge", ProcessEpoch: "process", Capacity: 2}, Pulse: pulse, Now: func() time.Time { return now }}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observation, _ := fake.Node("edge"); !observation.Ready {
		t.Fatalf("initial = %+v", observation)
	}
	state.BeginDrain(now.Add(time.Minute))
	if err := worker.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observation, _ := fake.Node("edge"); observation.Ready || !observation.Draining {
		t.Fatalf("final = %+v", observation)
	}
}

func TestWorkersStopWhenPulseCloses(t *testing.T) {
	queue, _ := usage.NewQueue(1, 1024)
	pulse := make(chan time.Time)
	worker := &UsageWorker{Queue: queue, Sink: &usageSink{}, Pulse: pulse}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(pulse)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	state := node.New("edge")
	state.MarkReady()
	manager, _ := node.NewManager(state, 1)
	nodePulse := make(chan time.Time)
	fake := testedge.New()
	nodeWorker := &NodeWorker{Manager: manager, Sink: fake, Registration: control.NodeRegistration{NodeID: "edge", ProcessEpoch: "p", Capacity: 1}, Pulse: nodePulse}
	if err := nodeWorker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(nodePulse)
	if err := nodeWorker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRouteWorkerReplacesAuthoritativeSnapshotAtomically(t *testing.T) {
	registry := route.NewRegistry()
	state := node.New("edge")
	state.MarkReady()
	fake := testedge.New()
	if err := fake.SetRoute(control.RouteAssignment{RouteID: "route", Revision: 2, Environment: "env", Generation: 1, NodeID: "edge", Kind: "helper_https_wss", PublicHost: "app.example.test", TargetHost: "127.0.0.1", TargetPort: 8080}); err != nil {
		t.Fatal(err)
	}
	pulse := make(chan time.Time, 1)
	observer := &routeObserver{}
	worker := &RouteWorker{Registry: registry, Source: fake, Observer: observer, State: state, NodeID: "edge", Pulse: pulse}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attachment, ok := registry.Get("route"); !ok || attachment.Revision != 2 {
		t.Fatalf("attachment = %+v, present=%v", attachment, ok)
	}
	if observer.nodeID != "edge" || len(observer.observations) != 1 || observer.observations[0].RouteRevision != 2 || observer.observations[0].ConnectorGeneration != 1 {
		t.Fatalf("observations = %#v", observer.observations)
	}
	close(pulse)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRouteWorkerRejectsForeignNodeSnapshot(t *testing.T) {
	registry := route.NewRegistry()
	state := node.New("edge")
	state.MarkReady()
	current := route.Attachment{ID: "route", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Host: "app.example.test", Target: "127.0.0.1:8080", Kind: route.HelperHTTPSWSS}
	if _, err := registry.Attach(current); err != nil {
		t.Fatal(err)
	}
	worker := &RouteWorker{Registry: registry, Source: routeSourceFunc(func(context.Context, string) ([]control.RouteAssignment, error) {
		return []control.RouteAssignment{{RouteID: "replacement", Revision: 2, Environment: "env", Generation: 2, NodeID: "other", Kind: "helper_https_wss", PublicHost: "other.example.test", TargetHost: "127.0.0.1", TargetPort: 8081}}, nil
	}), State: state, NodeID: "edge", Pulse: make(chan time.Time, 1)}
	if err := worker.Start(context.Background()); err == nil {
		t.Fatal("foreign snapshot accepted")
	}
	if got, ok := registry.Get(current.ID); !ok || got != current {
		t.Fatalf("registry mutated: %+v, present=%v", got, ok)
	}
}

func TestRouteWorkerExposesAndClearsRefreshError(t *testing.T) {
	state := node.New("edge")
	state.MarkReady()
	source := &toggledRouteSource{err: errors.New("control unavailable"), called: make(chan struct{}, 4)}
	pulse := make(chan time.Time, 1)
	worker := &RouteWorker{Registry: route.NewRegistry(), Source: source, State: state, NodeID: "edge", Pulse: pulse}
	if err := worker.Start(context.Background()); err == nil {
		t.Fatal("initial unavailable source accepted")
	}
	<-source.called
	// Start errors are returned synchronously; a running worker records refresh errors.
	source.mu.Lock()
	source.err = nil
	source.mu.Unlock()
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-source.called
	source.mu.Lock()
	source.err = errors.New("temporary failure")
	source.mu.Unlock()
	pulse <- time.Now()
	<-source.called
	if worker.LastError() == nil {
		t.Fatal("refresh error not exposed")
	}
	if state.Snapshot().Ready {
		t.Fatal("control failure did not clear readiness")
	}
	source.mu.Lock()
	source.err = nil
	source.mu.Unlock()
	pulse <- time.Now()
	<-source.called
	if worker.LastError() != nil {
		t.Fatalf("refresh error not cleared: %v", worker.LastError())
	}
	if !state.Snapshot().Ready {
		t.Fatal("control recovery did not restore readiness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
