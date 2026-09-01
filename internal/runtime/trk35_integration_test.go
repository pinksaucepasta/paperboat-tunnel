package runtime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

// TestTRK35IntegratedRouteLifecycleFaultHarness composes the edge route worker,
// canonical matcher, durable admission authority, and a real yamux carrier.
// The host side is an in-memory origin goroutine. The sequence intentionally
// crosses process/control and data-plane boundaries instead of calling route
// state transitions in isolation:
//
//	control outage -> reconnect -> lost ACK -> process/carrier restart/replay
//	-> bounded overload -> failed replacement with old traffic retained
//	-> replacement recovery -> exact empty snapshot and carrier cleanup.
func TestTRK35IntegratedRouteLifecycleFaultHarness(t *testing.T) {
	publicKey, thumbprint := durableWorkerIdentity(t)
	oldAssignment := durableWorkerAssignment(publicKey, thumbprint, "route_trk35_integration", "assignment_trk35_old", route.TunnelHTTPSWSS)
	newAssignment := oldAssignment
	newAssignment.AssignmentID = "assignment_trk35_new"
	newAssignment.AssignmentGeneration = 2
	newAssignment.Revision = 2
	newAssignment.Generation = 2
	newAssignment.ConnectorSessionID = "session_trk35_new"
	newAssignment.ConnectorProcessGeneration = 2
	newAssignment.ConfigGeneration = 2
	newAssignment.State = "staged"
	newAssignment.ConfigContentHash = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"

	source := &trk35IntegrationRouteSource{
		snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{oldAssignment}, Complete: true, Canonical: true},
		err:      control.ErrControlUnavailable,
		calls:    make(chan struct{}, 16),
	}
	observer := &trk35IntegrationRouteObserver{failNext: errTrk35IntegrationLostACK}
	canonical, err := route.NewRegistryWithOptions("", "", route.GenerationRegistryOptions{MaximumStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	durableAdmissions, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	carrierRoutes, err := edgehttp.NewDataCarrierRouteRegistry(edgehttp.DataCarrierRouteRegistryConfig{MaximumRoutes: 8})
	if err != nil {
		t.Fatal(err)
	}
	carrier := &trk35IntegrationCarrier{registry: carrierRoutes}
	t.Cleanup(func() {
		_ = carrierRoutes.Close()
		_ = durableAdmissions.Close()
		_ = canonical.Close()
	})

	firstPair, err := newTRK35IntegrationCarrierPair(oldAssignment, durableAdmissions)
	if err != nil {
		t.Fatal(err)
	}
	pairs := []*trk35IntegrationCarrierPair{firstPair}
	t.Cleanup(func() {
		for _, pair := range pairs {
			_ = pair.Close()
		}
	})
	if err := carrierRoutes.AttachReplica(firstPair.server, publicKey, thumbprint, trk35IntegrationReplicaState(oldAssignment)); err != nil {
		t.Fatal(err)
	}

	state := node.New("edge_1")
	if !state.MarkReady() {
		t.Fatal("edge state did not enter ready phase")
	}
	pulse := make(chan time.Time, 16)
	worker := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: carrier,
		DurableAdmissions: durableAdmissions, Pulse: pulse, DrainTimeout: 250 * time.Millisecond,
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("start during control outage: %v", err)
	}
	trks35IntegrationAwaitCall(t, source.calls)
	if !errors.Is(worker.LastError(), control.ErrControlUnavailable) {
		t.Fatalf("initial control error = %v", worker.LastError())
	}
	if got := canonical.Generation(); got != 0 {
		t.Fatalf("control outage activated generation %d", got)
	}
	if !state.Snapshot().Ready {
		t.Fatal("transient control outage withdrew edge readiness")
	}

	// Reconnect control. The first complete snapshot reaches the real carrier,
	// but its ACK response is lost. The candidate remains pending and no route
	// generation is promoted.
	source.setError(nil)
	trks35IntegrationPulse(t, pulse, source.calls)
	trks35IntegrationWait(t, func() bool {
		return errors.Is(worker.LastError(), errTrk35IntegrationLostACK) && canonical.Generation() == 0
	})
	if got := firstPair.probes.Load(); got != 1 {
		t.Fatalf("lost-ACK origin probes = %d, want 1", got)
	}
	if got := len(durableAdmissions.Snapshot()); got != 1 {
		t.Fatalf("lost-ACK durable candidate count = %d, want 1", got)
	}

	// Kill the process/carrier incarnation. A fresh worker and carrier replay
	// the same authoritative snapshot and commit it exactly once.
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	if err := worker.Shutdown(shutdownContext); err != nil {
		cancelShutdown()
		t.Fatal(err)
	}
	cancelShutdown()
	if err := carrierRoutes.Detach(firstPair.server); err != nil {
		t.Fatal(err)
	}
	if err := firstPair.Close(); err != nil {
		t.Fatal(err)
	}

	secondPair, err := newTRK35IntegrationCarrierPair(oldAssignment, durableAdmissions)
	if err != nil {
		t.Fatal(err)
	}
	pairs = append(pairs, secondPair)
	if err := carrierRoutes.AttachReplica(secondPair.server, publicKey, thumbprint, trk35IntegrationReplicaState(oldAssignment)); err != nil {
		t.Fatal(err)
	}
	restartedPulse := make(chan time.Time, 16)
	restarted := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: carrier,
		DurableAdmissions: durableAdmissions, Pulse: restartedPulse, DrainTimeout: 250 * time.Millisecond,
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatalf("replay after process/carrier restart: %v", err)
	}
	// Start performs one synchronous snapshot pull. Drain that call before
	// pulses so each later wait corresponds to the pulse just sent.
	trks35IntegrationAwaitCall(t, source.calls)
	if got := canonical.Generation(); got != 1 {
		t.Fatalf("replayed canonical generation = %d, want 1", got)
	}
	if got := secondPair.probes.Load(); got != 1 {
		t.Fatalf("replayed origin probes = %d, want 1", got)
	}
	if got := len(observer.snapshot()); got != 1 || observer.snapshot()[0].AssignmentID != oldAssignment.AssignmentID {
		t.Fatalf("replayed ACK observations = %+v", observer.snapshot())
	}

	// A real route lease and carrier stream consume the one-stream budget. The
	// next request is rejected synchronously, proving overload is bounded and
	// does not create an untracked carrier stream.
	lease, match, err := canonical.Acquire(context.Background(), oldAssignment.PublicHost, "/held")
	if err != nil {
		t.Fatalf("acquire first route stream: %v", err)
	}
	heldStream, err := carrier.OpenRouteStream(context.Background(), match.Rule, "hold_trk35_old")
	if err != nil {
		_ = lease.Close()
		t.Fatalf("open first carrier stream: %v", err)
	}
	if _, err := secondPair.waitHeld(context.Background(), "hold_trk35_old"); err != nil {
		_ = heldStream.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if _, _, err := canonical.Acquire(context.Background(), oldAssignment.PublicHost, "/overloaded"); !errors.Is(err, route.ErrStreamOverloaded) {
		t.Fatalf("second route acquire error = %v, want ErrStreamOverloaded", err)
	}
	if got := secondPair.client.ActiveStreams(); got > 1 {
		t.Fatalf("carrier streams exceeded route budget: %d", got)
	}
	if err := heldStream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	trks35IntegrationWait(t, func() bool {
		return secondPair.client.ActiveStreams() == 0 && secondPair.server.ActiveStreams() == 0
	})

	// A control disconnect while the old generation is active must keep the
	// last-known-good route. Once control reconnects, a carrier/origin failure
	// rejects the replacement without withdrawing that active generation.
	source.setError(control.ErrControlUnavailable)
	trks35IntegrationPulse(t, restartedPulse, source.calls)
	trks35IntegrationWait(t, func() bool {
		return errors.Is(restarted.LastError(), control.ErrControlUnavailable) && canonical.Generation() == 1
	})
	if !state.Snapshot().Ready {
		t.Fatal("control reconnect outage withdrew the last-known-good readiness")
	}
	source.setSnapshot(control.RouteSnapshot{Routes: []control.RouteAssignment{oldAssignment, newAssignment}, Complete: true, Canonical: true})
	source.setError(nil)
	carrier.setProbeError(errors.New("origin is unavailable during replacement"))
	trks35IntegrationPulse(t, restartedPulse, source.calls)
	trks35IntegrationWait(t, func() bool {
		return errors.Is(restarted.LastError(), carrier.probeErrorValue()) && canonical.Generation() == 1
	})
	if state.Snapshot().Ready {
		t.Fatal("failed replacement remained marked ready")
	}
	lkgMatch, err := canonical.Match(oldAssignment.PublicHost, "/still-live")
	if err != nil {
		t.Fatalf("last-known-good route disappeared after failed replacement: %v", err)
	}
	if lkgMatch.Rule.AssignmentID != oldAssignment.AssignmentID {
		t.Fatalf("failed replacement changed the active route: %+v", lkgMatch.Rule)
	}

	// Retire the disconnected old carrier only after its generation has been
	// proven usable, then attach the replacement and replay the newer snapshot.
	if err := carrierRoutes.Detach(secondPair.server); err != nil {
		t.Fatal(err)
	}
	if err := secondPair.Close(); err != nil {
		t.Fatal(err)
	}
	thirdPair, err := newTRK35IntegrationCarrierPair(newAssignment, durableAdmissions)
	if err != nil {
		t.Fatal(err)
	}
	pairs = append(pairs, thirdPair)
	if err := carrierRoutes.AttachReplica(thirdPair.server, publicKey, thumbprint, trk35IntegrationReplicaState(newAssignment)); err != nil {
		t.Fatal(err)
	}
	newAssignment.State = "staged"
	source.setSnapshot(control.RouteSnapshot{Routes: []control.RouteAssignment{oldAssignment, newAssignment}, Complete: true, Canonical: true})
	carrier.setProbeError(nil)
	trks35IntegrationPulse(t, restartedPulse, source.calls)
	trks35IntegrationWait(t, func() bool {
		return restarted.LastError() == nil && canonical.Generation() == 2 && state.Snapshot().Ready
	})
	if got := thirdPair.probes.Load(); got != 1 {
		t.Fatalf("replacement origin probes = %d, want 1", got)
	}
	recoveredMatch, err := canonical.Match(newAssignment.PublicHost, "/recovered")
	if err != nil {
		t.Fatalf("replacement route did not recover: %v", err)
	}
	if recoveredMatch.Rule.AssignmentID != newAssignment.AssignmentID {
		t.Fatalf("replacement route matched the wrong assignment: %+v", recoveredMatch.Rule)
	}

	// A complete empty canonical snapshot is the terminal cleanup projection.
	// It must remove both the route and durable admission, not leave the old
	// session or a stale route selectable after the worker stops.
	source.setSnapshot(control.RouteSnapshot{Routes: nil, Complete: true, Canonical: true})
	trks35IntegrationPulse(t, restartedPulse, source.calls)
	trks35IntegrationWait(t, func() bool {
		return restarted.LastError() == nil && len(durableAdmissions.Snapshot()) == 0
	})
	if _, err := canonical.Match(newAssignment.PublicHost, "/after-cleanup"); !errors.Is(err, route.ErrNoMatch) {
		t.Fatalf("empty snapshot left a selectable route: %v", err)
	}
	if got := carrierRoutes.Len(); got != 1 {
		t.Fatalf("carrier registry before exact detach = %d, want 1", got)
	}
	if err := restarted.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := carrierRoutes.Detach(thirdPair.server); err != nil {
		t.Fatal(err)
	}
	if _, err := carrier.OpenRouteStream(context.Background(), recoveredMatch.Rule, "stale_trk35"); !errors.Is(err, edgehttp.ErrDataCarrierRouteUnavailable) {
		t.Fatalf("detached carrier accepted stale route session: %v", err)
	}
	if err := thirdPair.Close(); err != nil {
		t.Fatal(err)
	}
	trks35IntegrationWait(t, func() bool {
		return carrierRoutes.Len() == 0 && thirdPair.client.ActiveStreams() == 0 && thirdPair.server.ActiveStreams() == 0
	})
	if got := len(durableAdmissions.Snapshot()); got != 0 {
		t.Fatalf("durable admissions after exact cleanup = %d, want 0", got)
	}
}

type trk35IntegrationRouteSource struct {
	mu       sync.RWMutex
	snapshot control.RouteSnapshot
	err      error
	calls    chan struct{}
}

func (s *trk35IntegrationRouteSource) DesiredRouteSnapshot(context.Context, string, string) (control.RouteSnapshot, error) {
	s.mu.RLock()
	snapshot := s.snapshot
	snapshot.Routes = trk35IntegrationCloneAssignments(snapshot.Routes)
	err := s.err
	calls := s.calls
	s.mu.RUnlock()
	if calls != nil {
		select {
		case calls <- struct{}{}:
		default:
		}
	}
	return snapshot, err
}

func (s *trk35IntegrationRouteSource) DesiredRoutes(ctx context.Context, nodeID string) ([]control.RouteAssignment, error) {
	snapshot, err := s.DesiredRouteSnapshot(ctx, nodeID, "")
	return snapshot.Routes, err
}

func (s *trk35IntegrationRouteSource) setError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *trk35IntegrationRouteSource) setSnapshot(snapshot control.RouteSnapshot) {
	s.mu.Lock()
	s.snapshot = snapshot
	s.snapshot.Routes = trk35IntegrationCloneAssignments(snapshot.Routes)
	s.mu.Unlock()
}

func trk35IntegrationCloneAssignments(assignments []control.RouteAssignment) []control.RouteAssignment {
	result := make([]control.RouteAssignment, len(assignments))
	for index, assignment := range assignments {
		result[index] = assignment
		result[index].DomainBindings = append([]control.DomainBinding(nil), assignment.DomainBindings...)
	}
	return result
}

type trk35IntegrationRouteObserver struct {
	mu       sync.Mutex
	failNext error
	observed []control.RouteObservation
}

func (o *trk35IntegrationRouteObserver) ObserveRoutes(_ context.Context, _ string, observations []control.RouteObservation) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failNext != nil {
		err := o.failNext
		o.failNext = nil
		return err
	}
	o.observed = append(o.observed, observations...)
	return nil
}

func (o *trk35IntegrationRouteObserver) snapshot() []control.RouteObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]control.RouteObservation(nil), o.observed...)
}

type trk35IntegrationCarrier struct {
	registry *edgehttp.DataCarrierRouteRegistry
	mu       sync.RWMutex
	probeErr error
}

func (c *trk35IntegrationCarrier) ProbeRoutes(ctx context.Context, rules []route.RouteRule) error {
	c.mu.RLock()
	err := c.probeErr
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	return c.registry.ProbeRoutes(ctx, rules)
}

func (c *trk35IntegrationCarrier) OpenRouteStream(ctx context.Context, rule route.RouteRule, requestID string) (io.ReadWriteCloser, error) {
	return c.registry.OpenRouteStream(ctx, rule, requestID)
}

func (c *trk35IntegrationCarrier) setProbeError(err error) {
	c.mu.Lock()
	c.probeErr = err
	c.mu.Unlock()
}

func (c *trk35IntegrationCarrier) probeErrorValue() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.probeErr
}

var _ RouteCarrier = (*trk35IntegrationCarrier)(nil)

type trk35IntegrationCarrierPair struct {
	server  *datacarrier.Server
	client  *datacarrier.Client
	local   net.Conn
	remote  net.Conn
	cancel  context.CancelFunc
	done    chan struct{}
	held    chan trk35IntegrationHeldStream
	probes  atomic.Int32
	once    sync.Once
	mu      sync.Mutex
	streams []*datacarrier.Stream
}

type trk35IntegrationHeldStream struct {
	stream *datacarrier.Stream
	open   datacarrier.StreamOpen
}

func newTRK35IntegrationCarrierPair(assignment control.RouteAssignment, admissions *datacarrier.DurableAdmissionRegistry) (*trk35IntegrationCarrierPair, error) {
	identity := datacarrier.Identity{
		AccountID: assignment.AccountID, HostID: assignment.HostID, TunnelID: assignment.TunnelID,
		ConnectorID: assignment.ConnectorID, SessionID: assignment.ConnectorSessionID,
		ProcessGeneration: assignment.ConnectorProcessGeneration, Generation: assignment.ConfigGeneration,
	}
	serverConfig := trk35IntegrationCarrierConfig(identity, admissions)
	clientConfig := trk35IntegrationCarrierConfig(identity, datacarrier.AuthorizerFunc(func(ctx context.Context, got datacarrier.Identity, open datacarrier.StreamOpen) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if got != identity || open.RouteID != assignment.RouteID {
			return datacarrier.ErrIdentityMismatch
		}
		return nil
	}))
	local, remote := net.Pipe()
	server, err := datacarrier.NewServer(context.Background(), remote, serverConfig)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		return nil, err
	}
	client, err := datacarrier.NewClient(context.Background(), local, clientConfig)
	if err != nil {
		_ = server.Close()
		_ = local.Close()
		_ = remote.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	pair := &trk35IntegrationCarrierPair{server: server, client: client, local: local, remote: remote, cancel: cancel, done: make(chan struct{}), held: make(chan trk35IntegrationHeldStream, 16)}
	go pair.acceptHostStreams(ctx)
	return pair, nil
}

func trk35IntegrationCarrierConfig(identity datacarrier.Identity, authorizer datacarrier.Authorizer) datacarrier.Config {
	return datacarrier.Config{
		MaximumStreams:       4,
		AcceptBacklog:        4,
		QueueDepth:           4,
		StreamWindow:         256 << 10,
		KeepAliveInterval:    20 * time.Millisecond,
		ConnectionWriteLimit: time.Second,
		StreamOpenLimit:      time.Second,
		StreamCloseLimit:     time.Second,
		Identity:             identity,
		Authorize:            authorizer,
	}
}

func (p *trk35IntegrationCarrierPair) acceptHostStreams(ctx context.Context) {
	defer close(p.done)
	for {
		stream, open, err := p.client.AcceptStream(ctx)
		if err != nil {
			return
		}
		if strings.HasPrefix(open.RequestID, "edge-probe-") {
			go p.serveProbe(stream)
			continue
		}
		p.mu.Lock()
		p.streams = append(p.streams, stream)
		p.mu.Unlock()
		select {
		case p.held <- trk35IntegrationHeldStream{stream: stream, open: open}:
		case <-ctx.Done():
			_ = stream.Close()
			return
		}
		go func() {
			_, _ = io.Copy(io.Discard, stream)
			_ = stream.Close()
		}()
	}
}

func (p *trk35IntegrationCarrierPair) serveProbe(stream *datacarrier.Stream) {
	p.probes.Add(1)
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err == nil {
		_ = request.Body.Close()
		_, _ = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}
	_ = stream.Close()
}

func (p *trk35IntegrationCarrierPair) waitHeld(ctx context.Context, requestID string) (*datacarrier.Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case held := <-p.held:
			if held.open.RequestID == requestID {
				return held.stream, nil
			}
			_ = held.stream.Close()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *trk35IntegrationCarrierPair) Close() error {
	if p == nil {
		return nil
	}
	var closeErr error
	p.once.Do(func() {
		p.cancel()
		p.mu.Lock()
		streams := append([]*datacarrier.Stream(nil), p.streams...)
		p.mu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		if err := p.client.Close(); err != nil {
			closeErr = trk35IntegrationJoinUnexpectedCloseError(closeErr, err)
		}
		if err := p.server.Close(); err != nil {
			closeErr = trk35IntegrationJoinUnexpectedCloseError(closeErr, err)
		}
		closeErr = trk35IntegrationJoinUnexpectedCloseError(closeErr, p.local.Close())
		closeErr = trk35IntegrationJoinUnexpectedCloseError(closeErr, p.remote.Close())
	})
	select {
	case <-p.done:
	case <-time.After(time.Second):
		closeErr = errors.Join(closeErr, errors.New("carrier host goroutine did not stop"))
	}
	return closeErr
}

func trk35IntegrationJoinUnexpectedCloseError(current, next error) error {
	if next == nil || errors.Is(next, datacarrier.ErrCarrierClosed) || errors.Is(next, net.ErrClosed) || errors.Is(next, context.Canceled) || errors.Is(next, io.EOF) {
		return current
	}
	return errors.Join(current, next)
}

func trk35IntegrationReplicaState(assignment control.RouteAssignment) edgehttp.ReplicaState {
	return edgehttp.ReplicaState{
		Ready: true, Generation: assignment.ConfigGeneration, RouteIDs: []string{assignment.RouteID},
		HealthyRoutes: []string{assignment.RouteID}, FailureDomain: "zone_1", Capacity: 4,
		RouteBindings: []edgehttp.ReplicaRouteBinding{{
			RouteID: assignment.RouteID, AssignmentID: assignment.AssignmentID,
			AssignmentGeneration: assignment.AssignmentGeneration, RouteGeneration: assignment.Revision,
			ConfigContentHash: assignment.ConfigContentHash,
		}},
	}
}

func trks35IntegrationPulse(t *testing.T, pulse chan<- time.Time, calls <-chan struct{}) {
	t.Helper()
	select {
	case pulse <- time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC):
	case <-time.After(time.Second):
		t.Fatal("route worker pulse could not be delivered")
	}
	trks35IntegrationAwaitCall(t, calls)
}

func trks35IntegrationAwaitCall(t *testing.T, calls <-chan struct{}) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("route worker control call was not observed")
	}
}

func trks35IntegrationWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("integrated fault harness condition did not become true before deadline")
		default:
			runtime.Gosched()
		}
	}
}

var errTrk35IntegrationLostACK = errors.New("route ready ACK response was lost")
