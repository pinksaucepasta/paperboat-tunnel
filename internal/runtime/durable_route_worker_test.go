package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestRouteWorkerSeparatesCanonicalHTTPAndPrivateTCPFromLegacyRoutes(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(publicKey)
	thumbprint, err := connectorprotocol.IdentityThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	assignment := durableWorkerAssignment(encodedKey, thumbprint, "route_http", "assignment_http", route.TunnelHTTPSWSS)
	private := durableWorkerAssignment(encodedKey, thumbprint, "route_tcp", "assignment_tcp", route.TunnelPrivateTCP)
	private.AccessMode = "private"
	private.Protocol = "private_tcp"
	private.Revision = 2
	private.AssignmentGeneration = 2
	private.PublicHost = ""
	private.MatchType = ""
	private.MatchHostname = ""
	private.WildcardSuffix = ""
	private.PathPrefix = ""
	if err := validateCanonicalAssignment(assignment, "edge_1", "edge_epoch_1"); err != nil {
		t.Fatalf("http assignment validation: %v", err)
	}
	if err := validateCanonicalAssignment(private, "edge_1", "edge_epoch_1"); err != nil {
		t.Fatalf("private assignment validation: %v", err)
	}
	legacy := route.NewRegistry("preview.example.test", "example.test")
	if _, err := legacy.Attach(route.Attachment{ID: "legacy_route", Revision: 1, Environment: "env", Node: "edge_1", Generation: 1, Kind: route.HelperHTTPSWSS, Host: "helper.example.test", Target: "127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	carrier := &workerCarrierProbe{}
	state := node.New("edge_1")
	state.MarkReady()
	source := &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{
		assignment,
		private,
		{RouteID: "legacy_route", Revision: 1, Environment: "env", Generation: 1, NodeID: "edge_1", Kind: string(route.HelperHTTPSWSS), PublicHost: "helper.example.test", TargetHost: "127.0.0.1", TargetPort: 8080},
	}, Complete: true, Canonical: true}}
	observer := &routeObserver{}
	worker := &RouteWorker{
		Registry: canonical, LegacyRegistry: legacy, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: carrier, DurableAdmissions: durable,
		Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = worker.Shutdown(ctx)
	}()
	lease, _, err := canonical.Acquire(context.Background(), assignment.PublicHost, "/normal")
	if err != nil {
		t.Fatalf("canonical HTTP route unavailable: %v", err)
	}
	_ = lease.Close()
	if _, err := canonical.Match("private.example.test", "/"); !errors.Is(err, route.ErrNoMatch) {
		t.Fatalf("private TCP route entered HTTP matcher: %v", err)
	}
	if _, err := legacy.Match("helper.example.test", "/healthz"); err != nil {
		t.Fatalf("legacy route was erased by canonical snapshot: %v", err)
	}
	admissions := durable.Snapshot()
	if len(admissions) != 2 {
		t.Fatalf("durable admissions = %d, want 2", len(admissions))
	}
	if carrier.privateProbes != 1 || len(carrier.privateRules) != 1 || carrier.privateRules[0].Kind != route.TunnelPrivateTCP {
		t.Fatalf("private carrier probes = %d rules=%+v", carrier.privateProbes, carrier.privateRules)
	}
	if len(observer.observations) != 2 {
		t.Fatalf("observations = %+v, want HTTP and private", observer.observations)
	}
}

func TestRouteWorkerCompleteCanonicalEmptyKeepsLegacyRegistry(t *testing.T) {
	legacy := route.NewRegistry("preview.example.test", "example.test")
	if _, err := legacy.Attach(route.Attachment{ID: "legacy_route", Revision: 1, Environment: "env", Node: "edge_1", Generation: 1, Kind: route.HelperHTTPSWSS, Host: "helper.example.test", Target: "127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	state := node.New("edge_1")
	state.MarkReady()
	worker := &RouteWorker{
		Registry: canonical, LegacyRegistry: legacy, Source: &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{{RouteID: "legacy_route", Revision: 1, Environment: "env", Generation: 1, NodeID: "edge_1", Kind: string(route.HelperHTTPSWSS), PublicHost: "helper.example.test", TargetHost: "127.0.0.1", TargetPort: 8080}}, Complete: true, Canonical: true}},
		Observer: &routeObserver{}, State: state, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{}, DurableAdmissions: durable,
		Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = worker.Shutdown(ctx)
	}()
	if canonical.HasActiveGeneration() == false {
		t.Fatal("canonical empty generation was not activated")
	}
	if _, err := canonical.Match("helper.example.test", "/healthz"); !errors.Is(err, route.ErrNoMatch) {
		t.Fatalf("legacy row leaked into canonical matcher: %v", err)
	}
	if _, err := legacy.Match("helper.example.test", "/healthz"); err != nil {
		t.Fatalf("legacy registry was removed by canonical empty snapshot: %v", err)
	}
}

func TestRouteWorkerReadyFailureLeavesPreviousCanonicalGeneration(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(publicKey)
	thumbprint, err := connectorprotocol.IdentityThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	first := durableWorkerAssignment(encodedKey, thumbprint, "route_first", "assignment_first", route.TunnelHTTPSWSS)
	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	state := node.New("edge_1")
	state.MarkReady()
	source := &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{first}, Complete: true, Canonical: true}}
	worker := &RouteWorker{Registry: canonical, Source: source, Observer: &routeObserver{}, State: state, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{}, DurableAdmissions: durable, Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time)}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstGeneration := canonical.Generation()
	second := first
	second.RouteID = "route_second"
	second.AssignmentID = "assignment_second"
	second.Revision = 2
	second.AssignmentGeneration = 2
	source.snapshot.Routes = []control.RouteAssignment{second}
	worker.Ready = func(context.Context, []route.RouteRule) error { return errors.New("origin unavailable") }
	if err := worker.reconcile(context.Background()); err == nil {
		t.Fatal("ready failure accepted")
	}
	if canonical.Generation() != firstGeneration {
		t.Fatalf("canonical generation changed after failed ready: got %d want %d", canonical.Generation(), firstGeneration)
	}
	if _, err := canonical.Match(first.PublicHost, "/"); err != nil {
		t.Fatalf("previous route unavailable after failed ready: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRouteWorkerRestartDetachesSupersededActiveAssignmentAfterReplacement(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index + 7)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(publicKey)
	thumbprint, err := connectorprotocol.IdentityThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	old := durableWorkerAssignment(encodedKey, thumbprint, "route_restart", "assignment_old", route.TunnelHTTPSWSS)
	newAssignment := old
	newAssignment.AssignmentID = "assignment_new"
	newAssignment.AssignmentGeneration = 2
	newAssignment.Revision = 2
	newAssignment.ConnectorSessionID = "session_new"
	newAssignment.State = "staged"
	newAssignment.PublicHost = old.PublicHost
	newAssignment.MatchHostname = old.MatchHostname
	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	state := node.New("edge_1")
	state.MarkReady()
	source := &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{old}, Complete: true, Canonical: true}}
	observer := &routeObserver{}
	worker := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{}, DurableAdmissions: durable,
		Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// A restarted edge has no prior local assignment list, but the complete
	// server snapshot still carries both old active and new staged rows. It
	// must activate the new row and ACK the old row as detached.
	restartedObserver := &appendRouteObserver{}
	restarted := &RouteWorker{
		Registry: route.NewRegistry("", ""), Source: &workerSnapshotSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{old, newAssignment}, Complete: true, Canonical: true}},
		Observer: restartedObserver, State: state, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{}, DurableAdmissions: durable,
		Ready: func(context.Context, []route.RouteRule) error { return nil }, Pulse: make(chan time.Time),
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = restarted.Shutdown(ctx)
	}()
	if len(restartedObserver.observations) != 2 || restartedObserver.observations[0].AssignmentID != "assignment_new" || restartedObserver.observations[1].AssignmentID != "assignment_old" || restartedObserver.observations[1].ObservedState != "detached" {
		t.Fatalf("restart observations = %+v, want new ready and old detached", restartedObserver.observations)
	}
}

type workerSnapshotSource struct {
	snapshot control.RouteSnapshot
}

type appendRouteObserver struct {
	observations []control.RouteObservation
}

func (o *appendRouteObserver) ObserveRoutes(_ context.Context, _ string, observations []control.RouteObservation) error {
	o.observations = append(o.observations, observations...)
	return nil
}

func (s *workerSnapshotSource) DesiredRouteSnapshot(context.Context, string, string) (control.RouteSnapshot, error) {
	return s.snapshot, nil
}

func (s *workerSnapshotSource) DesiredRoutes(context.Context, string) ([]control.RouteAssignment, error) {
	return s.snapshot.Routes, nil
}

type workerCarrierProbe struct {
	privateProbes int
	privateRules  []route.RouteRule
}

func (p *workerCarrierProbe) ProbeRoutes(context.Context, []route.RouteRule) error { return nil }

func (p *workerCarrierProbe) ProbePrivateRoutes(_ context.Context, rules []route.RouteRule) error {
	p.privateProbes++
	p.privateRules = append([]route.RouteRule(nil), rules...)
	return nil
}

func (p *workerCarrierProbe) OpenRouteStream(context.Context, route.RouteRule, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("not used in worker probe")
}

func durableWorkerAssignment(publicKey, thumbprint, routeID, assignmentID string, kind route.Kind) control.RouteAssignment {
	return control.RouteAssignment{
		RouteID: routeID, Revision: 1, Environment: "env_1", AccountID: "account_1", HostID: "host_1",
		MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: thumbprint, TunnelID: "tunnel_1", ConnectorID: "connector_1",
		Generation: 1, ConnectorSessionID: "session_1", ConnectorProcessGeneration: 1, ConfigGeneration: 1,
		ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AssignmentID: assignmentID,
		AssignmentGeneration: 1, EdgeFailureDomain: "zone_1", EdgeProcessEpoch: "edge_epoch_1", NodeID: "edge_1", Kind: string(kind),
		PublicHost: "app.example.test", MatchType: route.MatchExact, MatchHostname: "app.example.test", PathPrefix: "/", Protocol: "https", AccessMode: "public", State: "active",
	}
}

func durableWorkerIdentity(t *testing.T) (string, string) {
	t.Helper()
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(publicKey), thumbprint
}

func TestCanonicalRouteRulesPublishReadyExactAndWildcardDomainAliases(t *testing.T) {
	assignment := durableWorkerAssignment("key", "thumbprint", "route_http", "assignment_http", route.TunnelHTTPSWSS)
	assignment.DomainBindings = []control.DomainBinding{
		{ID: "domain_exact", Hostname: "app.customer.example", MatchType: route.MatchExact, Generation: 4},
		{ID: "domain_wild", Hostname: "*.apps.customer.example", MatchType: route.MatchOneLabelWildcard, Generation: 5},
	}
	rules := canonicalRouteRules([]control.RouteAssignment{assignment})
	if len(rules) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	byID := make(map[string]route.RouteRule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	exact := byID["route_http@domain_exact"]
	if exact.Hostname != "app.customer.example" || exact.Target != "route_http" || exact.Revision != 4 {
		t.Fatalf("exact alias = %+v", exact)
	}
	wildcard := byID["route_http@domain_wild"]
	if wildcard.Hostname != "" || wildcard.WildcardSuffix != "apps.customer.example" || wildcard.Target != "route_http" || wildcard.Revision != 5 {
		t.Fatalf("wildcard alias = %+v", wildcard)
	}
}

func TestCanonicalAssignmentRejectsUnsafeDomainBindings(t *testing.T) {
	publicKey, thumbprint := durableWorkerIdentity(t)
	base := durableWorkerAssignment(publicKey, thumbprint, "route_http", "assignment_http", route.TunnelHTTPSWSS)
	for name, bindings := range map[string][]control.DomainBinding{
		"unknown match":      {{ID: "domain_1", Hostname: "app.example.test", MatchType: "recursive_wildcard", Generation: 1}},
		"recursive wildcard": {{ID: "domain_1", Hostname: "*.*.example.test", MatchType: route.MatchOneLabelWildcard, Generation: 1}},
		"duplicate hostname": {{ID: "domain_1", Hostname: "app.example.test", MatchType: route.MatchExact, Generation: 1}, {ID: "domain_2", Hostname: "app.example.test", MatchType: route.MatchExact, Generation: 1}},
		"terminal dot":       {{ID: "domain_1", Hostname: "app.example.test.", MatchType: route.MatchExact, Generation: 1}},
		"zero generation":    {{ID: "domain_1", Hostname: "app.example.test", MatchType: route.MatchExact}},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.DomainBindings = bindings
			if err := validateCanonicalAssignment(candidate, candidate.NodeID, candidate.EdgeProcessEpoch); !errors.Is(err, route.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCanonicalRouteHashIncludesDomainBindingsButNotTheirOrder(t *testing.T) {
	assignment := durableWorkerAssignment("key", "thumbprint", "route_http", "assignment_http", route.TunnelHTTPSWSS)
	assignment.DomainBindings = []control.DomainBinding{
		{ID: "domain_b", Hostname: "b.customer.example", MatchType: route.MatchExact, Generation: 2},
		{ID: "domain_a", Hostname: "a.customer.example", MatchType: route.MatchExact, Generation: 1},
	}
	first := canonicalRouteHash([]control.RouteAssignment{assignment})
	assignment.DomainBindings[0], assignment.DomainBindings[1] = assignment.DomainBindings[1], assignment.DomainBindings[0]
	if got := canonicalRouteHash([]control.RouteAssignment{assignment}); got != first {
		t.Fatal("domain binding order changed canonical hash")
	}
	assignment.DomainBindings[0].Generation++
	if got := canonicalRouteHash([]control.RouteAssignment{assignment}); got == first {
		t.Fatal("domain generation change did not change canonical hash")
	}
}
