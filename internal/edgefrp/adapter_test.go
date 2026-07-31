package edgefrp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestLoginAttachesOnlyAfterAdmissionAndRevokeCleansUp(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	journal, _ := operation.NewJournal(8)
	claims := admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", JTI: "jti_admit_0001", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", MachineID: "mch_test_01", ConnectorID: "runtime", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(time.Minute)}
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: verifier(func(context.Context, string) (admission.Claims, error) { return claims, nil }), Authorizer: authorizer(func(context.Context, string, string, string) (admission.Current, error) {
		return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
	}), Journal: journal, Now: func() time.Time { return now }, NewRunID: func(g uint64, expiry time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_1", Generation: g, ExpiresAt: expiry}, nil
	}}
	registry := route.NewRegistry("preview.example.test", "example.test")
	adapter := NewAdapter(service, registry)
	recorder := &trafficRecorder{}
	adapter.Traffic = recorder
	adapter.Now = func() time.Time { return now }
	request := admission.Request{OperationID: "op_admit_0001", Credential: "credential-test-only-0000000000000000000000000000", Environment: "env_test_01", Machine: "mch_test_01", Connector: "runtime", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []admission.Route{{RouteID: "rte_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: "helper.example.test", ProxyName: "helper_1", TargetHost: "127.0.0.1", TargetPort: 8080}}}
	response, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if attached, ok := registry.Get("rte_1"); !ok || attached.Target != "127.0.0.1:8080" {
		t.Fatal("route was not attached")
	}
	_, err = adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if kind, state, _, found := adapter.RouteState("helper.example.test"); !found || kind != "runtime_https_wss" || state != "offline" {
		t.Fatalf("unregistered helper state = kind=%q state=%q found=%v", kind, state, found)
	}
	identity := frpProxyIdentity(adapter.sessions[response.RunID.Value], request.Routes[0])
	if err := adapter.AuthorizeProxy(response.RunID.Value, identity.name, "http", "helper.example.test", identity.group, identity.groupKey); err != nil {
		t.Fatal(err)
	}
	if kind, state, reason, found := adapter.RouteState("helper.example.test"); !found || kind != "runtime_https_wss" || state != "ready" || reason != "" {
		t.Fatalf("registered helper state = kind=%q state=%q reason=%q found=%v", kind, state, reason, found)
	}
	if err := adapter.AuthorizeProxyRun(response.RunID.Value); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeStream(response.RunID.Value, identity.name, "http"); err != nil {
		t.Fatal(err)
	}
	if stats := adapter.Stats(); stats.Sessions != 1 || stats.Routes != 1 || stats.ActiveStreams != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	adapter.CloseStream(response.RunID.Value, identity.name)
	adapter.CloseStream(response.RunID.Value, identity.name)
	if stats := adapter.Stats(); stats.ActiveStreams != 0 {
		t.Fatalf("closed stream stats = %+v", stats)
	}
	adapter.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if stats := adapter.Stats(); stats.Sessions != 1 || stats.Routes != 1 {
		t.Fatalf("established session disappeared after admission expiry: %+v", stats)
	}
	if kind, state, reason, found := adapter.RouteState("helper.example.test"); !found || kind != "runtime_https_wss" || state != "ready" || reason != "" {
		t.Fatalf("expired admission disabled established route: kind=%q state=%q reason=%q found=%v", kind, state, reason, found)
	}
	if err := adapter.AuthorizeProxyRun(response.RunID.Value); err != nil {
		t.Fatalf("expired admission disabled established work connection: %v", err)
	}
	if err := adapter.AuthorizeStream(response.RunID.Value, identity.name, "http"); err != nil {
		t.Fatalf("expired admission disabled established proxy stream: %v", err)
	}
	adapter.CloseStream(response.RunID.Value, identity.name)
	adapter.Now = func() time.Time { return now }
	if err := adapter.RecordTraffic(response.RunID.Value, identity.name, "http", 10, 20); err != nil {
		t.Fatal(err)
	}
	if recorder.environment != "env_test_01" || recorder.route != "rte_1" || recorder.revision != 1 || recorder.ingress != 10 || recorder.egress != 20 {
		t.Fatalf("traffic = %+v", recorder)
	}
	if err := adapter.RecordTrafficSnapshot(response.RunID.Value, identity.name, "http", 15, 25); err != nil {
		t.Fatal(err)
	}
	if err := adapter.RecordTrafficSnapshot(response.RunID.Value, identity.name, "http", 15, 25); err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 2 || recorder.ingress != 15 || recorder.egress != 25 {
		t.Fatalf("duplicate snapshot was not idempotent: %+v", recorder)
	}
	if err := adapter.RecordTrafficSnapshot(response.RunID.Value, identity.name, "http", 18, 29); err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 3 || recorder.ingress != 3 || recorder.egress != 4 {
		t.Fatalf("snapshot delta = %+v", recorder)
	}
	if err := registry.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeProxyRun(response.RunID.Value); err == nil {
		t.Fatal("work connection survived route removal")
	}
	if err := adapter.AuthorizeStream(response.RunID.Value, identity.name, "http"); err == nil {
		t.Fatal("user connection survived route removal")
	}
	adapter.Revoke(response.RunID.Value)
	if _, ok := registry.Get("rte_1"); ok {
		t.Fatal("revoked route remains attached")
	}
	limited := NewAdapter(service, route.NewRegistry("preview.example.test", "example.test"), 1)
	limited.sessions["occupied"] = session{active: make(map[string]uint32)}
	if _, err := limited.Login(context.Background(), request); err == nil {
		t.Fatal("connector capacity was not enforced")
	} else if code, ok := edgeerrors.CodeOf(err); !ok || code != edgeerrors.CodeServiceUnavailable {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestLoginRefreshOverlapsRunsForAtomicFRPReplacement(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	journal, _ := operation.NewJournal(8)
	claims := admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", MachineID: "mch_test_01", ConnectorID: "runtime", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(5 * time.Minute)}
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: verifier(func(_ context.Context, token string) (admission.Claims, error) {
		claims.JTI = token
		return claims, nil
	}), Authorizer: authorizer(func(context.Context, string, string, string) (admission.Current, error) {
		return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
	}), Journal: journal, Now: func() time.Time { return now }, NewRunID: func(_ uint64, _ time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_1", Generation: 3, ExpiresAt: now.Add(5 * time.Minute)}, nil
	}}
	registry := route.NewRegistry("preview.example.test", "example.test")
	adapter := NewAdapter(service, registry)
	adapter.Now = func() time.Time { return now }
	request := admission.Request{OperationID: "op_admit_0001", Credential: "jti_admit_0001", Environment: "env_test_01", Machine: "mch_test_01", Connector: "runtime", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []admission.Route{{RouteID: "rte_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: "helper.example.test", ProxyName: "helper_1", TargetHost: "127.0.0.1", TargetPort: 8080}}}
	first, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	firstIdentity := frpProxyIdentity(adapter.sessions[first.RunID.Value], request.Routes[0])
	if err := adapter.AuthorizeProxy(first.RunID.Value, firstIdentity.name, "http", request.Routes[0].PublicHost, firstIdentity.group, firstIdentity.groupKey); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeStream(first.RunID.Value, firstIdentity.name, "http"); err != nil {
		t.Fatal(err)
	}
	service.NewRunID = func(_ uint64, _ time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_2", Generation: 3, ExpiresAt: now.Add(5 * time.Minute)}, nil
	}
	request.OperationID = "op_admit_0002"
	request.Credential = "jti_admit_0002"
	second, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID.Value == first.RunID.Value {
		t.Fatalf("refresh reused run ID: first=%q second=%q", first.RunID.Value, second.RunID.Value)
	}
	if stats := adapter.Stats(); stats.Sessions != 2 || stats.Routes != 1 || stats.ActiveStreams != 1 {
		t.Fatalf("replacement stats = %+v", stats)
	}
	secondIdentity := frpProxyIdentity(adapter.sessions[second.RunID.Value], request.Routes[0])
	if firstIdentity.name == secondIdentity.name || firstIdentity.group != secondIdentity.group || firstIdentity.groupKey != secondIdentity.groupKey {
		t.Fatalf("replacement identities: first=%+v second=%+v", firstIdentity, secondIdentity)
	}
	if err := adapter.AuthorizeProxy(second.RunID.Value, secondIdentity.name, "http", request.Routes[0].PublicHost, secondIdentity.group, secondIdentity.groupKey); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeHeartbeat(first.RunID.Value); err != nil {
		t.Fatalf("retired heartbeat rejected with active stream: %v", err)
	}
	if err := adapter.AuthorizeProxyRun(first.RunID.Value); err == nil {
		t.Fatal("retired run accepted new work")
	}
	adapter.CloseProxy(first.RunID.Value, firstIdentity.name)
	if stats := adapter.Stats(); stats.Sessions != 2 || stats.ActiveStreams != 1 {
		t.Fatalf("proxy retirement closed active stream: %+v", stats)
	}
	adapter.CloseStream(first.RunID.Value, firstIdentity.name)
	if stats := adapter.Stats(); stats.Sessions != 1 || stats.ActiveStreams != 0 {
		t.Fatalf("drained replacement stats = %+v", stats)
	}
	if err := adapter.AuthorizeHeartbeat(first.RunID.Value); err == nil {
		t.Fatal("idle retired heartbeat remained authorized")
	}
	service.NewRunID = func(_ uint64, _ time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_3", Generation: 3, ExpiresAt: now.Add(5 * time.Minute)}, nil
	}
	request.OperationID = "op_admit_0003"
	request.Credential = "jti_admit_0003"
	third, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if stats := adapter.Stats(); stats.Sessions != 1 {
		t.Fatalf("idle replacement stats = %+v", stats)
	}
	adapter.CloseProxy(first.RunID.Value, firstIdentity.name)
	if _, ok := registry.Get(request.Routes[0].RouteID); !ok {
		t.Fatal("retired proxy detached the replacement route")
	}
	if err := adapter.AuthorizeProxyRun(third.RunID.Value); err != nil {
		t.Fatalf("replacement run authorization: %v", err)
	}
}

func TestResumeRotatesRunAndFencesRetiredCloseCallbacks(t *testing.T) {
	now := time.Now().UTC()
	journal, _ := operation.NewJournal(8)
	claims := admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", JTI: "jti_admit_resume", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", MachineID: "mch_test_01", ConnectorID: "runtime", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(time.Minute)}
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: verifier(func(context.Context, string) (admission.Claims, error) { return claims, nil }), Authorizer: authorizer(func(context.Context, string, string, string) (admission.Current, error) {
		return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
	}), Journal: journal, Now: func() time.Time { return now }, NewRunID: func(generation uint64, expiresAt time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_initial", Generation: generation, ExpiresAt: expiresAt}, nil
	}}
	adapter := NewAdapter(service, route.NewRegistry("preview.example.test", "helper.example.test"))
	adapter.Now = func() time.Time { return now }
	request := admission.Request{OperationID: "op_admit_resume", Credential: "credential-test-only-0000000000000000000000000000", Environment: "env_test_01", Machine: "mch_test_01", Connector: "runtime", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []admission.Route{{RouteID: "rte_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: "env.helper.example.test", ProxyName: "helper_1", TargetHost: "127.0.0.1", TargetPort: 8080}}}
	initial, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	identity := frpProxyIdentity(adapter.sessions[initial.RunID.Value], request.Routes[0])
	if err := adapter.AuthorizeProxy(initial.RunID.Value, identity.name, "http", "env.helper.example.test", identity.group, identity.groupKey); err != nil {
		t.Fatal(err)
	}
	resumed, err := adapter.Resume(context.Background(), request, initial.RunID.Value)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.RunID.Value == initial.RunID.Value {
		t.Fatal("resume reused the retired transport run ID")
	}
	adapter.CloseProxy(initial.RunID.Value, identity.name)
	resumedIdentity := frpProxyIdentity(adapter.sessions[resumed.RunID.Value], request.Routes[0])
	if err := adapter.AuthorizeProxy(resumed.RunID.Value, resumedIdentity.name, "http", "env.helper.example.test", resumedIdentity.group, resumedIdentity.groupKey); err != nil {
		t.Fatalf("retired close callback removed resumed run: %v", err)
	}
	if err := adapter.AuthorizeProxyRun(resumed.RunID.Value); err != nil {
		t.Fatalf("resumed work connection rejected: %v", err)
	}
	if err := adapter.AuthorizeProxyRun(initial.RunID.Value); err == nil {
		t.Fatal("retired run remained authorized")
	}
}

func TestResumeReportsUnknownRunAfterEdgeRestart(t *testing.T) {
	now := time.Now().UTC()
	journal, _ := operation.NewJournal(8)
	claims := admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", JTI: "jti_admit_restart", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", MachineID: "mch_test_01", ConnectorID: "runtime", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(time.Minute)}
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: verifier(func(context.Context, string) (admission.Claims, error) { return claims, nil }), Authorizer: authorizer(func(context.Context, string, string, string) (admission.Current, error) {
		return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
	}), Journal: journal, Now: func() time.Time { return now }}
	adapter := NewAdapter(service, route.NewRegistry("preview.example.test", "helper.example.test"))
	request := admission.Request{OperationID: "op_admit_restart", Credential: "credential-test-only-0000000000000000000000000000", Environment: "env_test_01", Machine: "mch_test_01", Connector: "runtime", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []admission.Route{{RouteID: "rte_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: "env.helper.example.test", ProxyName: "helper_1", TargetHost: "127.0.0.1", TargetPort: 8080}}}
	if _, err := adapter.Resume(context.Background(), request, "run_from_prior_edge_process"); !errors.Is(err, ErrRunUnknown) {
		t.Fatalf("unknown resumed run error = %v", err)
	}
}

func TestFRPProxyIdentityMatchesHelperContract(t *testing.T) {
	current := session{environment: "env", machine: "machine", connector: "runtime", operationID: "op_admit_first"}
	route := admission.Route{RouteID: "route_1", ProxyName: "helper_1"}
	identity := frpProxyIdentity(current, route)
	if identity.name != "pbp_1332950afeddd5c0aea71c2152a9c22a" || identity.group != "pbg_cae1ebe5f77a8693bd4ab53069abc9f5" || identity.groupKey != "6a96339851ee24ba42cf0facf7cc02437d64bef1e7cbb053dd48e0aa84136d80" {
		t.Fatalf("identity contract changed: %+v", identity)
	}
}

type trafficRecorder struct {
	environment, route string
	revision           uint64
	ingress, egress    uint64
	calls              int
}

func (r *trafficRecorder) Record(environment, route string, revision uint64, ingress, egress uint64) error {
	r.calls++
	r.environment, r.route, r.revision, r.ingress, r.egress = environment, route, revision, ingress, egress
	return nil
}

type verifier func(context.Context, string) (admission.Claims, error)

func (f verifier) Verify(ctx context.Context, token string) (admission.Claims, error) {
	return f(ctx, token)
}

type authorizer func(context.Context, string, string, string) (admission.Current, error)

func (f authorizer) Current(ctx context.Context, env, machine, connector string) (admission.Current, error) {
	return f(ctx, env, machine, connector)
}
