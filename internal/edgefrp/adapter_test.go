package edgefrp

import (
	"context"
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
	claims := admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", JTI: "jti_admit_0001", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", HelperID: "hlp_test_01", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(time.Minute)}
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: verifier(func(context.Context, string) (admission.Claims, error) { return claims, nil }), Authorizer: authorizer(func(context.Context, string, string) (admission.Current, error) {
		return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
	}), Journal: journal, Now: func() time.Time { return now }, NewRunID: func(g uint64, expiry time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run_1", Generation: g, ExpiresAt: expiry}, nil
	}}
	registry := route.NewRegistry()
	adapter := NewAdapter(service, registry)
	recorder := &trafficRecorder{}
	adapter.Traffic = recorder
	adapter.Now = func() time.Time { return now }
	request := admission.Request{OperationID: "op_admit_0001", Credential: "credential-test-only-0000000000000000000000000000", Environment: "env_test_01", Helper: "hlp_test_01", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []admission.Route{{RouteID: "rte_1", Revision: 1, Kind: "helper_https_wss", PublicHost: "helper.example.test", ProxyName: "helper_1", TargetHost: "127.0.0.1", TargetPort: 8080}}}
	response, err := adapter.Login(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if attached, ok := registry.Get("rte_1"); !ok || attached.Target != "127.0.0.1:8080" {
		t.Fatal("route was not attached")
	}
	if _, err := adapter.Login(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeProxyRun(response.RunID.Value); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeStream(response.RunID.Value, "helper_1", "http"); err != nil {
		t.Fatal(err)
	}
	if stats := adapter.Stats(); stats.Sessions != 1 || stats.Routes != 1 || stats.ActiveStreams != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	adapter.CloseStream(response.RunID.Value, "helper_1")
	adapter.CloseStream(response.RunID.Value, "helper_1")
	if stats := adapter.Stats(); stats.ActiveStreams != 0 {
		t.Fatalf("closed stream stats = %+v", stats)
	}
	adapter.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if stats := adapter.Stats(); stats.Sessions != 0 || stats.Routes != 0 {
		t.Fatalf("expired session stats = %+v", stats)
	}
	adapter.Now = func() time.Time { return now }
	if err := adapter.RecordTraffic(response.RunID.Value, "helper_1", "http", 10, 20); err != nil {
		t.Fatal(err)
	}
	if recorder.environment != "env_test_01" || recorder.route != "rte_1" || recorder.revision != 1 || recorder.ingress != 10 || recorder.egress != 20 {
		t.Fatalf("traffic = %+v", recorder)
	}
	if err := registry.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AuthorizeProxyRun(response.RunID.Value); err == nil {
		t.Fatal("work connection survived route removal")
	}
	if err := adapter.AuthorizeStream(response.RunID.Value, "helper_1", "http"); err == nil {
		t.Fatal("user connection survived route removal")
	}
	adapter.Revoke(response.RunID.Value)
	if _, ok := registry.Get("rte_1"); ok {
		t.Fatal("revoked route remains attached")
	}
	limited := NewAdapter(service, route.NewRegistry(), 1)
	limited.sessions["occupied"] = session{active: make(map[string]uint32)}
	if _, err := limited.Login(context.Background(), request); err == nil {
		t.Fatal("connector capacity was not enforced")
	} else if code, ok := edgeerrors.CodeOf(err); !ok || code != edgeerrors.CodeServiceUnavailable {
		t.Fatalf("capacity error = %v", err)
	}
}

type trafficRecorder struct {
	environment, route string
	revision           uint64
	ingress, egress    uint64
}

func (r *trafficRecorder) Record(environment, route string, revision uint64, ingress, egress uint64) error {
	r.environment, r.route, r.revision, r.ingress, r.egress = environment, route, revision, ingress, egress
	return nil
}

type verifier func(context.Context, string) (admission.Claims, error)

func (f verifier) Verify(ctx context.Context, token string) (admission.Claims, error) {
	return f(ctx, token)
}

type authorizer func(context.Context, string, string) (admission.Current, error)

func (f authorizer) Current(ctx context.Context, env, helper string) (admission.Current, error) {
	return f(ctx, env, helper)
}
