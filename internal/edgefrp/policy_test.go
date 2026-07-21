package edgefrp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/testedge"
)

type resolverFunc func(context.Context, LoginContent) (admission.Request, error)

func (f resolverFunc) ResolveLogin(ctx context.Context, content LoginContent) (admission.Request, error) {
	return f(ctx, content)
}

func TestPolicyLoginAndProxyAllowList(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	fake := testedge.New()
	fake.SetCredential("token", admission.Claims{Issuer: "https://api.paperboat.test", Audience: "paperboat-edge", JTI: "jti_1", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env", HelperID: "helper", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge", ExpiresAt: now.Add(time.Minute)})
	fake.SetAssignment("env", "helper", admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge"})
	journal, _ := operation.NewJournal(8)
	service := &admission.Service{Issuer: "https://api.paperboat.test", Verifier: fake, Authorizer: fake, Journal: journal, Now: func() time.Time { return now }, NewRunID: func(g uint64, expiry time.Time) (admission.RunID, error) {
		return admission.RunID{Value: "run", Generation: g, ExpiresAt: expiry}, nil
	}}
	adapter := NewAdapter(service, route.NewRegistry())
	adapter.Now = func() time.Time { return now }
	policy := Policy{Adapter: adapter, InternalAuthToken: "internal-token-012345678901234567890123456789", Resolver: resolverFunc(func(context.Context, LoginContent) (admission.Request, error) {
		return admission.Request{OperationID: "op_1", Credential: "token", Environment: "env", Helper: "helper", Generation: 3, EdgePool: "default", EdgeNode: "edge", Routes: []admission.Route{{RouteID: "route", Revision: 1, Kind: "helper_https_wss", PublicHost: "helper.test", ProxyName: "proxy", TargetHost: "127.0.0.1", TargetPort: 8080}}}, nil
	})}
	login, err := policy.Handle(context.Background(), "Login", json.RawMessage(`{"privilege_key":"token"}`))
	if err != nil {
		t.Fatal(err)
	}
	var loginFields map[string]any
	if err := json.Unmarshal(login, &loginFields); err != nil || loginFields["run_id"] != "run" {
		t.Fatalf("login = %s", login)
	}
	validProxy := json.RawMessage(`{"user":{"run_id":"run"},"proxy_name":"proxy","proxy_type":"http","custom_domains":["helper.test"]}`)
	if _, err := policy.Handle(context.Background(), "NewProxy", validProxy); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"Ping", "NewWorkConn"} {
		mutated, err := policy.Handle(context.Background(), operation, json.RawMessage(`{"user":{"run_id":"run"},"run_id":"run","timestamp":123,"privilege_key":"connector-credential"}`))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(mutated, &fields); err != nil || fields["privilege_key"] != internalAuthKey(policy.InternalAuthToken, 123) {
			t.Fatalf("%s = %s", operation, mutated)
		}
	}
	unsupported := json.RawMessage(`{"user":{"run_id":"run"},"proxy_name":"proxy","proxy_type":"tcp","custom_domains":["helper.test"]}`)
	if _, err := policy.Handle(context.Background(), "NewProxy", unsupported); err == nil {
		t.Fatal("unsupported proxy accepted")
	}
	unknown := json.RawMessage(`{"user":{"run_id":"run"},"proxy_name":"other","proxy_type":"http","custom_domains":["other.test"]}`)
	if _, err := policy.Handle(context.Background(), "NewProxy", unknown); err == nil {
		t.Fatal("unknown proxy accepted")
	}
	if _, err := policy.Handle(context.Background(), "CloseProxy", json.RawMessage(`{"user":{"run_id":"run"},"proxy_name":"proxy"}`)); err != nil {
		t.Fatal(err)
	}
	if stats := adapter.Stats(); stats.Sessions != 0 || stats.Routes != 0 {
		t.Fatalf("closed final proxy retained connector state: %+v", stats)
	}
}
