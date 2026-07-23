package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
)

type verifierFunc func(context.Context, string) (Claims, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (Claims, error) { return f(ctx, token) }

type authorizerFunc func(context.Context, string, string) (Current, error)

func (f authorizerFunc) Current(ctx context.Context, env, helper string) (Current, error) {
	return f(ctx, env, helper)
}

func admissionService(t *testing.T, now time.Time, claims Claims) *Service {
	t.Helper()
	journal, err := operation.NewJournal(8)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		Issuer:   "https://api.paperboat.test",
		Verifier: verifierFunc(func(context.Context, string) (Claims, error) { return claims, nil }),
		Authorizer: authorizerFunc(func(context.Context, string, string) (Current, error) {
			return Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01"}, nil
		}),
		Journal: journal, Now: func() time.Time { return now },
		NewRunID: func(generation uint64, expiry time.Time) (RunID, error) {
			return RunID{Value: "run_test_01", Generation: generation, ExpiresAt: expiry}, nil
		},
	}
}

func validClaims(now time.Time) Claims {
	return Claims{Issuer: "https://api.paperboat.test", Audience: audience, JTI: "jti_admit_0001", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_test_01", HelperID: "hlp_test_01", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_test_01", ExpiresAt: now.Add(5 * time.Minute)}
}

func validRequest() Request {
	return Request{OperationID: "op_admit_0001", Credential: "credential-test-only-0000000000000000000000000000", Environment: "env_test_01", Helper: "hlp_test_01", Generation: 3, EdgePool: "default", EdgeNode: "edge_test_01", Routes: []Route{{RouteID: "rte_helper_01", Revision: 1, Kind: "helper_https_wss", PublicHost: "helper.example.test", ProxyName: "helper_01", TargetHost: "127.0.0.1", TargetPort: 8080}}}
}

func TestAdmissionBindsAndReplaysCanonicalDecision(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	service := admissionService(t, now, validClaims(now))
	request := validRequest()
	first, err := service.Admit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID.Value != "run_test_01" || len(first.Routes) != 1 {
		t.Fatalf("response = %+v", first)
	}
	retry, err := service.Admit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if retry.RunID.Value != first.RunID.Value {
		t.Fatalf("retry = %+v", retry)
	}
	changed := request
	changed.OperationID = "op_admit_0002"
	changed.Routes = append([]Route(nil), request.Routes...)
	changed.Routes[0].TargetPort = 8081
	if _, err := service.Admit(context.Background(), changed); !errors.Is(err, operation.ErrReplay) {
		t.Fatalf("changed replay = %v", err)
	}
}

func TestAdmissionRejectsBindingAndGenerationBeforeJournalMutation(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	service := admissionService(t, now, validClaims(now))
	request := validRequest()
	request.EdgeNode = "edge_other"
	if _, err := service.Admit(context.Background(), request); err == nil {
		t.Fatal("wrong node accepted")
	}
	if service.Journal.Len() != 0 {
		t.Fatal("invalid admission mutated journal")
	}
	request = validRequest()
	request.Generation = 2
	_, err := service.Admit(context.Background(), request)
	if err == nil {
		t.Fatal("stale generation accepted")
	}
	if code, _ := edgeerrors.CodeOf(err); code != edgeerrors.CodeBindingInvalid {
		t.Fatalf("wrong code: %s", code)
	}
}

func TestAdmissionRejectsStaleCredentialGenerationBeforeJournalMutation(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	claims := validClaims(now)
	claims.ConnectorGeneration = 2
	service := admissionService(t, now, claims)
	request := validRequest()
	request.Generation = 2

	_, err := service.Admit(context.Background(), request)
	if err == nil {
		t.Fatal("stale credential generation accepted")
	}
	if code, _ := edgeerrors.CodeOf(err); code != edgeerrors.CodeGenerationStale {
		t.Fatalf("wrong code: %s", code)
	}
	if service.Journal.Len() != 0 {
		t.Fatal("stale admission mutated journal")
	}
}

func TestRunIDFencesReconnect(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	run := RunID{Value: "run_1", Generation: 3, ExpiresAt: now.Add(time.Minute)}
	if err := run.Resume("run_1", 3, now); err != nil {
		t.Fatal(err)
	}
	if err := run.Resume("run_2", 3, now); err == nil {
		t.Fatal("different run accepted")
	}
	if err := run.Resume("run_1", 4, now); err == nil {
		t.Fatal("different generation accepted")
	}
	run.Revoked = true
	if err := run.Resume("run_1", 3, now); err == nil {
		t.Fatal("revoked run accepted")
	}
}
