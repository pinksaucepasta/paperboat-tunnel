package tlscert

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

type testDistributionAuth struct {
	actions []string
	err     error
}

func (a *testDistributionAuth) Verify(_ context.Context, action string, envelope DistributionEnvelope) error {
	if envelope.Binding.EdgeNodeID == "" || envelope.Binding.EdgeProcessEpoch == "" {
		return ErrDistributionAuth
	}
	a.actions = append(a.actions, action)
	return a.err
}

func TestDistributionReceiverRequiresAuthenticatedExactEdgeAndKeepsKeysInMemory(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	auth := new(testDistributionAuth)
	receiver, err := NewDistributionReceiver(ReceiverConfig{Registry: registry, NodeID: "edge_1", ProcessEpoch: "epoch_0001", Authenticator: auth, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("tls.example.test", 1)
	bundle := testBundle(t, binding.Hostname, now, 1)
	envelope := DistributionEnvelope{CertificateID: "cert_001", Binding: binding, Bundle: bundle, Proof: []byte("server-proof"), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	if err := receiver.Stage(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Ready(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Activate(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: binding.Hostname}); err != nil {
		t.Fatal(err)
	}
	if got, want := len(auth.actions), 3; got != want {
		t.Fatalf("auth actions=%v", auth.actions)
	}
	stale := envelope
	stale.Binding.EdgeProcessEpoch = "epoch_0002"
	if err := receiver.Stage(context.Background(), stale); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale process accepted: %v", err)
	}
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}
	if got := registry.Snapshot(); len(got) != 0 {
		t.Fatalf("private material survived close: %+v", got)
	}
}

func TestDistributionReceiverRejectsExpiredOrUnauthenticatedEnvelope(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	auth := &testDistributionAuth{err: ErrDistributionAuth}
	receiver, err := NewDistributionReceiver(ReceiverConfig{Registry: registry, NodeID: "edge_1", ProcessEpoch: "epoch_0001", Authenticator: auth, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("tls.example.test", 1)
	envelope := DistributionEnvelope{CertificateID: "cert_001", Binding: binding, Bundle: testBundle(t, binding.Hostname, now, 1), Proof: []byte("proof"), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second)}
	if err := receiver.Stage(context.Background(), envelope); !errors.Is(err, ErrDistributionInvalid) {
		t.Fatalf("expired envelope error=%v", err)
	}
	envelope.ExpiresAt = now.Add(time.Minute)
	if err := receiver.Stage(context.Background(), envelope); !errors.Is(err, ErrDistributionAuth) {
		t.Fatalf("unauthenticated envelope error=%v", err)
	}
	if got := registry.Snapshot(); len(got) != 0 {
		t.Fatalf("unauthenticated distribution mutated registry: %+v", got)
	}
}

func TestDistributionReceiverStageAndReadyAuthenticatesStageActionOnce(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	auth := new(testDistributionAuth)
	receiver, err := NewDistributionReceiver(ReceiverConfig{Registry: registry, NodeID: "edge_1", ProcessEpoch: "epoch_0001", Authenticator: auth, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("tls.example.test", 1)
	envelope := DistributionEnvelope{CertificateID: "cert_001", Binding: binding, Bundle: testBundle(t, binding.Hostname, now, 1), Proof: []byte("server-proof"), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	if err := receiver.StageAndReady(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(auth.actions) != 1 || auth.actions[0] != "stage" {
		t.Fatalf("authenticated actions = %v, want one stage action", auth.actions)
	}
	if err := receiver.Activate(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
}
