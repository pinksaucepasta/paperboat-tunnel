package tlscert

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTRK35CertificateReplacementFailurePreservesExactLeavesAndWildcard(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	clock := now
	registry, err := NewRegistry(Config{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}

	wildcard := testBinding("*.chaos.example.test", 1)
	leaf := wildcard
	leaf.Hostname = "a.chaos.example.test"
	leaf.CertificateGeneration = 2
	for serial, binding := range map[uint64]Binding{1: wildcard, 2: leaf} {
		if err := registry.Stage(context.Background(), binding, testBundle(t, binding.Hostname, now, serial)); err != nil {
			t.Fatalf("stage %s: %v", binding.Hostname, err)
		}
		if err := registry.MarkReady(context.Background(), binding); err != nil {
			t.Fatalf("ready %s: %v", binding.Hostname, err)
		}
		if err := registry.Activate(context.Background(), binding); err != nil {
			t.Fatalf("activate %s: %v", binding.Hostname, err)
		}
	}
	assertTRK35CertificateSerial(t, registry, leaf.Hostname, 2)
	assertTRK35CertificateSerial(t, registry, "other.chaos.example.test", 1)

	// Stage a replacement whose readiness ACK is lost, then let that staged
	// certificate expire. Both failures must leave the currently active leaf
	// serving while the exact-SNI wildcard sibling remains independent.
	failed := leaf
	failed.CertificateGeneration = 3
	failed.AssignmentGeneration = 3
	failedBundle := testBundle(t, failed.Hostname, now.Add(-23*time.Hour), 3)
	if err := registry.Stage(context.Background(), failed, failedBundle); err != nil {
		t.Fatalf("stage failed replacement: %v", err)
	}
	readyContext, cancelReady := context.WithCancel(context.Background())
	cancelReady()
	if err := registry.MarkReady(readyContext, failed); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost ready ACK error = %v, want context.Canceled", err)
	}
	assertTRK35CertificateSerial(t, registry, leaf.Hostname, 2)
	assertTRK35CertificateSerial(t, registry, "other.chaos.example.test", 1)

	clock = failedBundle.NotAfter
	if err := registry.MarkReady(context.Background(), failed); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expired replacement error = %v, want ErrCertificateExpired", err)
	}
	assertTRK35CertificateSerial(t, registry, leaf.Hostname, 2)
	assertTRK35CertificateSerial(t, registry, "other.chaos.example.test", 1)

	// A later valid candidate can still activate after the failed candidate is
	// fenced out. Revoking that exact leaf then falls back only to the active
	// wildcard; revoking the parent removes the remaining certificate too.
	clock = now
	replacement := leaf
	replacement.CertificateGeneration = 4
	replacement.AssignmentGeneration = 4
	if err := registry.Stage(context.Background(), replacement, testBundle(t, replacement.Hostname, now, 4)); err != nil {
		t.Fatalf("stage valid replacement: %v", err)
	}
	if err := registry.MarkReady(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	assertTRK35CertificateSerial(t, registry, leaf.Hostname, 4)
	if err := registry.Revoke(context.Background(), replacement); err != nil {
		t.Fatalf("revoke exact leaf: %v", err)
	}
	assertTRK35CertificateSerial(t, registry, leaf.Hostname, 1)
	if err := registry.Revoke(context.Background(), wildcard); err != nil {
		t.Fatalf("revoke wildcard parent: %v", err)
	}
	if _, err := registry.GetCertificate(tlsClientHello("other.chaos.example.test")); !errors.Is(err, ErrCertificateMissing) {
		t.Fatalf("revoked wildcard lookup = %v, want missing", err)
	}
}

func assertTRK35CertificateSerial(t *testing.T, registry *Registry, hostname string, want int64) {
	t.Helper()
	certificate, err := registry.GetCertificate(tlsClientHello(hostname))
	if err != nil || certificate == nil || certificate.Leaf == nil || certificate.Leaf.SerialNumber == nil || certificate.Leaf.SerialNumber.Int64() != want {
		t.Fatalf("certificate %s = serial=%v err=%v, want %d", hostname, certificateSerial(certificate), err, want)
	}
}
