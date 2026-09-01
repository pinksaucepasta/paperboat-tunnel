package tlscert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestRegistryRequiresReadyBeforeActivationAndFencesReplacement(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	clock := now
	registry, err := NewRegistry(Config{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	binding1 := testBinding("preview.example.test", 1)
	bundle1 := testBundle(t, binding1.Hostname, now, 1)
	if err := registry.Stage(context.Background(), binding1, bundle1); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding1); !errors.Is(err, ErrNotReady) {
		t.Fatalf("activate before ready: %v", err)
	}
	if err := registry.MarkReady(context.Background(), binding1); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding1); err != nil {
		t.Fatal(err)
	}
	if err := registry.Retire(context.Background(), binding1); !errors.Is(err, ErrReplacementNotReady) {
		t.Fatalf("retire active certificate without replacement: %v", err)
	}

	binding2 := binding1
	binding2.CertificateGeneration = 2
	bundle2 := testBundle(t, binding2.Hostname, now, 2)
	if err := registry.Stage(context.Background(), binding2, bundle2); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), binding2); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding2); err != nil {
		t.Fatal(err)
	}
	if err := registry.Retire(context.Background(), binding1); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetCertificate(tlsClientHello("preview.example.test")); err != nil {
		t.Fatal(err)
	}
	if err := registry.Stage(context.Background(), binding1, bundle1); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale generation stage: %v", err)
	}
	views := registry.Snapshot()
	if len(views) != 1 || views[0].Binding.CertificateGeneration != 2 || views[0].State != StateActive {
		t.Fatalf("unexpected replacement snapshot: %+v", views)
	}
}

func TestRegistryMatchesExactAndOneLabelWildcardOnly(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	exact := testBinding("exact.example.test", 1)
	wild := testBinding("*.wild.example.test", 1)
	wild.DomainID = "domain_2"
	for _, binding := range []Binding{exact, wild} {
		bundle := testBundle(t, binding.Hostname, now, binding.CertificateGeneration)
		if err := registry.Stage(context.Background(), binding, bundle); err != nil {
			t.Fatal(err)
		}
		if err := registry.MarkReady(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		if err := registry.Activate(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		host   string
		found  bool
		status error
	}{
		{host: "exact.example.test", found: true},
		{host: "one.wild.example.test", found: true},
		{host: "two.one.wild.example.test", found: false, status: ErrCertificateMissing},
		{host: "wild.example.test", found: false, status: ErrCertificateMissing},
		{host: "other.example.test", found: false, status: ErrCertificateMissing},
	} {
		certificate, err := registry.GetCertificate(tlsClientHello(test.host))
		if test.found {
			if err != nil || certificate == nil {
				t.Fatalf("%s: certificate=%v err=%v", test.host, certificate, err)
			}
		} else if !errors.Is(err, test.status) {
			t.Fatalf("%s: err=%v, want %v", test.host, err, test.status)
		}
	}
}

func TestRegistryAcceptsOnlyBoundPlatformWildcardFamilies(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		domainID string
		hostname string
		child    string
		serial   uint64
	}{
		{domainID: "platform_preview", hostname: "*.preview.example.test", child: "random.preview.example.test", serial: 11},
		{domainID: "platform_tunnel", hostname: "*.tunnels.example.test", child: "random.tunnels.example.test", serial: 12},
	} {
		binding := testBinding(test.hostname, 1)
		binding.TargetKind = TargetPlatformWildcard
		binding.TunnelID = ""
		binding.DomainID = test.domainID
		bundle := testBundle(t, binding.Hostname, now, test.serial)
		if err := registry.Stage(context.Background(), binding, bundle); err != nil {
			t.Fatalf("stage %s: %v", binding.Hostname, err)
		}
		if err := registry.MarkReady(context.Background(), binding); err != nil {
			t.Fatalf("ready %s: %v", binding.Hostname, err)
		}
		if err := registry.Activate(context.Background(), binding); err != nil {
			t.Fatalf("activate %s: %v", binding.Hostname, err)
		}
		certificate, err := registry.GetCertificate(tlsClientHello(test.child))
		if err != nil || certificate == nil || certificate.Leaf == nil || certificate.Leaf.SerialNumber.Uint64() != test.serial {
			t.Fatalf("lookup %s: serial=%v err=%v", test.child, certificateSerial(certificate), err)
		}
		if _, err := registry.GetCertificate(tlsClientHello("nested." + test.child)); !errors.Is(err, ErrCertificateMissing) {
			t.Fatalf("nested lookup %s: %v", test.child, err)
		}
		if _, err := registry.GetCertificate(tlsClientHello(strings.TrimPrefix(test.hostname, "*."))); !errors.Is(err, ErrCertificateMissing) {
			t.Fatalf("apex lookup %s: %v", test.hostname, err)
		}
	}

	invalid := testBinding("platform.example.test", 1)
	invalid.TargetKind = TargetPlatformWildcard
	invalid.TunnelID = ""
	if err := registry.Stage(context.Background(), invalid, testBundle(t, invalid.Hostname, now, 13)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("platform exact binding accepted: %v", err)
	}
	invalid.Hostname = "*.platform.example.test"
	invalid.OnDemandLeaf = true
	if err := registry.Stage(context.Background(), invalid, testBundle(t, invalid.Hostname, now, 14)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("platform on-demand binding accepted: %v", err)
	}
}

func TestRegistryFencesReplacementEdgeProcessForSameCertificate(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	oldBinding := testBinding("restart.example.test", 1)
	oldBundle := testBundle(t, oldBinding.Hostname, now, 1)
	if err := registry.Stage(context.Background(), oldBinding, oldBundle); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), oldBinding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), oldBinding); err != nil {
		t.Fatal(err)
	}
	newBinding := oldBinding
	newBinding.EdgeProcessEpoch = "epoch_0002"
	newBinding.AssignmentGeneration = 2
	if err := registry.Stage(context.Background(), newBinding, oldBundle); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), newBinding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), newBinding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Retire(context.Background(), oldBinding); err != nil {
		t.Fatal(err)
	}
	views := registry.Snapshot()
	if len(views) != 1 || views[0].Binding.EdgeProcessEpoch != newBinding.EdgeProcessEpoch || views[0].State != StateActive {
		t.Fatalf("replacement process snapshot = %+v", views)
	}
}

func TestRegistryRebindsPreviewLeaseWithoutCertificateGenerationChurn(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	clock := now
	registry, err := NewRegistry(Config{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("preview-rebind.example.test", 1)
	binding.TunnelID = ""
	binding.TargetKind = TargetPreviewLease
	binding.PreviewID = "preview_1"
	binding.PreviewGeneration = 4
	binding.PreviewState = "active"
	binding.PreviewExpiresAt = now.Add(time.Hour)
	bundle := testBundle(t, binding.Hostname, now, 1)
	for _, step := range []func() error{
		func() error { return registry.Stage(context.Background(), binding, bundle) },
		func() error { return registry.MarkReady(context.Background(), binding) },
		func() error { return registry.Activate(context.Background(), binding) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	rebound := binding
	rebound.PreviewGeneration = 5
	rebound.PreviewExpiresAt = now.Add(2 * time.Hour)
	if err := registry.Stage(context.Background(), rebound, bundle); err != nil {
		t.Fatalf("stage rebind: %v", err)
	}
	if err := registry.MarkReady(context.Background(), rebound); err != nil {
		t.Fatalf("ready rebind: %v", err)
	}
	if err := registry.Activate(context.Background(), rebound); err != nil {
		t.Fatalf("activate rebind: %v", err)
	}
	views := registry.Snapshot()
	if len(views) != 1 || views[0].State != StateActive || views[0].Binding.PreviewGeneration != 5 || views[0].Binding.CertificateGeneration != 1 {
		t.Fatalf("rebind snapshot = %+v", views)
	}
	if _, err := registry.GetCertificate(tlsClientHello(binding.Hostname)); err != nil {
		t.Fatalf("rebound lookup: %v", err)
	}
}

func TestRegistryKeepsWildcardAndExactLeavesIndependent(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	wildcard := testBinding("*.leaves.example.test", 1)
	leafA := wildcard
	leafA.Hostname = "a.leaves.example.test"
	leafB := wildcard
	leafB.Hostname = "b.leaves.example.test"
	bindings := []struct {
		binding Binding
		serial  uint64
	}{
		{wildcard, 1},
		{leafA, 2},
		{leafB, 3},
	}
	for _, item := range bindings {
		if err := registry.Stage(context.Background(), item.binding, testBundle(t, item.binding.Hostname, now, item.serial)); err != nil {
			t.Fatalf("stage %s: %v", item.binding.Hostname, err)
		}
		if err := registry.MarkReady(context.Background(), item.binding); err != nil {
			t.Fatalf("ready %s: %v", item.binding.Hostname, err)
		}
		if err := registry.Activate(context.Background(), item.binding); err != nil {
			t.Fatalf("activate %s: %v", item.binding.Hostname, err)
		}
	}
	assertSerial := func(host string, want int64) {
		t.Helper()
		certificate, err := registry.GetCertificate(tlsClientHello(host))
		if err != nil || certificate == nil || certificate.Leaf == nil || certificate.Leaf.SerialNumber.Int64() != want {
			t.Fatalf("certificate %s = serial=%v err=%v, want %d", host, certificateSerial(certificate), err, want)
		}
	}
	assertSerial("a.leaves.example.test", 2)
	assertSerial("b.leaves.example.test", 3)
	assertSerial("other.leaves.example.test", 1)
	if err := registry.Revoke(context.Background(), leafA); err != nil {
		t.Fatal(err)
	}
	assertSerial("a.leaves.example.test", 1)
	assertSerial("b.leaves.example.test", 3)
	assertSerial("other.leaves.example.test", 1)
	if err := registry.Revoke(context.Background(), leafB); err != nil {
		t.Fatal(err)
	}
	assertSerial("b.leaves.example.test", 1)
}

func TestRegistryOnDemandWildcardMarksOnlyOneLabelMisses(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	parent := testBinding("*.ondemand.example.test", 1)
	parent.OnDemandLeaf = true
	if err := registry.Stage(context.Background(), parent, testBundle(t, parent.Hostname, now, 1)); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host string
		want bool
	}{
		{host: "one.ondemand.example.test", want: true},
		{host: "two.one.ondemand.example.test", want: false},
		{host: "ondemand.example.test", want: false},
		{host: "*.ondemand.example.test", want: false},
	} {
		if got := registry.RequiresExactCertificate(test.host); got != test.want {
			t.Fatalf("RequiresExactCertificate(%q) = %v, want %v", test.host, got, test.want)
		}
		if _, err := registry.GetCertificate(tlsClientHello(test.host)); !errors.Is(err, ErrCertificateMissing) {
			t.Fatalf("GetCertificate(%q) = %v, want missing", test.host, err)
		}
	}

	leaf := parent
	leaf.Hostname = "one.ondemand.example.test"
	leaf.OnDemandLeaf = false
	leaf.CertificateGeneration = 2
	if err := registry.Stage(context.Background(), leaf, testBundle(t, leaf.Hostname, now, 2)); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), leaf); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), leaf); err != nil {
		t.Fatal(err)
	}
	if registry.RequiresExactCertificate(leaf.Hostname) {
		t.Fatal("active exact leaf still marked on-demand")
	}
	if _, err := registry.GetCertificate(tlsClientHello(leaf.Hostname)); err != nil {
		t.Fatalf("active exact leaf lookup: %v", err)
	}
}

func certificateSerial(certificate *tls.Certificate) any {
	if certificate == nil || certificate.Leaf == nil || certificate.Leaf.SerialNumber == nil {
		return nil
	}
	return certificate.Leaf.SerialNumber
}

func TestRegistryRejectsInvalidBindingAndRevocationOrExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("secure.example.test", 1)
	bundle := testBundle(t, binding.Hostname, now, 1)
	wrong := bundle
	wrong.PrivateKeyPEM = testBundle(t, binding.Hostname, now, 99).PrivateKeyPEM
	if err := registry.Stage(context.Background(), binding, wrong); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("mismatched key: %v", err)
	}
	wrongBinding := binding
	wrongBinding.Hostname = "other.example.test"
	if err := registry.Stage(context.Background(), wrongBinding, bundle); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("wrong hostname: %v", err)
	}
	if err := registry.Stage(context.Background(), binding, bundle); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetCertificate(tlsClientHello(binding.Hostname)); !errors.Is(err, ErrCertificateMissing) {
		t.Fatalf("revoked certificate lookup: %v", err)
	}

	expiredBinding := testBinding("expired.example.test", 1)
	if err := registry.Stage(context.Background(), expiredBinding, testBundle(t, expiredBinding.Hostname, now, 2)); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), expiredBinding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), expiredBinding); err != nil {
		t.Fatal(err)
	}
	now = now.Add(48 * time.Hour)
	if _, err := registry.GetCertificate(tlsClientHello(expiredBinding.Hostname)); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expired certificate lookup: %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registry.Stage(context.Background(), binding, testBundle(t, binding.Hostname, now, 3)); !errors.Is(err, ErrClosed) {
		t.Fatalf("stage after close: %v", err)
	}
}

func TestRegistryContextCancellationDoesNotMutate(t *testing.T) {
	registry, err := NewRegistry(Config{})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("cancel.example.test", 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registry.Stage(ctx, binding, testBundle(t, binding.Hostname, time.Now().UTC(), 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stage: %v", err)
	}
	if got := registry.Snapshot(); len(got) != 0 {
		t.Fatalf("cancelled stage mutated registry: %+v", got)
	}
}

func TestNormalizeHostnameCanonicalizesIDNA(t *testing.T) {
	got, wildcard, err := NormalizeHostname("TÉST.Example.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if wildcard || got != "xn--tst-bma.example.test" {
		t.Fatalf("normalized IDNA hostname = %q wildcard=%v", got, wildcard)
	}
	got, wildcard, err = NormalizeHostname("*.TÉST.Example.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if !wildcard || got != "*.xn--tst-bma.example.test" {
		t.Fatalf("normalized IDNA wildcard = %q wildcard=%v", got, wildcard)
	}
}

func testBinding(host string, certificateGeneration uint64) Binding {
	return Binding{AccountID: "account_1", TunnelID: "tunnel_1", DomainID: "domain_1", Hostname: host, DomainGeneration: 1, CertificateGeneration: certificateGeneration, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_0001", AssignmentGeneration: 1}
}

func testBundle(t *testing.T, hostname string, now time.Time, serial uint64) Bundle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetUint64(serial), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), Issuer: "test-ca", NotBefore: template.NotBefore, NotAfter: template.NotAfter}
}

func tlsClientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: serverName}
}
