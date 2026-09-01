package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/certbroker"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

func TestCertificateBrokerServesRegistryReplacementAndRevoke(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	clock := now
	registry, err := tlscert.NewRegistry(tlscert.Config{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	binding := tlscert.Binding{AccountID: "account_1", TunnelID: "tunnel_1", DomainID: "domain_1", Hostname: "preview.example.test", DomainGeneration: 1, CertificateGeneration: 1, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_0001", AssignmentGeneration: 1}
	bundle1 := brokerTestBundle(t, binding.Hostname, now, 1)
	if err := registry.Stage(context.Background(), binding, bundle1); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	broker, err := NewCertificateBroker(CertificateBrokerConfig{SocketPath: brokerTestSocket(t, ""), Source: registry})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Shutdown(context.Background()) }()
	first := brokerFetchCertificate(t, broker.SocketPath(), binding.Hostname)
	if first.Leaf == nil || first.Leaf.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("first certificate serial = %v", first.Leaf)
	}
	binding2 := binding
	binding2.CertificateGeneration = 2
	bundle2 := brokerTestBundle(t, binding2.Hostname, now, 2)
	if err := registry.Stage(context.Background(), binding2, bundle2); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkReady(context.Background(), binding2); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(context.Background(), binding2); err != nil {
		t.Fatal(err)
	}
	second := brokerFetchCertificate(t, broker.SocketPath(), binding.Hostname)
	if second.Leaf == nil || second.Leaf.SerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("replacement certificate serial = %v", second.Leaf.SerialNumber)
	}
	if err := registry.Revoke(context.Background(), binding2); err != nil {
		t.Fatal(err)
	}
	response := brokerFetchResponse(t, broker.SocketPath(), binding.Hostname)
	if response.OK || response.Error == "" || len(response.CertificatePEM) != 0 || len(response.PrivateKeyPEM) != 0 {
		t.Fatalf("revoked response leaked or succeeded: %+v", response)
	}
}

func TestCertificateBrokerOwnsPrivateSocketAndRejectsInvalidRequests(t *testing.T) {
	socket := brokerTestSocket(t, "nested")
	broker, err := NewCertificateBroker(CertificateBrokerConfig{SocketPath: socket, Source: brokerSource{host: "example.test", certificate: brokerTestCertificate(t, "example.test", time.Now().UTC(), 1)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("broker socket mode/type = %v", info.Mode())
	}
	response := brokerFetchResponse(t, socket, "unknown.example.test")
	if response.OK || response.Error == "" {
		t.Fatalf("unknown certificate response = %+v", response)
	}
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := certbroker.Write(connection, certbroker.Request{Version: certbroker.Version, ServerName: "bad/name.example.test"}, certbroker.MaximumRequest); err != nil {
		t.Fatal(err)
	}
	var invalid certbroker.Response
	if err := certbroker.Read(connection, &invalid, certbroker.MaximumResponse); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if invalid.OK || invalid.Error != "certificate_request_invalid" {
		t.Fatalf("invalid request response = %+v", invalid)
	}
	if err := broker.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}

func TestCertificateBrokerChecksDERNotStaleLeafMetadata(t *testing.T) {
	now := time.Now().UTC()
	claimed := brokerTestCertificate(t, "example.test", now, 31)
	actual := brokerTestCertificate(t, "other.example.test", now, 32)
	// Leaf is a caller-maintained cache. Deliberately make it claim a
	// different hostname than the DER and private key that the broker would
	// send. The broker must inspect Certificate[0], not trust this cache.
	actual.Leaf = claimed.Leaf
	broker, err := NewCertificateBroker(CertificateBrokerConfig{
		SocketPath: brokerTestSocket(t, "stale-leaf"),
		Source:     brokerSource{host: "example.test", certificate: actual},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer broker.Shutdown(context.Background())
	response := brokerFetchResponse(t, broker.SocketPath(), "example.test")
	if response.OK || response.Error != "certificate_unavailable" {
		t.Fatalf("stale leaf metadata was trusted: %+v", response)
	}
}

func TestCertificateBrokerConcurrentStartShutdown(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		broker, err := NewCertificateBroker(CertificateBrokerConfig{
			SocketPath: brokerTestSocket(t, "concurrent"),
			Source:     brokerSource{certificate: brokerTestCertificate(t, "example.test", time.Now().UTC(), int64(attempt+1))},
		})
		if err != nil {
			t.Fatal(err)
		}
		startResult := make(chan error, 1)
		shutdownResult := make(chan error, 1)
		go func() { startResult <- broker.Start(context.Background()) }()
		go func() { shutdownResult <- broker.Shutdown(context.Background()) }()
		startErr := <-startResult
		shutdownErr := <-shutdownResult
		if shutdownErr != nil {
			t.Fatalf("attempt %d shutdown error = %v", attempt, shutdownErr)
		}
		if startErr != nil && !errors.Is(startErr, ErrCertificateBrokerInvalid) {
			t.Fatalf("attempt %d start error = %v", attempt, startErr)
		}
		if err := broker.Shutdown(context.Background()); err != nil {
			t.Fatalf("attempt %d final shutdown error = %v", attempt, err)
		}
	}
}

func TestCertificateBrokerRequestsExactLeafOnMissWithSingleFlight(t *testing.T) {
	now := time.Now().UTC()
	host := "leaf.example.test"
	source := &onDemandBrokerSource{}
	certificate := brokerTestCertificate(t, host, now, 17)
	var requestsMu sync.Mutex
	requests := 0
	broker, err := NewCertificateBroker(CertificateBrokerConfig{
		SocketPath: brokerTestSocket(t, "on-demand"), Source: source,
		OnDemandRequester: OnDemandCertificateRequesterFunc(func(ctx context.Context, requested string) error {
			if requested != host {
				return errors.New("unexpected hostname")
			}
			requestsMu.Lock()
			requests++
			requestsMu.Unlock()
			source.set(certificate)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Shutdown(context.Background()) }()

	const callers = 8
	results := make(chan certbroker.Response, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- brokerFetchResponse(t, broker.SocketPath(), host)
		}()
	}
	wg.Wait()
	close(results)
	for response := range results {
		if !response.OK {
			t.Fatalf("on-demand response = %+v", response)
		}
	}
	requestsMu.Lock()
	deferredRequests := requests
	requestsMu.Unlock()
	if deferredRequests != 1 {
		t.Fatalf("on-demand request count = %d, want 1", deferredRequests)
	}

	// A policy-marked SNI must not silently receive an already-active wildcard
	// certificate. The matcher forces the request path before the source is
	// consulted, and the resulting certificate is the exact leaf.
	matcherSource := &onDemandBrokerSource{}
	matcherCertificate := brokerTestCertificate(t, host, now, 18)
	matcherBroker, err := NewCertificateBroker(CertificateBrokerConfig{
		SocketPath: brokerTestSocket(t, "matcher"), Source: matcherSource,
		OnDemandMatcher: OnDemandCertificateMatcherFunc(func(requested string) bool { return requested == host }),
		OnDemandRequester: OnDemandCertificateRequesterFunc(func(ctx context.Context, requested string) error {
			if requested != host {
				return errors.New("unexpected hostname")
			}
			matcherSource.set(matcherCertificate)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := matcherBroker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = matcherBroker.Shutdown(context.Background()) }()
	response := brokerFetchCertificate(t, matcherBroker.SocketPath(), host)
	if response.Leaf == nil || response.Leaf.SerialNumber.Cmp(big.NewInt(18)) != 0 {
		t.Fatalf("matched exact leaf serial = %v", response.Leaf)
	}
}

func TestCertificateBrokerMatcherServesInstalledExactWithoutRequest(t *testing.T) {
	now := time.Now().UTC()
	host := "leaf.example.test"
	source := &onDemandBrokerSource{}
	source.set(brokerTestCertificate(t, host, now, 19))
	var requestsMu sync.Mutex
	requests := 0
	broker, err := NewCertificateBroker(CertificateBrokerConfig{
		SocketPath:      brokerTestSocket(t, "matcher-active"),
		Source:          source,
		OnDemandMatcher: OnDemandCertificateMatcherFunc(func(requested string) bool { return requested == host }),
		OnDemandRequester: OnDemandCertificateRequesterFunc(func(context.Context, string) error {
			requestsMu.Lock()
			requests++
			requestsMu.Unlock()
			return errors.New("unexpected duplicate request")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Shutdown(context.Background()) }()
	certificate := brokerFetchCertificate(t, broker.SocketPath(), host)
	if certificate.Leaf == nil || certificate.Leaf.SerialNumber.Cmp(big.NewInt(19)) != 0 {
		t.Fatalf("installed exact leaf serial = %v", certificate.Leaf)
	}
	requestsMu.Lock()
	deferredRequests := requests
	requestsMu.Unlock()
	if deferredRequests != 0 {
		t.Fatalf("on-demand request count = %d, want 0", deferredRequests)
	}
}

func TestCertificateBrokerOnDemandIsBoundedAndFailsClosed(t *testing.T) {
	source := &onDemandBrokerSource{}
	broker, err := NewCertificateBroker(CertificateBrokerConfig{
		SocketPath: brokerTestSocket(t, "timeout"), Source: source, HandshakeTimeout: 40 * time.Millisecond,
		OnDemandRequester: OnDemandCertificateRequesterFunc(func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Shutdown(context.Background()) }()
	response := brokerFetchResponse(t, broker.SocketPath(), "leaf.example.test")
	if response.OK || response.Error != "certificate_unavailable" || len(response.PrivateKeyPEM) != 0 {
		t.Fatalf("bounded on-demand response = %+v", response)
	}
}

type onDemandBrokerSource struct {
	mu          sync.RWMutex
	certificate *tls.Certificate
}

func (s *onDemandBrokerSource) set(certificate tls.Certificate) {
	s.mu.Lock()
	s.certificate = &certificate
	s.mu.Unlock()
}

func (s *onDemandBrokerSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.certificate == nil {
		return nil, tlscert.ErrCertificateMissing
	}
	return s.certificate, nil
}

type brokerSource struct {
	host        string
	certificate tls.Certificate
}

func (s brokerSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || s.host != "" && hello.ServerName != s.host {
		return nil, errors.New("certificate is not configured")
	}
	return &s.certificate, nil
}

func brokerFetchCertificate(t *testing.T, socket, host string) tls.Certificate {
	t.Helper()
	response := brokerFetchResponse(t, socket, host)
	if !response.OK {
		t.Fatalf("broker certificate error: %+v", response)
	}
	certificate, err := tls.X509KeyPair(response.CertificatePEM, response.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func brokerFetchResponse(t *testing.T, socket, host string) certbroker.Response {
	t.Helper()
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := certbroker.Write(connection, certbroker.Request{Version: certbroker.Version, ServerName: host}, certbroker.MaximumRequest); err != nil {
		t.Fatal(err)
	}
	var response certbroker.Response
	if err := certbroker.Read(connection, &response, certbroker.MaximumResponse); err != nil {
		t.Fatal(err)
	}
	if err := certbroker.ValidateResponse(response); err != nil {
		t.Fatal(err)
	}
	return response
}

func brokerTestBundle(t *testing.T, host string, now time.Time, serial int64) tlscert.Bundle {
	t.Helper()
	certificate := brokerTestCertificate(t, host, now, serial)
	certificatePEM := make([]byte, 0, len(certificate.Certificate[0]))
	for _, der := range certificate.Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tlscert.Bundle{CertificatePEM: certificatePEM, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), Issuer: "test", NotBefore: certificate.Leaf.NotBefore, NotAfter: certificate.Leaf.NotAfter}
}

func brokerTestCertificate(t *testing.T, host string, now time.Time, serial int64) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: template}
}

func brokerTestSocket(t *testing.T, nested string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pb19-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if nested != "" {
		directory = filepath.Join(directory, nested)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(directory, "certificate.sock")
}
