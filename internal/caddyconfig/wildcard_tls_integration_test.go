package caddyconfig_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/certbroker"
	paperboatRuntime "github.com/pinksaucepasta/paperboat-tunnel/internal/runtime"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

// TestPlatformAndInfrastructureTLS13Handshake exercises the same boundaries
// used by the embedded Caddy listener: the registry is served by the Unix
// certificate broker, the broker is consumed through the certificate-source
// seam, and DynamicTLSConfig installs the selected certificate for an actual
// TLS 1.3 handshake. Both platform wildcard families and the explicit
// signaling/health infrastructure names are covered, so a broker catch-all
// cannot strand the bootstrap SNI with an internal TLS error.
func TestPlatformAndInfrastructureTLS13Handshake(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	registry, err := tlscert.NewRegistry(tlscert.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()

	preview := platformWildcardBinding("platform_preview", "*.preview.example.test", 1)
	tunnel := platformWildcardBinding("platform_tunnel", "*.tunnels.example.test", 1)
	previewBundle := wildcardBundle(t, preview.Hostname, now, 101)
	tunnelBundle := wildcardBundle(t, tunnel.Hostname, now, 201)
	signaling := infrastructureBinding("platform_signaling", "signal.example.test", 1)
	health := infrastructureBinding("platform_health", "edge.example.test", 1)
	signalingBundle := wildcardBundle(t, signaling.Hostname, now, 301)
	healthBundle := wildcardBundle(t, health.Hostname, now, 302)
	activate := func(binding tlscert.Binding, bundle tlscert.Bundle) {
		t.Helper()
		if err := registry.Stage(context.Background(), binding, bundle); err != nil {
			t.Fatalf("stage %s: %v", binding.Hostname, err)
		}
		if err := registry.MarkReady(context.Background(), binding); err != nil {
			t.Fatalf("ready %s: %v", binding.Hostname, err)
		}
		if err := registry.Activate(context.Background(), binding); err != nil {
			t.Fatalf("activate %s: %v", binding.Hostname, err)
		}
	}
	activate(preview, previewBundle)
	activate(tunnel, tunnelBundle)
	activate(signaling, signalingBundle)
	activate(health, healthBundle)

	socketDir, err := os.MkdirTemp("/tmp", "pb19-wildcard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "certificate.sock")
	broker, err := paperboatRuntime.NewCertificateBroker(paperboatRuntime.CertificateBrokerConfig{SocketPath: socket, Source: registry})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer broker.Shutdown(context.Background())

	// This source is deliberately a client of the real broker protocol. It is
	// the in-process equivalent of Caddy's registered certificate getter and
	// keeps this test independent from a running Caddy process.
	source := brokerCertificateSource{socket: broker.SocketPath()}
	serverConfig, err := caddyconfig.DynamicTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}, source)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, serverConfig)
	var serverWG sync.WaitGroup
	serverDone := make(chan struct{})
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				select {
				case <-serverDone:
					return
				default:
				}
				return
			}
			serverWG.Add(1)
			go func() {
				defer serverWG.Done()
				defer connection.Close()
				// Handshake errors are expected for the revoked cases below.
				_ = connection.(*tls.Conn).Handshake()
			}()
		}
	}()
	defer func() {
		close(serverDone)
		_ = tlsListener.Close()
		serverWG.Wait()
	}()

	address := listener.Addr().String()
	assertHandshake := func(host string, serial int64) {
		t.Helper()
		leaf, err := tls13HandshakeLeaf(address, host)
		if err != nil {
			t.Fatalf("TLS 1.3 handshake for %s: %v", host, err)
		}
		if leaf.SerialNumber == nil || leaf.SerialNumber.Cmp(big.NewInt(serial)) != 0 {
			t.Fatalf("certificate for %s serial=%v, want %d", host, leaf.SerialNumber, serial)
		}
		if err := leaf.VerifyHostname(host); err != nil {
			t.Fatalf("certificate for %s does not verify hostname: %v", host, err)
		}
	}
	assertMissing := func(host string) {
		t.Helper()
		if _, err := tls13HandshakeLeaf(address, host); err == nil {
			t.Fatalf("TLS handshake for revoked %s unexpectedly succeeded", host)
		}
	}

	assertHandshake("alpha.preview.example.test", 101)
	assertHandshake("beta.tunnels.example.test", 201)
	assertHandshake("signal.example.test", 301)
	assertHandshake("edge.example.test", 302)

	preview.CertificateGeneration = 2
	tunnel.CertificateGeneration = 2
	activate(preview, wildcardBundle(t, preview.Hostname, now, 102))
	activate(tunnel, wildcardBundle(t, tunnel.Hostname, now, 202))
	assertHandshake("alpha.preview.example.test", 102)
	assertHandshake("beta.tunnels.example.test", 202)

	if err := registry.Revoke(context.Background(), preview); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(context.Background(), tunnel); err != nil {
		t.Fatal(err)
	}
	assertMissing("alpha.preview.example.test")
	assertMissing("beta.tunnels.example.test")
}

type brokerCertificateSource struct {
	socket string
}

func (s brokerCertificateSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, tlscert.ErrCertificateMissing
	}
	connection, err := net.DialTimeout("unix", s.socket, time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if err := certbroker.Write(connection, certbroker.Request{Version: certbroker.Version, ServerName: hello.ServerName}, certbroker.MaximumRequest); err != nil {
		return nil, err
	}
	var response certbroker.Response
	if err := certbroker.Read(connection, &response, certbroker.MaximumResponse); err != nil {
		return nil, err
	}
	if err := certbroker.ValidateResponse(response); err != nil {
		return nil, err
	}
	if !response.OK {
		if response.Error == "" {
			return nil, errors.New("certificate broker rejected request")
		}
		return nil, fmt.Errorf("certificate broker: %s", response.Error)
	}
	certificate, err := tls.X509KeyPair(response.CertificatePEM, response.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

func tls13HandshakeLeaf(address, host string) (*x509.Certificate, error) {
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, InsecureSkipVerify: true}) // #nosec G402 -- the test verifies the presented leaf explicitly.
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	state := connection.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("negotiated TLS version %x, want TLS 1.3", state.Version)
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server did not present a certificate")
	}
	return state.PeerCertificates[0], nil
}

func platformWildcardBinding(domainID, hostname string, certificateGeneration uint64) tlscert.Binding {
	return tlscert.Binding{AccountID: "platform_account", DomainID: domainID, Hostname: hostname, TargetKind: tlscert.TargetPlatformWildcard, DomainGeneration: 1, CertificateGeneration: certificateGeneration, EdgeNodeID: "edge_001", EdgeProcessEpoch: "epoch_0001", AssignmentGeneration: 1}
}

func infrastructureBinding(domainID, hostname string, certificateGeneration uint64) tlscert.Binding {
	return tlscert.Binding{AccountID: "platform_account", TunnelID: "infra_tunnel", DomainID: domainID, Hostname: hostname, TargetKind: tlscert.TargetDurableRoute, RouteID: "infra_route", DomainGeneration: 1, CertificateGeneration: certificateGeneration, EdgeNodeID: "edge_001", EdgeProcessEpoch: "epoch_0001", AssignmentGeneration: 1}
}

func wildcardBundle(t *testing.T, hostname string, now time.Time, serial int64) tlscert.Bundle {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return tlscert.Bundle{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), Issuer: "platform-test", NotBefore: template.NotBefore, NotAfter: template.NotAfter}
}
