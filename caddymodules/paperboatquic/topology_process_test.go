package paperboatquic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	edgeauth "github.com/pinksaucepasta/paperboat-tunnel/internal/auth"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelayhttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalinghttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalingprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/stunserver"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type topologyFileReadiness struct{}

func (topologyFileReadiness) RouteState(string) (string, string, string, bool) {
	return "runtime_https_wss", "ready", "", true
}

type topologyNoRevocations struct{}

func (topologyNoRevocations) Revoked(context.Context, admission.Claims) (bool, error) {
	return false, nil
}

func TestTopologyRelayProcess(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_ROLE") == "" {
		t.Skip("topology relay process mode is not configured")
	}
	if os.Getenv("PAPERBOAT_TOPOLOGY_ROLE") != "relay-edge" {
		t.Fatal("invalid topology relay process role")
	}
	manager, err := peerrelay.NewManager(peerrelay.DevelopmentConfig(), topologyRelayRecorder{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	authenticator := newTopologyRelayAuthenticator()
	signaling, err := peersignaling.New(peersignaling.Config{
		Authenticator: authenticator.production, Validators: peersignalingprotocol.Factory{},
		MaximumSessions: 4, MaximumConsumed: 8, QueueDepth: 64, MaximumMessage: peersignalingprotocol.MaximumMessage,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer signaling.Close()
	handler := http.NewServeMux()
	handler.Handle("/v1/peer-relay", peerrelayhttp.Handler{Path: "/v1/peer-relay", Authenticator: authenticator, Manager: manager})
	handler.Handle("/v1/peer-signaling", peersignalinghttp.Handler{Path: "/v1/peer-signaling", Service: signaling, ObserveError: func(err error) {
		fmt.Printf("PAPERBOAT_TOPOLOGY_SIGNALING_ERROR %v\n", err)
	}})
	if os.Getenv("PAPERBOAT_TOPOLOGY_FILE_RELAY") == "1" {
		upstream := os.Getenv("PAPERBOAT_TOPOLOGY_FILE_UPSTREAM")
		target, parseErr := url.Parse("http://" + upstream)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ModifyResponse = func(response *http.Response) error {
			fmt.Printf("PAPERBOAT_TOPOLOGY_FILE_UPSTREAM proto=%s path=%s status=%d\n", response.Proto, response.Request.URL.Path, response.StatusCode)
			return nil
		}
		proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
			fmt.Printf("PAPERBOAT_TOPOLOGY_FILE_UPSTREAM_ERROR path=%s error=%v\n", request.URL.Path, proxyErr)
			http.Error(writer, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		}
		policy, policyErr := edgehttp.New(edgehttp.Config{
			PreviewBaseDomain: "preview.paperboat.test", HelperBaseDomain: "paperboat.test",
			MaxHeaderBytes: 32 << 10, MaxBodyBytes: 8 << 20, Readiness: topologyFileReadiness{},
			HelperAccess: authenticator.production, Revocations: topologyNoRevocations{}, RevocationCheckInterval: time.Second,
		}, proxy)
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		handler.Handle("/", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			status := &topologyStatusWriter{ResponseWriter: writer, status: http.StatusOK}
			policy.ServeHTTP(status, request)
			fmt.Printf("PAPERBOAT_TOPOLOGY_FILE_RELAY proto=%s host=%s absolute=%t method=%s path=%s status=%d\n", request.Proto, request.Host, request.URL.IsAbs(), request.Method, request.URL.Path, status.status)
		}))
	}
	stun, err := stunserver.New(stunserver.Config{Address: "0.0.0.0:3478", AuthenticatePMTU: func(token string, _ netip.AddrPort) bool {
		if err := authenticator.production.AuthenticatePMTU(context.Background(), token); err != nil {
			return false
		}
		fmt.Println("PAPERBOAT_TOPOLOGY_PMTU_ADMITTED")
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stun.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", "0.0.0.0:9443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler:   handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{topologyRelayCertificate(t)}, NextProtos: []string{http3.NextProtoH3}},
	}
	wssListener, err := net.Listen("tcp4", "0.0.0.0:9444")
	if err != nil {
		t.Fatal(err)
	}
	wssServer := &http.Server{
		Handler:           handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{topologyRelayCertificate(t)}, NextProtos: []string{"http/1.1"}},
		ReadHeaderTimeout: 2 * time.Second,
	}
	h2Listener, err := net.Listen("tcp4", "0.0.0.0:9442")
	if err != nil {
		t.Fatal(err)
	}
	h2Server := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{topologyRelayCertificate(t)}, NextProtos: []string{"h2", "http/1.1"}}, ReadHeaderTimeout: 2 * time.Second}
	if err := http2.ConfigureServer(h2Server, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	wssErrors := make(chan error, 1)
	go func() { wssErrors <- wssServer.Serve(tls.NewListener(wssListener, wssServer.TLSConfig)) }()
	h2Errors := make(chan error, 1)
	go func() { h2Errors <- h2Server.Serve(tls.NewListener(h2Listener, h2Server.TLSConfig)) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := wssServer.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := h2Server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if err := stun.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		_ = packet.Close()
	}()
	fmt.Println("PAPERBOAT_TOPOLOGY_RELAY_EDGE_READY")
	h3Errors := make(chan error, 1)
	go func() { h3Errors <- server.Serve(packet) }()
	select {
	case err := <-h3Errors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case err := <-wssErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case err := <-h2Errors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case err := <-stun.Done():
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	}
}

type topologyStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *topologyStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func topologyRelayCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay.paperboat.test"},
		NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0),
		DNSNames: []string{"relay.paperboat.test", "machine.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}
}

type topologyRelayAuthenticator struct {
	production *edgeauth.Verifier
}

type topologyRelayKeySource struct {
	key ed25519.PublicKey
}

func (source topologyRelayKeySource) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	if keyID != "peer-integration" {
		return nil, edgeauth.ErrSnapshotInvalid
	}
	return append(ed25519.PublicKey(nil), source.key...), nil
}

func newTopologyRelayAuthenticator() topologyRelayAuthenticator {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'i'}, ed25519.SeedSize))
	return topologyRelayAuthenticator{production: &edgeauth.Verifier{
		Issuer: "https://authority.paperboat.test:9445",
		NodeID: "edge-topology",
		Keys:   topologyRelayKeySource{key: private.Public().(ed25519.PublicKey)},
	}}
}

func (authenticator topologyRelayAuthenticator) AuthenticateRelay(ctx context.Context, credential string, attachment peerrelayhttp.Attachment) (peerrelay.Admission, error) {
	if credential != "relay.payload.signature" {
		admission, err := authenticator.production.AuthenticateRelay(ctx, credential, attachment)
		if err == nil {
			fmt.Printf("PAPERBOAT_TOPOLOGY_RELAY_ADMITTED role=%d carrier=%d\n", attachment.Role, attachment.Carrier)
		} else {
			fmt.Printf("PAPERBOAT_TOPOLOGY_RELAY_REJECTED role=%d carrier=%d error=%T\n", attachment.Role, attachment.Carrier, err)
		}
		return admission, err
	}
	if attachment.StreamHandle == [16]byte{} || attachment.Carrier != peerrelay.CarrierQUIC && attachment.Carrier != peerrelay.CarrierWSS {
		return peerrelay.Admission{}, peerrelay.ErrInvalid
	}
	wantEndpoint := "endpoint-cli"
	if attachment.Role == peerrelay.RoleHost {
		wantEndpoint = "endpoint-host"
	}
	if attachment.EndpointID != wantEndpoint {
		return peerrelay.Admission{}, peerrelay.ErrInvalid
	}
	return peerrelay.Admission{Binding: topologyRelayBinding(attachment.StreamHandle), Role: attachment.Role, Carrier: attachment.Carrier}, nil
}

type topologyRelayRecorder struct{}

func (topologyRelayRecorder) RecordRelayUsage(context.Context, peerrelay.Usage) error { return nil }

func topologyRelayBinding(handle [16]byte) peerrelay.Binding {
	var allocation [16]byte
	for index := range allocation {
		allocation[index] = 4
	}
	return peerrelay.Binding{
		RouteAllocation: allocation, StreamHandle: handle, EnvironmentID: "environment-topology",
		RouteID: "route-topology", RouteRevision: 1, IntentID: "intent-topology", Attempt: 1, Network: 1,
		ExpiresAt: time.Unix(4_102_444_800, 0), MaximumBytes: 1 << 20,
	}
}
