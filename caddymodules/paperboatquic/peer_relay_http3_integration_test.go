package paperboatquic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelayhttp"
	"github.com/quic-go/quic-go/http3"
)

func TestPeerRelayHTTP3PairsOpaqueStreamsAndAccountsCancellation(t *testing.T) {
	recorder := &relayUsageRecorder{}
	config := peerrelay.DevelopmentConfig()
	manager, err := peerrelay.NewManager(config, recorder, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	binding := relayTestBinding(time.Now().Add(time.Minute))
	handler := peerrelayhttp.Handler{
		Path: "/v1/peer-relay",
		Authenticator: relayAuthenticatorFunc(func(_ context.Context, credential string, attachment peerrelayhttp.Attachment) (peerrelay.Admission, error) {
			if credential != "relay.integration.token" || attachment.StreamHandle != binding.StreamHandle {
				return peerrelay.Admission{}, errors.New("unauthorized relay attachment")
			}
			if attachment.Carrier != peerrelay.CarrierQUIC {
				return peerrelay.Admission{}, errors.New("unexpected relay carrier")
			}
			switch attachment.Role {
			case peerrelay.RoleInitiator:
				if attachment.EndpointID != "endpoint_cli" {
					return peerrelay.Admission{}, errors.New("unexpected initiator")
				}
			case peerrelay.RoleHost:
				if attachment.EndpointID != "endpoint_host" {
					return peerrelay.Admission{}, errors.New("unexpected host")
				}
			default:
				return peerrelay.Admission{}, errors.New("unexpected relay role")
			}
			return peerrelay.Admission{Binding: binding, Role: attachment.Role, Carrier: attachment.Carrier}, nil
		}),
		Manager: manager,
	}

	client, endpoint := newHTTP3TestServer(t, handler)
	initiator := openRelayHTTP3Leg(t, client, endpoint, binding.StreamHandle, "endpoint_cli", "initiator")
	host := openRelayHTTP3Leg(t, client, endpoint, binding.StreamHandle, "endpoint_host", "responder")

	toHost := []byte("opaque-noise-record-to-host")
	writeRelayLeg(t, initiator, toHost)
	readRelayLeg(t, host, toHost)
	toInitiator := []byte("opaque-noise-record-to-initiator")
	writeRelayLeg(t, host, toInitiator)
	readRelayLeg(t, initiator, toInitiator)

	initiator.cancel()
	initiator.close(t)
	host.close(t)

	usage := recorder.wait(t)
	if usage.Path != peerrelay.PathRelayQUIC || usage.BytesToHost != uint64(len(toHost)) || usage.BytesToInitiator != uint64(len(toInitiator)) {
		t.Fatalf("usage=%+v", usage)
	}
	if stats := manager.Stats(); stats != (peerrelay.Stats{}) {
		t.Fatalf("relay stats after cancellation=%+v", stats)
	}

	replay := openRelayHTTP3Leg(t, client, endpoint, binding.StreamHandle, "endpoint_cli", "initiator")
	replay.close(t)
	if got := recorder.snapshot(); len(got) != 1 {
		t.Fatalf("replayed handle recorded usage: %+v", got)
	}
}

type relayAuthenticatorFunc func(context.Context, string, peerrelayhttp.Attachment) (peerrelay.Admission, error)

func (f relayAuthenticatorFunc) AuthenticateRelay(ctx context.Context, credential string, attachment peerrelayhttp.Attachment) (peerrelay.Admission, error) {
	return f(ctx, credential, attachment)
}

type relayUsageRecorder struct {
	mu     sync.Mutex
	values []peerrelay.Usage
	notify chan struct{}
}

func (r *relayUsageRecorder) RecordRelayUsage(_ context.Context, usage peerrelay.Usage) error {
	r.mu.Lock()
	r.values = append(r.values, usage)
	if r.notify != nil {
		close(r.notify)
		r.notify = nil
	}
	r.mu.Unlock()
	return nil
}

func (r *relayUsageRecorder) snapshot() []peerrelay.Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]peerrelay.Usage(nil), r.values...)
}

func (r *relayUsageRecorder) wait(t *testing.T) peerrelay.Usage {
	t.Helper()
	r.mu.Lock()
	if len(r.values) > 0 {
		value := r.values[0]
		r.mu.Unlock()
		return value
	}
	r.notify = make(chan struct{})
	notify := r.notify
	r.mu.Unlock()
	select {
	case <-notify:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay usage")
	}
	return r.snapshot()[0]
}

type relayHTTP3Leg struct {
	requestWriter *io.PipeWriter
	response      *http.Response
	cancel        context.CancelFunc
}

func openRelayHTTP3Leg(t *testing.T, client *http.Client, endpoint string, handle [16]byte, endpointID, role string) *relayHTTP3Leg {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	requestBody := io.MultiReader(bytes.NewReader([]byte{'P', 'B', 'R', 'Q', 1}), reader)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer relay.integration.token")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Paperboat-Relay-Carrier", "HTTP/3.0")
	request.Header.Set("X-Paperboat-Stream-Handle", base64.RawURLEncoding.EncodeToString(handle[:]))
	request.Header.Set("X-Paperboat-Endpoint-Id", endpointID)
	request.Header.Set("X-Paperboat-Relay-Role", role)
	response, err := client.Do(request)
	if err != nil {
		cancel()
		_ = writer.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 3 {
		cancel()
		_ = writer.Close()
		response.Body.Close()
		t.Fatalf("relay response status=%d proto=%s", response.StatusCode, response.Proto)
	}
	return &relayHTTP3Leg{requestWriter: writer, response: response, cancel: cancel}
}

func writeRelayLeg(t *testing.T, leg *relayHTTP3Leg, payload []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := leg.requestWriter.Write(payload)
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out writing relay HTTP/3 request body")
	}
}

func readRelayLeg(t *testing.T, leg *relayHTTP3Leg, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(leg.response.Body, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("relayed bytes=%q want=%q", got, want)
	}
}

func (l *relayHTTP3Leg) close(t *testing.T) {
	t.Helper()
	_ = l.requestWriter.Close()
	_ = l.response.Body.Close()
	l.cancel()
}

func newHTTP3TestServer(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	certificate := newTestCertificate(t)
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport}
	t.Cleanup(func() {
		_ = transport.Close()
		_ = server.Close()
		_ = packetConn.Close()
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("HTTP/3 server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})
	return client, "https://" + packetConn.LocalAddr().String() + "/v1/peer-relay"
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "paperboat-relay-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func relayTestBinding(expiresAt time.Time) peerrelay.Binding {
	var routeAllocation, streamHandle [16]byte
	copy(routeAllocation[:], bytes.Repeat([]byte{1}, len(routeAllocation)))
	copy(streamHandle[:], bytes.Repeat([]byte{2}, len(streamHandle)))
	return peerrelay.Binding{
		RouteAllocation: routeAllocation,
		StreamHandle:    streamHandle,
		EnvironmentID:   "environment_integration",
		RouteID:         "route_integration",
		RouteRevision:   7,
		IntentID:        "intent_integration",
		Attempt:         3,
		Network:         5,
		ExpiresAt:       expiresAt.UTC(),
		MaximumBytes:    1 << 20,
	}
}
