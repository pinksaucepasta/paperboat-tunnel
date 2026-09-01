package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	edgetelemetry "github.com/pinksaucepasta/paperboat-tunnel/internal/telemetry"
)

func TestCaddyProbeHostUsesRelayHostWithoutPublicRoutes(t *testing.T) {
	deployment := config.Deployment{SignalingHost: "mumbai.relay.example.test"}
	if got := caddyProbeHost(deployment); got != deployment.SignalingHost {
		t.Fatalf("probe host = %q, want %q", got, deployment.SignalingHost)
	}
	deployment.PublicRoutes = []config.PublicRoute{{Host: "api.example.test"}}
	if got := caddyProbeHost(deployment); got != deployment.SignalingHost {
		t.Fatalf("probe host = %q, want infrastructure signaling host", got)
	}
}

func TestCarrierEndpointFromDeploymentIsSeparateAndComplete(t *testing.T) {
	deployment := config.Deployment{ConnectorAdvertiseHost: "edge.example.test", CarrierTCPListenAddress: "0.0.0.0:27443", CarrierQUICListenAddress: "0.0.0.0:27444"}
	endpoint, err := carrierEndpointFromDeployment(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint == nil || endpoint.Host != "edge.example.test" || endpoint.TCPPort != 27443 || endpoint.QUICPort != 27444 {
		t.Fatalf("carrier endpoint = %+v", endpoint)
	}
	if _, err := carrierEndpointFromDeployment(config.Deployment{ConnectorAdvertiseHost: "edge.example.test", CarrierTCPListenAddress: "0.0.0.0:27443"}); err == nil {
		t.Fatal("incomplete carrier endpoint accepted")
	}
	if endpoint, err := carrierEndpointFromDeployment(config.Deployment{}); err == nil || endpoint != nil {
		t.Fatalf("empty carrier endpoint = %+v, %v", endpoint, err)
	}
}

func TestPeerServiceDispatchUsesExactNormalizedHostAndPath(t *testing.T) {
	signaling := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusSwitchingProtocols)
	})
	relay := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	})
	gateway := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := peerServiceDispatch("signal.example.test", signaling, relay, gateway)

	for _, test := range []struct {
		host   string
		method string
		path   string
		want   int
	}{
		{host: "signal.example.test", method: http.MethodGet, path: "/network-check/v1", want: http.StatusNoContent},
		{host: "signal.example.test", method: http.MethodPost, path: "/network-check/v1", want: http.StatusNotFound},
		{host: "signal.example.test", method: http.MethodGet, path: "/v1/peer-signaling", want: http.StatusSwitchingProtocols},
		{host: "SIGNAL.EXAMPLE.TEST:443", method: http.MethodGet, path: "/v1/peer-relay", want: http.StatusAccepted},
		{host: "signal.example.test", method: http.MethodPost, path: "/v1/public-preview-relay", want: http.StatusNotFound},
		{host: "signal.example.test", method: http.MethodGet, path: "/v1/unknown", want: http.StatusNotFound},
		{host: "preview.example.test", method: http.MethodGet, path: "/v1/peer-signaling", want: http.StatusNoContent},
		{host: "signal.example.test.attacker.test", method: http.MethodGet, path: "/v1/peer-relay", want: http.StatusNoContent},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, "http://private"+test.path, nil)
		request.Host = test.host
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Errorf("host %q: status = %d, want %d", test.host, recorder.Code, test.want)
		}
		if test.path == "/network-check/v1" && test.method == http.MethodGet && (recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("network check body=%q cache=%q", recorder.Body.String(), recorder.Header().Get("Cache-Control"))
		}
	}
}

func TestProbeCaddyTLSVerifiesIdentityAndValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name            string
		certificateHost string
		probeHost       string
		notBefore       time.Time
		notAfter        time.Time
		wantError       bool
	}{
		{name: "valid", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour)},
		{name: "wrong host", certificateHost: "other.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), wantError: true},
		{name: "expired", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Hour), notAfter: now.Add(-time.Minute), wantError: true},
		{name: "not yet valid", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(time.Minute), notAfter: now.Add(time.Hour), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := serveTLS(t, test.certificateHost, test.notBefore, test.notAfter)
			expiresAt, err := probeCaddyTLS(address, test.probeHost)
			if (err != nil) != test.wantError {
				t.Fatalf("expiry=%s error=%v", expiresAt, err)
			}
			if !expiresAt.Equal(test.notAfter) {
				t.Fatalf("expiry=%s want=%s", expiresAt, test.notAfter)
			}
		})
	}
}

func TestLiveCarrierHTTPCompositionPreservesStreamingAndSharesTelemetry(t *testing.T) {
	metrics := edgetelemetry.NewMetrics()
	events, err := edgetelemetry.NewEventLogWithQueue(64, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	carrierTelemetry, err := datacarrier.NewCarrierTelemetry(datacarrier.CarrierTelemetryConfig{
		Metrics: metrics,
		Events:  events,
		Info: datacarrier.StreamInfo{
			IDs:           edgetelemetry.SafeIDs{EdgeNodeID: "edge_1"},
			CorrelationID: "corr_edge_carrier",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestTelemetry, err := edgehttp.NewRequestTelemetry(edgehttp.RequestTelemetryConfig{Metrics: metrics, Events: events, Info: edgehttp.RequestInfo{IDs: edgetelemetry.SafeIDs{EdgeNodeID: "edge_1"}, RouteKind: "tunnel_https_wss"}})
	if err != nil {
		t.Fatal(err)
	}
	gatewayTelemetry, err := edgehttp.NewRequestTelemetry(edgehttp.RequestTelemetryConfig{Metrics: metrics, Events: events, Info: edgehttp.RequestInfo{IDs: edgetelemetry.SafeIDs{EdgeNodeID: "edge_1"}}})
	if err != nil {
		t.Fatal(err)
	}
	gateway := gatewayTelemetry.Handler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	gatewayRecorder := httptest.NewRecorder()
	gateway.ServeHTTP(gatewayRecorder, httptest.NewRequest(http.MethodGet, "https://gateway.example.test/health", nil))
	if gatewayRecorder.Code != http.StatusNoContent {
		t.Fatalf("gateway status = %d", gatewayRecorder.Code)
	}
	transport := requestTelemetry.RoundTripper(&carrierTelemetryRoundTripper{
		Next: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("streamed response")), Request: request}, nil
		}),
		Telemetry: carrierTelemetry,
		RouteKind: "tunnel_https_wss",
		NodeID:    "edge_1",
	})
	request := httptest.NewRequest(http.MethodGet, "https://tunnel.example.test/stream", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "streamed response" {
		t.Fatalf("response body = %q", payload)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := requestMetricValue(metrics.Snapshot(), edgetelemetry.MetricActiveStreams); got != 0 {
		t.Fatalf("active carrier streams = %d", got)
	}
	if got := requestMetricValue(metrics.Snapshot(), edgetelemetry.MetricTrafficBytes, "ingress"); got != uint64(len("streamed response")) {
		t.Fatalf("carrier response bytes = %d", got)
	}
	if got := requestMetricValue(metrics.Snapshot(), edgetelemetry.MetricRouteRequests, "tunnel_https_wss", "success"); got != 1 {
		t.Fatalf("tunnel route request successes = %d", got)
	}
	if got := requestMetricValue(metrics.Snapshot(), edgetelemetry.MetricEdgeRequests, "https", "success"); got != 1 {
		t.Fatalf("gateway edge request successes = %d", got)
	}
	var opened, closed int
	for _, event := range events.Snapshot() {
		switch event.Name {
		case "carrier_stream_opened":
			opened++
		case "carrier_stream_closed":
			closed++
		}
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("carrier stream lifecycle opened=%d closed=%d", opened, closed)
	}
}

func TestTelemetryLifecycleReportsStartupReadinessAndShutdown(t *testing.T) {
	health, err := edgetelemetry.NewHealthTracker(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	metrics := edgetelemetry.NewMetrics()
	events, err := edgetelemetry.NewEventLogWithQueue(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := newTelemetryLifecycle(health, metrics, events)
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := health.Snapshot().Dimensions.Service; state.Status != edgetelemetry.StatusDegraded || state.Code != "service_starting" {
		t.Fatalf("starting health = %+v", state)
	}
	if err := lifecycle.MarkReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := health.Snapshot().Dimensions.Service; state.Status != edgetelemetry.StatusReady || state.Code != "service_ready" {
		t.Fatalf("ready health = %+v", state)
	}
	if err := lifecycle.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := health.Snapshot().Dimensions.Service; state.Status != edgetelemetry.StatusDown || state.Code != "service_shutdown" {
		t.Fatalf("shutdown health = %+v", state)
	}
	var names []string
	for _, event := range events.Snapshot() {
		names = append(names, event.Name)
	}
	if len(names) != 3 || names[0] != "edge_service_starting" || names[1] != "edge_service_ready" || names[2] != "edge_service_shutdown" {
		t.Fatalf("lifecycle events = %v", names)
	}
	if _, accepted, err := events.TryRecord(edgetelemetry.EventInput{At: time.Now(), Severity: edgetelemetry.SeverityInfo, Component: edgetelemetry.DimensionService, Name: "after_close", Code: "after_close", Outcome: edgetelemetry.OutcomeStateChange, Message: "ignored", CorrelationID: "corr_after_close", Retry: edgetelemetry.RetryNone}); err != nil || accepted {
		t.Fatalf("event after close accepted=%v err=%v", accepted, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func requestMetricValue(samples []edgetelemetry.MetricSample, name string, labels ...string) uint64 {
	for _, sample := range samples {
		if sample.Name != name || len(sample.Labels) != len(labels) {
			continue
		}
		match := true
		for index, value := range labels {
			if sample.Labels[index].Value != value {
				match = false
				break
			}
		}
		if match {
			return sample.Value
		}
	}
	return 0
}

func serveTLS(t *testing.T, host string, notBefore, notAfter time.Time) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	t.Cleanup(func() { _ = tlsListener.Close() })
	go func() {
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
			}()
		}
	}()
	return listener.Addr().String()
}
