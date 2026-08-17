package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func TestEventAndErrorCannotLeakApplicationContent(t *testing.T) {
	event := Event{At: time.Unix(100, 0), Kind: Admission, Result: Rejected, RejectionCode: "credential_replayed", ConnectorGeneration: 3}
	encoded, err := event.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorization", "cookie", "token", "body", "query", "public_host", "target"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("event contains %q: %s", forbidden, encoded)
		}
	}
	secret := errors.New("Authorization: Bearer secret-token body=private")
	safe := Error(edgeerrors.Wrap(edgeerrors.CodeCredentialInvalid, "credential failed", "request a fresh admission", secret))
	if strings.Contains(safe.Code+safe.Recovery, "secret") || safe.Code != "credential_invalid" {
		t.Fatalf("safe error = %+v", safe)
	}
	if got := Error(secret); got.Code != "internal_error" || strings.Contains(got.Recovery, secret.Error()) {
		t.Fatalf("unknown error = %+v", got)
	}
}

func TestPrivateHandlerReportsBoundedDiagnosticsAndMetrics(t *testing.T) {
	state := node.New("edge_test")
	if !state.MarkReady() {
		t.Fatal("mark ready")
	}
	manager, _ := node.NewManager(state, 8)
	queue, _ := usage.NewQueue(4, 4096)
	now := time.Unix(200, 0).UTC()
	if err := queue.Enqueue(usage.Report{OperationID: "op", Interval: [2]time.Time{now.Add(-10 * time.Second), now}, Payload: []byte("signed-private-payload")}); err != nil {
		t.Fatal(err)
	}
	controlErr := errors.New("Authorization: Bearer secret")
	var certificateErr error
	sessionRoutes := 2
	handler, err := NewHandler(Sources{Node: state.Snapshot, Manager: manager.Snapshot, Sessions: func() int { return 1 }, SessionRoutes: func() int { return sessionRoutes }, ActiveStreams: func() uint32 { return 3 }, RouteCount: func() int { return 2 }, Usage: queue.Stats, ControlErr: func() error { return controlErr }, RouteErr: func() error { return nil }, UsageErr: func() error { return nil }, FRPRunning: func() bool { return true }, CaddyRunning: func() bool { return true }, STUN: func() STUNStats { return STUNStats{Running: true, Accepted: 7, Rejected: 2, Errors: 1} }, Signaling: func() SignalingStats { return SignalingStats{Running: true, Sessions: 2, Attachments: 3, Capacity: 16} }, CaddyTLS: func() (time.Time, error) { return now.Add(time.Hour), certificateErr }, Events: NewMetrics().Snapshot, Traffic: usage.NewCounters().Snapshot, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || strings.Contains(ready.Body.String(), "secret") || strings.Contains(ready.Body.String(), "signed-private-payload") {
		t.Fatalf("ready response = %d %s", ready.Code, ready.Body.String())
	}
	if !strings.Contains(ready.Body.String(), `"control_unavailable"`) || !strings.Contains(ready.Body.String(), `"usage_pending_reports":1`) {
		t.Fatalf("diagnostics = %s", ready.Body.String())
	}
	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{"paperboat_tunnel_ready 0", "paperboat_tunnel_attached_routes 2", "paperboat_tunnel_usage_pending_reports 1", "paperboat_tunnel_stun_requests_total 7", "paperboat_tunnel_stun_rejected_total 2", "paperboat_tunnel_stun_errors_total 1", "paperboat_tunnel_signaling_sessions 2", "paperboat_tunnel_signaling_attachments 3", "paperboat_tunnel_signaling_capacity 16", `dependency="control"} 0`, `dependency="stun"} 1`, `dependency="signaling"} 1`} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("metrics missing %q: %s", expected, metrics.Body.String())
		}
	}
	controlErr = nil
	certificateErr = errors.New("certificate private detail")
	certificate := httptest.NewRecorder()
	handler.ServeHTTP(certificate, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if certificate.Code != http.StatusServiceUnavailable || !strings.Contains(certificate.Body.String(), "certificate_unavailable") || strings.Contains(certificate.Body.String(), "private detail") {
		t.Fatalf("certificate diagnostics = %d %s", certificate.Code, certificate.Body.String())
	}
	certificateErr = nil
	sessionRoutes = 0
	drift := httptest.NewRecorder()
	handler.ServeHTTP(drift, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if drift.Code != http.StatusServiceUnavailable || !strings.Contains(drift.Body.String(), `"route_drift":true`) || !strings.Contains(drift.Body.String(), `"route_drift"`) {
		t.Fatalf("route drift diagnostics = %d %s", drift.Code, drift.Body.String())
	}
}

func TestMetricsRejectUnboundedDimensions(t *testing.T) {
	metrics := NewMetrics()
	valid := MetricKey{Kind: Stream, Result: Success, RouteKind: "preview_public_https_wss", Direction: "egress"}
	if !metrics.Add(valid, 10) || metrics.Get(valid) != 10 {
		t.Fatal("valid metric rejected")
	}
	for _, invalid := range []MetricKey{{Kind: "credential-secret", Result: Success}, {Kind: Stream, Result: "user-input"}, {Kind: Stream, Result: Success, RouteKind: "route-id-123"}, {Kind: Usage, Result: Success, Direction: "host.example"}} {
		if metrics.Add(invalid, 1) {
			t.Fatalf("unbounded metric accepted: %+v", invalid)
		}
	}
}

func TestDiagnosticsDistinguishDependencies(t *testing.T) {
	healthy := Diagnostics{Control: Healthy, Store: Healthy, FRP: Healthy, Caddy: Healthy, STUN: Healthy, Signaling: Healthy, Usage: Healthy}
	if !healthy.Ready() {
		t.Fatal("healthy node is not ready")
	}
	healthy.Control = Degraded
	if healthy.Ready() {
		t.Fatal("control degradation remained ready")
	}
	healthy.Control, healthy.Usage = Healthy, Degraded
	if !healthy.Ready() {
		t.Fatal("bounded usage delivery degradation should remain ready")
	}
	healthy.Usage = Unavailable
	if healthy.Ready() {
		t.Fatal("undurable usage remained ready")
	}
}
