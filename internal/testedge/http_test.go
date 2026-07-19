package testedge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestHTTPHandlerMatchesControlClient(t *testing.T) {
	const credential = "fake-edge-control-credential-01234567890123456789"
	fake := New()
	fake.SetAssignment("env", "helper", admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge"})
	if err := fake.SetRoute(control.RouteAssignment{RouteID: "route", Revision: 2, Environment: "env", Generation: 3, NodeID: "edge", Kind: "helper_https_wss", PublicHost: "app.example.test", TargetHost: "127.0.0.1", TargetPort: 8080}); err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: handlerTransport{handler: Handler{Fake: fake, Credential: credential}}}
	client, err := control.NewHTTPClient(control.HTTPConfig{BaseURL: "https://fake-control.test", Credential: credential, Timeout: time.Second, Client: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	current, err := client.Current(ctx, "env", "helper")
	if err != nil || current.Generation != 3 {
		t.Fatalf("current = %+v, %v", current, err)
	}
	if err := client.RegisterNode(ctx, control.NodeRegistration{NodeID: "edge", ProcessEpoch: "process", Capacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(ctx, control.NodeObservation{NodeID: "edge", Ready: true, At: time.Unix(10, 0)}); err != nil {
		t.Fatal(err)
	}
	routes, err := client.DesiredRoutes(ctx, "edge")
	if err != nil || len(routes) != 1 || routes[0].TargetPort != 8080 {
		t.Fatalf("routes = %+v, %v", routes, err)
	}
	result, err := client.ReportUsage(ctx, control.UsageReport{OperationID: "op_usage_01", Key: usage.Key{Node: "edge", Epoch: "epoch_01", Environment: "env", Route: "route", Revision: 2, Direction: "egress"}, Bytes: 100, Interval: [2]time.Time{time.Unix(1, 0), time.Unix(2, 0)}})
	if err != nil || result.Delta != 100 {
		t.Fatalf("usage = %+v, %v", result, err)
	}
}
