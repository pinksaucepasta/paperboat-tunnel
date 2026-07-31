package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

const testControlCredential = "edge-control-test-012345678901234567890123456789"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func controlClient(t *testing.T, roundTrip roundTripFunc) *HTTPClient {
	t.Helper()
	client, err := NewHTTPClient(HTTPConfig{BaseURL: "https://control.test", Credential: testControlCredential, Timeout: time.Second, Client: &http.Client{Transport: roundTrip}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func usageKey() usage.Key {
	return usage.Key{Node: "edge", Epoch: "epoch", Environment: "env", Route: "route", Revision: 1, Direction: "egress"}
}

func TestHTTPClientTypedOperationsAndAuthentication(t *testing.T) {
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+testControlCredential {
			t.Errorf("unsafe auth request: %s %v", r.URL.String(), r.Header)
			return response(http.StatusUnauthorized, ""), nil
		}
		switch r.URL.Path {
		case "/v1/edge/assignments/current":
			data, _ := json.Marshal(map[string]any{"connector_generation": 3, "edge_pool": "default", "edge_node_id": "edge_1", "revoked": false})
			return response(http.StatusOK, string(data)), nil
		case "/v1/edge/usage-reports":
			var wire map[string]any
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || wire["edge_node_id"] != "edge" || wire["route_id"] != "route" || wire["counter_epoch"] != "epoch" {
				t.Errorf("usage wire = %#v", wire)
			}
			data, _ := json.Marshal(UsageResult{Delta: 10})
			return response(http.StatusOK, string(data)), nil
		case "/v1/nodes/register", "/v1/nodes/heartbeat":
			return response(http.StatusNoContent, ""), nil
		case "/v1/edge/routes/desired-state":
			return response(http.StatusOK, `{"routes":[{"route_id":"route","route_revision":2,"environment_id":"env","connector_generation":3,"edge_node_id":"edge","kind":"runtime_https_wss","public_host":"app.example.test","target":{"host":"127.0.0.1","port":8080}}]}`), nil
		case "/v1/edge/routes/observations":
			return response(http.StatusNoContent, ""), nil
		case "/v1/trust/revocations":
			if r.Method != http.MethodGet {
				t.Errorf("revocation method = %s", r.Method)
			}
			return response(http.StatusOK, `{"jtis":["jti_revoked"],"environments":[],"helper_generations":[],"key_ids":[]}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})
	current, err := client.Current(context.Background(), "env", "machine", "runtime")
	if err != nil || current.Generation != 3 || current.EdgeNode != "edge_1" {
		t.Fatalf("current = %+v, %v", current, err)
	}
	result, err := client.ReportUsage(context.Background(), UsageReport{OperationID: "op", Key: usageKey(), Interval: [2]time.Time{time.Unix(1, 0), time.Unix(2, 0)}})
	if err != nil || result.Delta != 10 {
		t.Fatalf("usage = %+v, %v", result, err)
	}
	if err := client.RegisterNode(context.Background(), NodeRegistration{NodeID: "edge"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(context.Background(), NodeObservation{NodeID: "edge"}); err != nil {
		t.Fatal(err)
	}
	routes, err := client.DesiredRoutes(context.Background(), "edge")
	if err != nil || len(routes) != 1 || routes[0].Revision != 2 {
		t.Fatalf("routes = %+v, %v", routes, err)
	}
	revocations, err := client.Revocations(context.Background())
	if err != nil || !strings.Contains(string(revocations), "jti_revoked") {
		t.Fatalf("revocations = %s, %v", revocations, err)
	}
	if err := client.ObserveRoutes(context.Background(), "edge", []RouteObservation{{RouteID: "route", RouteRevision: 2, EdgeNodeID: "edge", ConnectorGeneration: 3}}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientRejectsPlaintextRedirectMalformedAndOversized(t *testing.T) {
	if _, err := NewHTTPClient(HTTPConfig{BaseURL: "http://control.test", Credential: testControlCredential, Timeout: time.Second}); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("plaintext = %v", err)
	}
	client := controlClient(t, func(*http.Request) (*http.Response, error) {
		result := response(http.StatusTemporaryRedirect, "")
		result.Header.Set("Location", "https://other.test/")
		return result, nil
	})
	if _, err := client.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("redirect = %v", err)
	}
	malformed := controlClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"connector_generation":3,"unknown":true}`), nil
	})
	if _, err := malformed.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("malformed = %v", err)
	}
	oversized := controlClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.Repeat("x", maxControlDocument+1)), nil
	})
	if _, err := oversized.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("oversized = %v", err)
	}
	if _, err := oversized.Revocations(context.Background()); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("oversized revocations = %v", err)
	}
}
