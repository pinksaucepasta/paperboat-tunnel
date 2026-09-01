package edgehttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type durablePolicyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f durablePolicyRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGatewayDispatchesDurableRouteToCanonicalCarrier(t *testing.T) {
	routes := route.NewRegistry("preview.example.test", "runtime.example.test")
	rule := route.RouteRule{
		ID:                         "route_durable_01",
		Revision:                   1,
		Kind:                       route.TunnelHTTPSWSS,
		MatchType:                  route.MatchExact,
		Hostname:                   "service.customer.test",
		PathPrefix:                 "/",
		Target:                     "route_durable_01",
		Protocol:                   "http",
		OriginScheme:               "http",
		AccessMode:                 "public",
		AccountID:                  "account_01",
		HostID:                     "host_01",
		TunnelID:                   "tunnel_01",
		ConnectorID:                "connector_01",
		ConnectorSessionID:         "session_01",
		ConnectorProcessGeneration: 2,
		ConfigGeneration:           3,
		ConfigContentHash:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Node:                       "edge_01",
		EdgeProcessEpoch:           "epoch_0001",
		EdgeFailureDomain:          "region_01",
		AssignmentID:               "assignment_01",
		AssignmentGeneration:       1,
		ObservedState:              "ready",
	}
	if err := routes.ApplyGeneration(context.Background(), 1, []route.RouteRule{rule}, func(context.Context, []route.RouteRule) error { return nil }, 0); err != nil {
		t.Fatal(err)
	}

	var canonicalCalls int
	canonical := durablePolicyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		canonicalCalls++
		match, ok := RouteMatchFromContext(request.Context())
		if !ok || match.Rule.Kind != route.TunnelHTTPSWSS || match.Rule.ID != rule.ID {
			return nil, errors.New("canonical route match was not preserved")
		}
		if request.URL.Host == rule.Target || request.URL.Scheme == rule.Target {
			return nil, errors.New("opaque durable route target leaked into URL")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("from-carrier")), Request: request}, nil
	})
	var previewCalls, legacyCalls int
	preview := durablePolicyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		previewCalls++
		return nil, errors.New("preview transport must not receive durable route")
	})
	legacy := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { legacyCalls++ })
	config := Config{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: routes}
	policy, err := NewGatewayWithTransports(config, "127.0.0.1:1", preview, canonical)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the proxy's private legacy target with a sentinel by using a
	// second policy. A canonical match must never reach this handler regardless
	// of the retained legacy upstream configuration.
	_ = legacy
	request := httptest.NewRequest(http.MethodGet, "https://service.customer.test/normal", nil)
	request.Host = "service.customer.test"
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "from-carrier" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if canonicalCalls != 1 || previewCalls != 0 || legacyCalls != 0 {
		t.Fatalf("canonical=%d preview=%d legacy=%d", canonicalCalls, previewCalls, legacyCalls)
	}
}

func TestConfiguredRoutesRejectUnownedManagedHostBeforeLegacyFallback(t *testing.T) {
	routes := route.NewRegistry("preview.example.test", "runtime.example.test")
	rule := route.RouteRule{ID: "route_owned_01", Revision: 1, Kind: route.TunnelHTTPSWSS, MatchType: route.MatchExact, Hostname: "owned.customer.test", PathPrefix: "/", Target: "route_owned_01", Protocol: "http", AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", ConnectorSessionID: "session_01", ConnectorProcessGeneration: 1, ConfigGeneration: 1, ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Node: "edge_01", EdgeProcessEpoch: "epoch_0001", EdgeFailureDomain: "region_01", AssignmentID: "assignment_01", AssignmentGeneration: 1, ObservedState: "ready"}
	if err := routes.ApplyGeneration(context.Background(), 1, []route.RouteRule{rule}, func(context.Context, []route.RouteRule) error { return nil }, 0); err != nil {
		t.Fatal(err)
	}
	var nextCalls int
	policy, err := New(Config{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: routes}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://unowned.customer.test/", nil)
	request.Host = "unowned.customer.test"
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound || nextCalls != 0 {
		t.Fatalf("status=%d next_calls=%d", recorder.Code, nextCalls)
	}
}
