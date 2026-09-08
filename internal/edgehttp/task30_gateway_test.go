package edgehttp

import (
	"context"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"testing"
	"time"
)

func task24RouteGateway(t *testing.T, ctx context.Context, server *datacarrier.Server, httpDecision connectorprotocol.IngressDecision, refreshFixture ...bool) (*Policy, *DataCarrierRouteRegistry) {
	rule := replicaRule()
	rule.ID = "route_http"
	rule.RouteID = "route_http"
	rule.RouteGeneration = 1
	rule.AssignmentID = "assignment_task24"
	rule.AssignmentGeneration = 1
	rule.Generation = 1
	rule.Revision = 1
	rule.Hostname = httpDecision.Binding.Hostname
	rule.MatchType = route.MatchExact
	rule.PathPrefix = "/"
	rule.Target = rule.RouteID
	rule.Protocol = "http"
	rule.OriginScheme = "http"
	rule.AccessMode = "public"
	rule.DesiredState = "active"
	rule.ObservedState = "ready"
	rule.Node = httpDecision.EdgeNodeID
	rule.EdgeProcessEpoch = httpDecision.EdgeProcessEpoch
	rule.ConfigContentHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2, Usage: task24Usage{}, IngressAuthority: func(_ context.Context, current route.RouteRule) (connectorprotocol.IngressDecision, error) {
		if current.RouteID == rule.RouteID {
			d := httpDecision
			if len(refreshFixture) > 0 && refreshFixture[0] {
				d.IssuedAt = time.Now().UTC()
				d.ExpiresAt = d.IssuedAt.Add(10 * time.Second)
			}
			return d, nil
		}
		return connectorprotocol.IngressDecision{}, connectorprotocol.ErrIngressDenied
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { registry.Close() })
	state := replicaState(rule, 3, rule.AssignmentID, "task24-edge", time.Millisecond, 4)
	state.RouteIDs = []string{"route_http", "route_tcp"}
	state.HealthyRoutes = []string{"route_http", "route_tcp"}
	state.RouteBindings = []ReplicaRouteBinding{{RouteID: "route_http", AssignmentID: rule.AssignmentID, AssignmentGeneration: 1, RouteGeneration: 1, ConfigContentHash: rule.ConfigContentHash}, {RouteID: "route_tcp", AssignmentID: rule.AssignmentID, AssignmentGeneration: 1, RouteGeneration: 1, ConfigContentHash: rule.ConfigContentHash}}
	if err := registry.AttachReplica(server, "task24-key", "task24-thumb", state); err != nil {
		t.Fatal(err)
	}
	transport, err := NewDataCarrierRouteTransport(DataCarrierRouteTransportConfig{Registry: registry, StreamOpenTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	routes := route.NewRegistry("preview.example.test", "runtime.example.test")
	if err := routes.ApplyGeneration(ctx, 1, []route.RouteRule{rule}, func(context.Context, []route.RouteRule) error { return nil }, 0); err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGatewayWithTransports(Config{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: routes, RequestID: func() string { return "task24-request" }}, "127.0.0.1:1", nil, transport)
	if err != nil {
		t.Fatal(err)
	}

	return gateway, registry
}
