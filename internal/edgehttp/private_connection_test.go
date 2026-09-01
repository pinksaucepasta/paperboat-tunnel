package edgehttp

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestPrivateConnectionBindsExactRouteAndFencesStaleClose(t *testing.T) {
	now := time.Now().UTC()
	registry, _ := NewPrivateAccessConnectionRegistry(8)
	registry.now = func() time.Time { return now }
	request := edgePrivateAccessRequest(now)
	request.RouteID = "route_a"
	request.ResourceID = "preview_a"
	request.RouteGeneration = 7
	request.AssignmentGeneration = 9
	token, err := registry.Register("127.0.0.1:41001", request, request.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ruleA := route.RouteMatch{Host: request.Host, Rule: route.RouteRule{ID: "route_a", Revision: 7, ResourceKind: request.ResourceKind, SessionGeneration: request.SessionGeneration, AssignmentGeneration: 9, AccountID: request.AccountID, HostID: "connector_host_other_device", TunnelID: "preview_a", ConnectorID: request.ConnectorID, ConnectorSessionID: request.CarrierSessionID, ConnectorProcessGeneration: request.ProcessGeneration, ConfigGeneration: request.ConfigGeneration, Node: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch}}
	if status, ok := registry.Authorize("127.0.0.1:41001", ruleA); !ok || status != 200 {
		t.Fatalf("route A status=%d ok=%v", status, ok)
	}
	ruleB := ruleA
	ruleB.Rule.ID = "route_b"
	if status, ok := registry.Authorize("127.0.0.1:41001", ruleB); ok || status != 403 {
		t.Fatalf("route B status=%d ok=%v", status, ok)
	}
	newToken, err := registry.Register("127.0.0.1:41001", request, request.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	registry.Remove("127.0.0.1:41001", token)
	if status, ok := registry.Authorize("127.0.0.1:41001", ruleA); !ok || status != 200 {
		t.Fatalf("stale close removed replacement status=%d", status)
	}
	registry.Remove("127.0.0.1:41001", newToken)
	if status, ok := registry.Authorize("127.0.0.1:41001", ruleA); ok || status != 401 {
		t.Fatalf("removed status=%d", status)
	}
}

func TestPrivateConnectionDomainAliasesKeepAuthoritativeRouteBinding(t *testing.T) {
	now := time.Now().UTC()
	for _, host := range []string{"app.customer.example", "one.apps.customer.example"} {
		t.Run(host, func(t *testing.T) {
			registry, _ := NewPrivateAccessConnectionRegistry(8)
			registry.now = func() time.Time { return now }
			request := edgePrivateAccessRequest(now)
			request.Host = host
			request.RouteID = "route_a"
			request.RouteGeneration = 7
			request.AssignmentGeneration = 9
			if _, err := registry.Register("127.0.0.1:41001", request, request.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			match := route.RouteMatch{Host: host, Rule: route.RouteRule{
				ID: "route_a@domain_a", Revision: 12, RouteID: "route_a", RouteGeneration: 7,
				ResourceKind: request.ResourceKind, SessionGeneration: request.SessionGeneration,
				AssignmentGeneration: 9, AccountID: request.AccountID, HostID: "connector_host_other_device",
				TunnelID: request.ResourceID, ConnectorID: request.ConnectorID,
				ConnectorSessionID: request.CarrierSessionID, ConnectorProcessGeneration: request.ProcessGeneration,
				ConfigGeneration: request.ConfigGeneration, Node: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch,
			}}
			if status, ok := registry.Authorize("127.0.0.1:41001", match); !ok || status != 200 {
				t.Fatalf("status=%d ok=%v", status, ok)
			}
			match.Rule.RouteGeneration = 12
			if status, ok := registry.Authorize("127.0.0.1:41001", match); ok || status != 403 {
				t.Fatalf("domain generation replaced route generation: status=%d ok=%v", status, ok)
			}
		})
	}
}
