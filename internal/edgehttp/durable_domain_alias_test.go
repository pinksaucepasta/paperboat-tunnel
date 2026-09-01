package edgehttp

import (
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestCarrierRouteIDUsesOpaqueTargetForDomainAlias(t *testing.T) {
	alias := route.RouteRule{ID: "route_1@domain_1", Revision: 8, RouteID: "route_1", RouteGeneration: 3, Target: "route_1"}
	if got := carrierRouteID(alias); got != "route_1" {
		t.Fatalf("carrier route = %q", got)
	}
	if got := carrierRouteID(route.RouteRule{ID: "route_1"}); got != "route_1" {
		t.Fatalf("base carrier route = %q", got)
	}
}

func TestPrivateDomainAliasAuthorizesOriginalRouteGeneration(t *testing.T) {
	rule := route.RouteRule{ID: "route_1@domain_1", Revision: 8, RouteID: "route_1", RouteGeneration: 3}
	if carrierRouteID(rule) != "route_1" || rule.RouteGeneration != 3 {
		t.Fatalf("alias replaced route identity: %+v", rule)
	}
}
