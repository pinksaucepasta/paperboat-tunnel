package edgehttp

import (
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestDurableReplicaSelectionEligibilityLatencyAndDeterministicTie(t *testing.T) {
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	rule := replicaRule()
	fastIdentity := replicaIdentity("host_fast", "connector_fast", "session_fast", 3)
	slowIdentity := replicaIdentity("host_slow", "connector_slow", "session_slow", 3)
	fast, fastClient := testEdgePreviewCarrierPair(t, fastIdentity)
	slow, slowClient := testEdgePreviewCarrierPair(t, slowIdentity)
	defer fast.Close()
	defer fastClient.Close()
	defer slow.Close()
	defer slowClient.Close()
	fastState := replicaState(rule, 3, "assignment_fast", "zone_a", 5*time.Millisecond, 10)
	slowState := replicaState(rule, 3, "assignment_slow", "zone_b", 20*time.Millisecond, 10)
	if err := registry.AttachReplica(fast, "key-fast", "thumb-fast", fastState); err != nil {
		t.Fatal(err)
	}
	if err := registry.AttachReplica(slow, "key-slow", "thumb-slow", slowState); err != nil {
		t.Fatal(err)
	}
	selected, err := registry.entryFor(rule, "request_same")
	if err != nil || selected.server != fast {
		t.Fatalf("selected=%v err=%v, want fast", selected, err)
	}

	fastState.HealthyRoutes = nil
	if err := registry.UpdateReplicaState(fast, fastState); err != nil {
		t.Fatal(err)
	}
	selected, err = registry.entryFor(rule, "request_same")
	if err != nil || selected.server != slow {
		t.Fatalf("selected=%v err=%v, want healthy slow", selected, err)
	}

	slowState.Ready = false
	if err := registry.UpdateReplicaState(slow, slowState); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.entryFor(rule, "request_same"); !errors.Is(err, ErrDataCarrierRouteUnavailable) {
		t.Fatalf("error=%v", err)
	}

	fastState.HealthyRoutes = []string{rule.ID}
	slowState.Ready = true
	fastState.Latency, slowState.Latency = 10*time.Millisecond, 10*time.Millisecond
	if err := registry.UpdateReplicaState(fast, fastState); err != nil {
		t.Fatal(err)
	}
	if err := registry.UpdateReplicaState(slow, slowState); err != nil {
		t.Fatal(err)
	}
	first, err := registry.entryFor(rule, "stable_request")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		next, nextErr := registry.entryFor(rule, "stable_request")
		if nextErr != nil || next != first {
			t.Fatalf("selection changed: first=%p next=%p err=%v", first, next, nextErr)
		}
	}
	if registry.Len() != 2 {
		t.Fatalf("registry length=%d; selection must not broadcast or detach peers", registry.Len())
	}
	for _, mutate := range []func(*route.RouteRule){
		func(value *route.RouteRule) { value.RouteGeneration++ },
		func(value *route.RouteRule) {
			value.ConfigContentHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		forged := rule
		mutate(&forged)
		if _, err := registry.entryFor(forged, "forged_request"); !errors.Is(err, ErrDataCarrierRouteUnavailable) {
			t.Fatalf("forged route tuple error=%v, want unavailable", err)
		}
	}
}

func TestDurableReplicaOldSessionCleanupCannotRemoveReplacement(t *testing.T) {
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	identity := replicaIdentity("host_one", "connector_one", "session_same", 4)
	oldServer, oldClient := testEdgePreviewCarrierPair(t, identity)
	newServer, newClient := testEdgePreviewCarrierPair(t, identity)
	defer oldClient.Close()
	defer newClient.Close()
	defer newServer.Close()
	rule := replicaRule()
	rule.ConfigGeneration = 4
	state := replicaState(rule, 4, "assignment_replacement", "zone_a", time.Millisecond, 4)
	if err := registry.AttachReplica(oldServer, "key", "thumb", state); err != nil {
		t.Fatal(err)
	}
	if err := registry.AttachReplica(newServer, "key", "thumb", state); err != nil {
		t.Fatal(err)
	}
	if err := oldServer.Close(); err != nil {
		t.Fatal(err)
	}
	selected, err := registry.entryFor(rule, "request_after_cleanup")
	if err != nil || selected.server != newServer || registry.Len() != 1 {
		t.Fatalf("selected=%v len=%d err=%v", selected, registry.Len(), err)
	}
	if err := registry.UpdateReplicaState(oldServer, state); !errors.Is(err, ErrDataCarrierRouteUnavailable) {
		t.Fatalf("stale update error=%v", err)
	}
}

func TestDurableReplicaExactAssignmentSelectsOnlyAuthorizedConnector(t *testing.T) {
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	rule := replicaRule()
	firstIdentity := replicaIdentity("host_first", "connector_first", "session_first", rule.ConfigGeneration)
	secondIdentity := replicaIdentity("host_second", "connector_second", "session_second", rule.ConfigGeneration)
	first, firstClient := testEdgePreviewCarrierPair(t, firstIdentity)
	second, secondClient := testEdgePreviewCarrierPair(t, secondIdentity)
	defer first.Close()
	defer firstClient.Close()
	defer second.Close()
	defer secondClient.Close()
	firstState := replicaState(rule, rule.ConfigGeneration, "assignment_first", "zone_a", time.Millisecond, 4)
	secondState := replicaState(rule, rule.ConfigGeneration, "assignment_second", "zone_b", 20*time.Millisecond, 4)
	if err := registry.AttachReplica(first, "key-first", "thumb-first", firstState); err != nil {
		t.Fatal(err)
	}
	if err := registry.AttachReplica(second, "key-second", "thumb-second", secondState); err != nil {
		t.Fatal(err)
	}

	exact := rule
	exact.HostID = secondIdentity.HostID
	exact.ConnectorID = secondIdentity.ConnectorID
	exact.ConnectorSessionID = secondIdentity.SessionID
	exact.ConnectorProcessGeneration = secondIdentity.ProcessGeneration
	exact.AssignmentID = "assignment_second"
	selected, err := registry.entryForExactAssignment(exact)
	if err != nil || selected.server != second {
		t.Fatalf("selected=%v err=%v, want exact second replica", selected, err)
	}
	for _, mutate := range []func(*route.RouteRule){
		func(value *route.RouteRule) { value.ConnectorID = firstIdentity.ConnectorID },
		func(value *route.RouteRule) { value.AssignmentID = "assignment_first" },
		func(value *route.RouteRule) { value.AssignmentGeneration++ },
		func(value *route.RouteRule) { value.RouteGeneration++ },
		func(value *route.RouteRule) {
			value.ConfigContentHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		forged := exact
		mutate(&forged)
		if _, err := registry.entryForExactAssignment(forged); !errors.Is(err, ErrDataCarrierRouteUnavailable) {
			t.Fatalf("forged exact assignment error=%v, want unavailable", err)
		}
	}
}

func replicaIdentity(host, connector, session string, generation uint64) datacarrier.Identity {
	return datacarrier.Identity{AccountID: "account_replica", HostID: host, TunnelID: "tunnel_replica", ConnectorID: connector, SessionID: session, ProcessGeneration: generation, Generation: generation}
}

func replicaRule() route.RouteRule {
	return route.RouteRule{ID: "route_replica", RouteID: "route_replica", RouteGeneration: 7, AssignmentID: "assignment_representative", AssignmentGeneration: 11, Kind: route.TunnelHTTPSWSS, Protocol: "http", AccountID: "account_replica", HostID: "host_pinned", TunnelID: "tunnel_replica", ConnectorID: "connector_pinned", ConnectorSessionID: "session_pinned", ConnectorProcessGeneration: 3, ConfigGeneration: 3, ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
}

func replicaState(rule route.RouteRule, generation uint64, assignmentID, failureDomain string, latency time.Duration, capacity uint32) ReplicaState {
	routeID := carrierRouteID(rule)
	return ReplicaState{Ready: true, Generation: generation, RouteIDs: []string{routeID}, HealthyRoutes: []string{routeID}, RouteBindings: []ReplicaRouteBinding{{RouteID: routeID, AssignmentID: assignmentID, AssignmentGeneration: rule.AssignmentGeneration, RouteGeneration: rule.RouteGeneration, ConfigContentHash: rule.ConfigContentHash}}, FailureDomain: failureDomain, Latency: latency, Capacity: capacity}
}
