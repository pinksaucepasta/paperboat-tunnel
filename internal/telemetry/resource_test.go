package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProjectHealthResourceMatchesCanonicalWireAndCopies(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 5, 6, 0, time.UTC)
	tracker, err := NewHealthTracker(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(HealthUpdate{Dimension: DimensionOrigin, Status: StatusDegraded, Code: "origin_connection_refused", Summary: "Origin refused connection.", RepairAction: "Start the origin.", CorrelationID: "cor_01", Retry: RetryScheduled, NextRetryAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	resource, err := ProjectHealthResource(tracker.Snapshot(), HealthResourceBinding{ResourceKind: "tunnel", ResourceID: "tun_01", CorrelationID: "cor_01"})
	if err != nil {
		t.Fatal(err)
	}
	if resource.Schema != ResourceSchemaV1 || resource.Kind != "health" || resource.OverallCode != "origin_connection_refused" || !resource.Retrying || resource.NextRetryAt == nil || resource.Dimensions.Origin.Status != StatusDegraded {
		t.Fatalf("resource = %+v", resource)
	}
	*resource.NextRetryAt = time.Time{}
	second, err := ProjectHealthResource(tracker.Snapshot(), HealthResourceBinding{ResourceKind: "tunnel", ResourceID: "tun_01", CorrelationID: "cor_01"})
	if err != nil || second.NextRetryAt == nil || second.NextRetryAt.IsZero() {
		t.Fatalf("projection retained caller mutation: %+v err=%v", second, err)
	}
	body, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"schema":"paperboat.preview-tunnel/v1"`, `"kind":"health"`, `"resource_kind":"tunnel"`, `"resource_id":"tun_01"`, `"retrying":true`} {
		if !strings.Contains(string(body), required) {
			t.Fatalf("canonical health missing %q: %s", required, body)
		}
	}
}

func TestProjectHealthResourceRejectsRelabeledCorrelation(t *testing.T) {
	tracker, _ := NewHealthTracker(time.Now)
	if err := tracker.Update(HealthUpdate{Dimension: DimensionRoute, Status: StatusDown, Code: "route_down", Summary: "Route is down.", RepairAction: "Repair the route.", CorrelationID: "cor_original", Retry: RetryWaitForChange}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectHealthResource(tracker.Snapshot(), HealthResourceBinding{ResourceKind: "tunnel", ResourceID: "tun_01", CorrelationID: "cor_relabel"}); err == nil {
		t.Fatal("correlation relabel accepted")
	}
}

func TestProjectEventResourceRequiresDurableEnvelopeAndSafeMetadata(t *testing.T) {
	event, err := NewEvent(EventInput{
		At: time.Date(2026, 8, 31, 4, 5, 6, 0, time.UTC), Severity: SeverityInfo, Component: DimensionRoute,
		Name: "route_activated", Code: "ready", Outcome: OutcomeStateChange, Message: "Route activated.", CorrelationID: "cor_01",
		IDs:         SafeIDs{TunnelID: "tunnel_01", RouteID: "route_01", ConnectorID: "connector_01"},
		Generations: Generations{Config: 2, Route: 3, Assignment: 4}, Retry: RetryNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := ProjectEventResource(event, EventResourceBinding{ID: "evt_01", Cursor: "cur_0001", ResourceKind: "route", ResourceID: "route_01", Actor: EventActor{Type: "edge", ID: "edge_01"}})
	if err != nil {
		t.Fatal(err)
	}
	if resource.Schema != ResourceSchemaV1 || resource.Kind != "event" || resource.EventType != "route_activated" || resource.SafeMetadata["config_generation"] != uint64(2) || resource.SafeMetadata["route_id"] != "route_01" {
		t.Fatalf("resource = %+v", resource)
	}
	if _, err := ProjectEventResource(event, EventResourceBinding{ResourceKind: "route", ResourceID: "route_01", Actor: EventActor{Type: "edge", ID: "edge_01"}}); err == nil {
		t.Fatal("event without durable id/cursor accepted")
	}
	body, _ := json.Marshal(resource)
	for _, forbidden := range []string{"authorization", "cookie", "private_key", "message"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("canonical event contains %q: %s", forbidden, body)
		}
	}
}
