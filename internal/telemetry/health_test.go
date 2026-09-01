package telemetry

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHealthProjectionBrokenSinceRecoveryAndSuppression(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	setAllReady(t, tracker)

	at = at.Add(time.Minute)
	nextRetry := at.Add(10 * time.Second)
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionRoute, Status: StatusDegraded, Code: "route_stale", Summary: "Route assignment is stale.", RepairAction: "Wait for a fresh assignment.", CorrelationID: "corr_health_1", Retry: RetryScheduled, NextRetryAt: nextRetry})
	firstBroken := tracker.Snapshot()
	route := firstBroken.Dimensions.Route
	if route.BrokenSince == nil || !route.BrokenSince.Equal(at) || firstBroken.Overall.Dimension != DimensionRoute {
		t.Fatalf("first broken projection = %#v", firstBroken)
	}

	at = at.Add(time.Minute)
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionRoute, Status: StatusDown, Code: "route_unavailable", Summary: "Route is unavailable.", RepairAction: "Restore route assignment.", CorrelationID: "corr_health_2", Retry: RetryWaitForChange})
	secondBroken := tracker.Snapshot()
	if secondBroken.Dimensions.Route.BrokenSince == nil || !secondBroken.Dimensions.Route.BrokenSince.Equal(*route.BrokenSince) {
		t.Fatalf("broken_since was not preserved: %#v", secondBroken.Dimensions.Route)
	}
	if !secondBroken.Dimensions.Route.Since.Equal(at) {
		t.Fatalf("since = %s, want %s", secondBroken.Dimensions.Route.Since, at)
	}

	at = at.Add(time.Minute)
	updateHealth(t, tracker, readyUpdate(DimensionRoute))
	recovered := tracker.Snapshot()
	if recovered.Dimensions.Route.BrokenSince != nil || recovered.Dimensions.Route.Status != StatusReady {
		t.Fatalf("route did not recover: %#v", recovered.Dimensions.Route)
	}

	at = at.Add(time.Minute)
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionRoute, Status: StatusDown, Code: "route_unavailable", Summary: "Route is unavailable.", RepairAction: "Restore route assignment.", CorrelationID: "corr_health_3", Retry: RetryWaitForChange})
	at = at.Add(time.Minute)
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionEdge, Status: StatusDown, Code: "edge_offline", Summary: "Edge is offline.", RepairAction: "Restore edge connectivity.", CorrelationID: "corr_health_4", Retry: RetryScheduled, NextRetryAt: at.Add(time.Minute)})
	suppressed := tracker.Snapshot()
	if suppressed.Overall.Dimension != DimensionEdge || suppressed.Dimensions.Route.SuppressedBy != DimensionEdge {
		t.Fatalf("dependency suppression = %#v", suppressed)
	}
	if suppressed.Dimensions.Origin.SuppressedBy != DimensionEdge || suppressed.Dimensions.Certificate.SuppressedBy != DimensionEdge {
		t.Fatalf("dependent dimensions were not suppressed: %#v", suppressed.Dimensions)
	}
	alerts := suppressed.Alerts()
	if len(alerts) != 1 || alerts[0].Dimension != DimensionEdge || alerts[0].CorrelationID != "corr_health_4" || alerts[0].Correlation != "corr_health_4" {
		t.Fatalf("actionable root alerts = %#v", alerts)
	}
}

func TestHealthSnapshotJSONRejectsInvalidWireState(t *testing.T) {
	tracker := newTestHealthTracker(t, time.Now)
	snapshot := tracker.Snapshot()
	snapshot.Dimensions.Service.Summary = "authorization=Bearer leaked"
	if _, err := snapshot.JSON(); errorCode(err) != ErrorInvalidObservation {
		t.Fatalf("unsafe snapshot error = %v", err)
	}
}

func TestHealthSnapshotAndETagAreDeterministicAndIndependent(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 456789000, time.FixedZone("offset", 19800))
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	first := tracker.Snapshot()
	second := tracker.Snapshot()
	firstJSON, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) || first.ETag != second.ETag || !strings.HasPrefix(first.ETag, "sha256:") {
		t.Fatalf("unstable snapshots:\n%s\n%s", firstJSON, secondJSON)
	}
	first.Dimensions.Service.BrokenSince = timePointer(time.Unix(1, 0))
	if tracker.Snapshot().Dimensions.Service.BrokenSince != nil {
		t.Fatal("snapshot mutation changed tracker state")
	}
}

func TestHealthConstructionRedactsAndBoundsStrings(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	secret := "authorization=Bearer secret customer.example.com https://alice:password@example.com/x /Users/alice/private route_customer123"
	long := strings.Repeat("界", 300) + secret
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionAccess, Status: StatusDown, Code: "access_denied", Summary: long, RepairAction: secret, CorrelationID: "corr_safe_1", Retry: RetryNotRetryable})
	body, err := tracker.Snapshot().JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"secret", "customer.example.com", "alice", "route_customer123"} {
		if strings.Contains(string(body), unsafe) {
			t.Fatalf("unsafe value %q in %s", unsafe, body)
		}
	}
	if !strings.Contains(string(body), RedactedValue) || len(tracker.Snapshot().Dimensions.Access.Summary) > maximumSummaryBytes {
		t.Fatalf("redaction/bound failure: %s", body)
	}
	invalid := HealthUpdate{Dimension: Dimension("host.customer.example"), Status: StatusReady, Code: "ready", Summary: "ready", RepairAction: "none", Retry: RetryNone}
	if err := tracker.Update(invalid); errorCode(err) != ErrorInvalidDimension {
		t.Fatalf("invalid dimension error = %v", err)
	}
}

func TestHealthTrackerConcurrentUse(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	var group sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				dimension := dimensionOrder[(index+iteration)%len(dimensionOrder)]
				_ = tracker.Update(readyUpdate(dimension))
				body, err := tracker.Snapshot().JSON()
				if err != nil || !json.Valid(body) {
					t.Errorf("invalid concurrent snapshot: %s, %v", body, err)
					return
				}
			}
		}(worker)
	}
	group.Wait()
}

func setAllReady(t *testing.T, tracker *HealthTracker) {
	t.Helper()
	for _, dimension := range dimensionOrder {
		updateHealth(t, tracker, readyUpdate(dimension))
	}
}

func readyUpdate(dimension Dimension) HealthUpdate {
	return HealthUpdate{Dimension: dimension, Status: StatusReady, Code: "ready", Summary: "Dimension is ready.", RepairAction: "No action is required.", Retry: RetryNone}
}

func updateHealth(t *testing.T, tracker *HealthTracker, update HealthUpdate) {
	t.Helper()
	if err := tracker.Update(update); err != nil {
		t.Fatalf("Update(%s): %v", update.Dimension, err)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func errorCode(err error) ErrorCode {
	if typed, ok := err.(*Error); ok {
		return typed.Code
	}
	return ""
}

func newTestHealthTracker(t *testing.T, now func() time.Time) *HealthTracker {
	t.Helper()
	tracker, err := NewHealthTracker(now)
	if err != nil {
		t.Fatalf("NewHealthTracker: %v", err)
	}
	return tracker
}
