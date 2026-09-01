package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestRouteWorkerRetainsLKGAdmissionUntilReplacementPromotion(t *testing.T) {
	publicKey, thumbprint := durableWorkerIdentity(t)
	old := durableWorkerAssignment(publicKey, thumbprint, "route_lkg", "assignment_lkg_old", route.TunnelHTTPSWSS)
	newAssignment := old
	newAssignment.AssignmentID = "assignment_lkg_new"
	newAssignment.AssignmentGeneration = 2
	newAssignment.Revision = 2
	newAssignment.Generation = 2
	newAssignment.ConnectorSessionID = "session_lkg_new"
	newAssignment.ConnectorProcessGeneration = 2
	newAssignment.ConfigGeneration = 2
	newAssignment.ConfigContentHash = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	newAssignment.State = "staged"

	canonical := route.NewRegistry("", "")
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	state := node.New("edge_1")
	state.MarkReady()
	source := &workerSnapshotSource{snapshot: control.RouteSnapshot{
		Routes: []control.RouteAssignment{old}, Complete: true, Canonical: true,
	}}
	var readyErr error
	worker := &RouteWorker{
		Registry: canonical, Source: source, Observer: &appendRouteObserver{}, State: state,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: &workerCarrierProbe{},
		DurableAdmissions: durable, Ready: func(context.Context, []route.RouteRule) error { return readyErr },
		Pulse: make(chan time.Time), DrainTimeout: time.Second,
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = worker.Shutdown(ctx)
	}()

	source.snapshot.Routes = []control.RouteAssignment{old, newAssignment}
	readyErr = errors.New("replacement origin unavailable")
	if err := worker.reconcile(context.Background()); !errors.Is(err, readyErr) {
		t.Fatalf("failed replacement error = %v, want %v", err, readyErr)
	}
	admissions := durable.Snapshot()
	if len(admissions) != 2 {
		t.Fatalf("admissions during failed replacement = %+v, want LKG and staged candidate", admissions)
	}
	seen := make(map[string]bool, len(admissions))
	for _, admission := range admissions {
		seen[admission.AssignmentID] = true
	}
	if !seen[old.AssignmentID] || !seen[newAssignment.AssignmentID] {
		t.Fatalf("admissions during failed replacement = %+v, want both assignments", admissions)
	}
	if _, err := canonical.Match(old.PublicHost, "/still-live"); err != nil {
		t.Fatalf("LKG route disappeared during failed replacement: %v", err)
	}

	readyErr = nil
	if err := worker.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	admissions = durable.Snapshot()
	if len(admissions) != 1 || admissions[0].AssignmentID != newAssignment.AssignmentID {
		t.Fatalf("admissions after promotion = %+v, want only replacement", admissions)
	}
	match, err := canonical.Match(newAssignment.PublicHost, "/promoted")
	if err != nil {
		t.Fatal(err)
	}
	if match.Rule.AssignmentID != newAssignment.AssignmentID {
		t.Fatalf("active route assignment = %s, want %s", match.Rule.AssignmentID, newAssignment.AssignmentID)
	}
}
