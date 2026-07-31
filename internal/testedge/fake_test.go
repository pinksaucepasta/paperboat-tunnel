package testedge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func TestFakeUsageReconcilesMaximumByEpochAndRevision(t *testing.T) {
	fake := New()
	key := usage.Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Revision: 4, Direction: "egress"}
	ctx := context.Background()
	first := control.UsageReport{OperationID: "op_1", Key: key, Bytes: 1024, Interval: [2]time.Time{time.Unix(1, 0), time.Unix(2, 0)}}
	result, err := fake.ReportUsage(ctx, first)
	if err != nil || result.Delta != 1024 {
		t.Fatalf("first = %+v, %v", result, err)
	}
	duplicate, err := fake.ReportUsage(ctx, first)
	if err != nil || duplicate.Delta != 1024 {
		t.Fatalf("duplicate = %+v, %v", duplicate, err)
	}
	lower := first
	lower.OperationID, lower.Bytes = "op_2", 512
	result, err = fake.ReportUsage(ctx, lower)
	if err != nil || result.Delta != 0 {
		t.Fatalf("lower = %+v, %v", result, err)
	}
	higher := first
	higher.OperationID, higher.Bytes = "op_3", 2048
	result, err = fake.ReportUsage(ctx, higher)
	if err != nil || result.Delta != 1024 {
		t.Fatalf("higher = %+v, %v", result, err)
	}
	newEpoch := higher
	newEpoch.OperationID, newEpoch.Key.Epoch, newEpoch.Bytes = "op_4", "e2", 100
	result, err = fake.ReportUsage(ctx, newEpoch)
	if err != nil || result.Delta != 100 {
		t.Fatalf("new epoch = %+v, %v", result, err)
	}
	newRevision := higher
	newRevision.OperationID, newRevision.Key.Revision, newRevision.Bytes = "op_5", 5, 1
	result, err = fake.ReportUsage(ctx, newRevision)
	if err != nil || result.Delta != 1 {
		t.Fatalf("new revision = %+v, %v", result, err)
	}
}

func TestFakeCredentialAssignmentAndNodeLifecycle(t *testing.T) {
	fake := New()
	claims := admission.Claims{JTI: "jti_1"}
	fake.SetCredential("token", claims)
	got, err := fake.Verify(context.Background(), "token")
	if err != nil || got.JTI != claims.JTI {
		t.Fatalf("claims = %+v, %v", got, err)
	}
	if _, err := fake.Verify(context.Background(), "unknown"); !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("unknown = %v", err)
	}
	fake.SetAssignment("env", "machine", "runtime", admission.Current{Generation: 3})
	if current, err := fake.Current(context.Background(), "env", "machine", "runtime"); err != nil || current.Generation != 3 {
		t.Fatalf("current = %+v, %v", current, err)
	}
	if err := fake.RegisterNode(context.Background(), control.NodeRegistration{NodeID: "n", ProcessEpoch: "p", Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := fake.Heartbeat(context.Background(), control.NodeObservation{NodeID: "n", ProcessEpoch: "p", Ready: true, At: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if node, ok := fake.Node("n"); !ok || !node.Ready {
		t.Fatalf("node = %+v, %v", node, ok)
	}
	if registration, ok := fake.Registration("n"); !ok || registration.Capacity != 1 {
		t.Fatalf("registration = %+v, %v", registration, ok)
	}
	route := control.RouteAssignment{RouteID: "r", Revision: 2, Environment: "env", Generation: 3, NodeID: "n"}
	if err := fake.SetRoute(route); err != nil {
		t.Fatal(err)
	}
	route.Revision = 1
	if err := fake.SetRoute(route); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("stale route = %v", err)
	}
}

func TestDeliveryRetainsExactReportOnUncertainAcknowledgment(t *testing.T) {
	fake := New()
	queue, err := usage.NewQueue(2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake.SetUsageKey("usage-key-1", public)
	report, err := usage.NewSignedReport("usage-key-1", private, usage.SignedDocument{OperationID: "op_usage_01", Key: usage.Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Revision: 1, Direction: "egress"}, Bytes: 100, Start: time.Unix(1, 0), End: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	fake.LoseNextAcknowledgment()
	if _, delivered, err := control.DeliverNext(context.Background(), queue, fake); !delivered || !errors.Is(err, ErrAckLost) {
		t.Fatalf("delivery = %v, %v", delivered, err)
	}
	if queue.Len() != 1 {
		t.Fatal("uncertain report was removed")
	}
	result, delivered, err := control.DeliverNext(context.Background(), queue, fake)
	if err != nil || !delivered || result.Delta != 100 {
		t.Fatalf("retry = %+v, %v, %v", result, delivered, err)
	}
	if queue.Len() != 0 {
		t.Fatal("acknowledged report remains")
	}
}
