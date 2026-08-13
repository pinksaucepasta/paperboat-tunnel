package usage

import (
	"math"
	"testing"
)

func TestEpochIsRandomAndQueueRetriesExactReport(t *testing.T) {
	one, err := NewCounterEpoch()
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewCounterEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if one == two || len(one) < 16 {
		t.Fatalf("epochs = %q, %q", one, two)
	}
	queue, err := NewQueue(1, 64)
	if err != nil {
		t.Fatal(err)
	}
	report := Report{OperationID: "op_usage_0001", Key: Key{Node: "n", Epoch: one, Environment: "env", Route: "r", Direction: "egress"}, Bytes: 1024, Payload: []byte("signed-report")}
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	retry, ok := queue.Next()
	if !ok || retry.OperationID != report.OperationID || string(retry.Payload) != string(report.Payload) {
		t.Fatalf("retry = %+v", retry)
	}
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	if queue.Ack(report.OperationID) != true || queue.Ack(report.OperationID) {
		t.Fatal("ack semantics failed")
	}
}

func TestQueueBoundsReportsAndBytes(t *testing.T) {
	queue, _ := NewQueue(1, 4)
	if err := queue.Enqueue(Report{OperationID: "op_1", Payload: []byte("12345")}); err == nil {
		t.Fatal("oversized report accepted")
	}
	if err := queue.Enqueue(Report{OperationID: "op_1", Payload: []byte("1234")}); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(Report{OperationID: "op_2", Payload: []byte("1")}); err == nil {
		t.Fatal("over-capacity report accepted")
	}
}

func TestCounterAndQueueSnapshotsRestore(t *testing.T) {
	counters := NewCounters()
	key := Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Direction: "ingress"}
	counters.Add(key, 42)
	if got := RestoreCounters(counters.Snapshot()).Get(key); got != 42 {
		t.Fatal(got)
	}
	queue, _ := NewQueue(2, 16)
	report := Report{OperationID: "op_1", Payload: []byte("report")}
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreQueue(queue.Snapshot(), 2, 16)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := restored.Next()
	if !ok || got.OperationID != report.OperationID || string(got.Payload) != string(report.Payload) {
		t.Fatalf("got = %+v", got)
	}
}

func TestQueueCoalescesNewestAbsoluteSnapshot(t *testing.T) {
	queue, _ := NewQueue(1, 1024)
	key := Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Direction: "ingress"}
	if err := queue.EnqueueLatest(Report{OperationID: "old", Key: key, Bytes: 10, Payload: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	if err := queue.EnqueueLatest(Report{OperationID: "new", Key: key, Bytes: 20, Payload: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	report, ok := queue.Next()
	if !ok || report.OperationID != "new" || report.Bytes != 20 || string(report.Payload) != "new" {
		t.Fatalf("report=%+v present=%v", report, ok)
	}
}

func TestQueueByteBoundsRejectBeforeIntegerOverflow(t *testing.T) {
	queue, _ := NewQueue(2, math.MaxInt)
	queue.bytes = math.MaxInt - 1
	if err := queue.Enqueue(Report{OperationID: "new", Payload: []byte("12")}); err != ErrQueueFull {
		t.Fatalf("enqueue error=%v", err)
	}

	latest, _ := NewQueue(1, math.MaxInt)
	key := Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Direction: "ingress"}
	if err := latest.EnqueueLatest(Report{OperationID: "old", Key: key, Bytes: 1, Payload: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	latest.bytes = math.MaxInt
	if err := latest.EnqueueLatest(Report{OperationID: "new", Key: key, Bytes: 2, Payload: []byte("12")}); err != ErrQueueFull {
		t.Fatalf("latest error=%v", err)
	}
}
