package usage

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestMeterQueuesSignedAbsoluteReportsAndPersists(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	queue, _ := NewQueue(8, 1<<20)
	persisted := 0
	meter := &Meter{Node: "edge", Epoch: "epoch", Counters: NewCounters(), Queue: queue, KeyID: "usage-key", PrivateKey: private, Persist: func() error { persisted++; return nil }, Now: func() time.Time { return time.Unix(100, 0) }}
	if err := meter.Record("env", "route", 2, 10, 20); err != nil {
		t.Fatal(err)
	}
	if err := meter.Record("env", "route", 2, 5, 0); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 || queue.Len() != 0 {
		t.Fatalf("persisted=%d queued=%d", persisted, queue.Len())
	}
	if err := meter.Flush(); err != nil {
		t.Fatal(err)
	}
	if persisted != 1 || queue.Len() != 2 {
		t.Fatalf("persisted=%d queued=%d", persisted, queue.Len())
	}
	for queue.Len() > 0 {
		report, _ := queue.Next()
		document, err := VerifySignedReport("usage-key", public, report.Payload)
		if err != nil || document.Bytes != report.Bytes || document.Key != report.Key {
			t.Fatalf("report = %+v document = %+v err=%v", report, document, err)
		}
		queue.Ack(report.OperationID)
	}
	if got := meter.Counters.Get(Key{Node: "edge", Epoch: "epoch", Environment: "env", Route: "route", Revision: 2, Direction: "ingress"}); got != 15 {
		t.Fatalf("ingress = %d", got)
	}
}

func TestMeterFlushesRestoredCountersWithoutPriorRecord(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	key := Key{Node: "edge", Epoch: "restored-epoch", Environment: "env", Route: "route", Revision: 3, Direction: "ingress"}
	counters := NewCounters()
	counters.Observe(key, 42)
	queue, _ := NewQueue(2, 1<<20)
	meter := &Meter{Node: "edge", Epoch: "new-epoch", Counters: counters, Queue: queue, KeyID: "usage-key", PrivateKey: private, Persist: func() error { return nil }, Now: func() time.Time { return time.Unix(200, 0).UTC() }}
	if err := meter.Flush(); err != nil {
		t.Fatal(err)
	}
	report, ok := queue.Next()
	if !ok || report.Key != key || report.Bytes != 42 || report.Interval[0] != meter.Now() {
		t.Fatalf("restored report = %+v, present=%v", report, ok)
	}
}

func TestMeterRestoreBaselineDoesNotRegenerateAcknowledgedReport(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	key := Key{Node: "edge", Epoch: "restored-epoch", Environment: "env", Route: "route", Revision: 1, Direction: "egress"}
	counters := NewCounters()
	counters.Observe(key, 42)
	queue, _ := NewQueue(2, 1<<20)
	meter := &Meter{Node: "edge", Epoch: "new-epoch", Counters: counters, Queue: queue, KeyID: "usage-key", PrivateKey: private, Persist: func() error { return nil }, Now: func() time.Time { return time.Unix(200, 0).UTC() }}
	if err := meter.RestoreBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := meter.Flush(); err != nil {
		t.Fatal(err)
	}
	if queue.Len() != 0 {
		t.Fatalf("restored acknowledged counter was regenerated: %d reports", queue.Len())
	}
}
