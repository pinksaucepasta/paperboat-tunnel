package usage

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestMeterRevisionChangesPreserveSignedAbsoluteAndRestart(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	queue, _ := NewQueue(8, 1<<20)
	meter := &Meter{Node: "edge", Epoch: "epoch", Counters: NewCounters(), Queue: queue, KeyID: "key", PrivateKey: private, Persist: func() error { return nil }, Now: func() time.Time { return time.Unix(100, 0) }}
	check := func(want uint64) {
		t.Helper()
		if err := meter.Flush(); err != nil {
			t.Fatal(err)
		}
		report, ok := meter.Queue.Next()
		if !ok {
			t.Fatal("no report")
		}
		doc, err := VerifySignedReport("key", public, report.Payload)
		if err != nil || doc.Bytes != want {
			t.Fatalf("signed total=%d want=%d err=%v", doc.Bytes, want, err)
		}
		if want >= 120 && doc.Key.Revision != 2 {
			t.Fatalf("revision regressed: %d", doc.Key.Revision)
		}
		if meter.Queue.Len() != 1 {
			t.Fatalf("revision split queue: %d", meter.Queue.Len())
		}
	}
	if err := meter.Record("env", "route", 1, 100, 0); err != nil {
		t.Fatal(err)
	}
	check(100)
	if err := meter.Record("env", "route", 2, 20, 0); err != nil {
		t.Fatal(err)
	}
	check(120)
	restored := RestoreCounters(meter.Counters.Snapshot())
	restored = RestoreCounters(restored.Snapshot())
	restoredQueue, err := RestoreQueue(meter.Queue.Snapshot(), 8, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	meter.Counters = restored
	meter.Queue = restoredQueue
	meter.last = nil
	if err := meter.RestoreBaseline(); err != nil {
		t.Fatal(err)
	}
	check(120)
	if err := meter.Record("env", "route", 1, 5, 0); err != nil {
		t.Fatal(err)
	}
	check(125)
}

func TestRestoreRevisionPartitionsDeduplicatesAndReportsUnacknowledgedSum(t *testing.T) {
	key := Key{Node: "edge", Epoch: "epoch", Environment: "env", Route: "route", Direction: "ingress", Revision: 1}
	next := key
	next.Revision = 2
	counters := RestoreCounters([]CounterRecord{{Key: key, Bytes: 100}, {Key: key, Bytes: 100}, {Key: next, Bytes: 20}})
	if got := counters.Get(key); got != 120 {
		t.Fatalf("total=%d", got)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	queue, _ := NewQueue(8, 1<<20)
	meter := &Meter{Counters: counters, Queue: queue, KeyID: "key", PrivateKey: private, Persist: func() error { return nil }}
	if err := meter.RestoreBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := meter.Flush(); err != nil {
		t.Fatal(err)
	}
	report, ok := queue.Next()
	if !ok || report.Bytes != 120 {
		t.Fatalf("missing cumulative correction: %+v", report)
	}
	records := counters.Snapshot()
	if len(records) != 1 || RestoreCounters(records).Get(key) != 120 {
		t.Fatal("restart double counted")
	}
	for _, change := range []func(*Key){func(k *Key) { k.Node = "other" }, func(k *Key) { k.Epoch = "other" }, func(k *Key) { k.Environment = "other" }, func(k *Key) { k.Route = "other" }, func(k *Key) { k.Direction = "egress" }} {
		other := key
		change(&other)
		counters.Add(other, 7)
		if counters.Get(key) != 120 || counters.Get(other) != 7 {
			t.Fatal("counter identities crossed")
		}
	}
}
