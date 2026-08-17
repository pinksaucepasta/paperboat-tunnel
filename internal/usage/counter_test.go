package usage

import "testing"

func TestReconcileIsMonotonic(t *testing.T) {
	c := NewCounters()
	k := Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Direction: "egress"}
	if got := c.Reconcile(k, 1024); got != 1024 {
		t.Fatal(got)
	}
	if got := c.Reconcile(k, 512); got != 0 {
		t.Fatal(got)
	}
	if got := c.Reconcile(k, 2048); got != 1024 {
		t.Fatal(got)
	}
	if got := NewCounters().Reconcile(Key{Node: "n", Epoch: "new"}, 1); got != 1 {
		t.Fatal(got)
	}
}

func TestCountersSaturateInsteadOfWrapping(t *testing.T) {
	counters := NewCounters()
	key := Key{Node: "edge", Epoch: "epoch", Environment: "env", Route: "route", Revision: 1, Direction: "ingress"}
	if got := counters.Observe(key, ^uint64(0)-1); got != ^uint64(0)-1 {
		t.Fatalf("baseline=%d", got)
	}
	if got := counters.Add(key, 2); got != ^uint64(0) {
		t.Fatalf("saturated=%d", got)
	}
	if got := counters.Add(key, 1); got != ^uint64(0) {
		t.Fatalf("post-saturation=%d", got)
	}
}
