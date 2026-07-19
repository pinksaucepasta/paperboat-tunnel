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
