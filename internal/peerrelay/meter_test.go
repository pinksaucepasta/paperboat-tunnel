package peerrelay

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func TestMeterRecorderCountsEachRelayDirectionOnce(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := usage.NewQueue(8, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	counters := usage.NewCounters()
	meter := &usage.Meter{Node: "edge_01", Epoch: "epoch_01", Counters: counters, Queue: queue, KeyID: "key_01", PrivateKey: private, Persist: func() error { return nil }}
	recorder := MeterRecorder{Meter: meter}
	record := Usage{EnvironmentID: "environment_01", RouteID: "peer_route_01", RouteRevision: 7, BytesToHost: 31, BytesToInitiator: 19}
	if err := recorder.RecordRelayUsage(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	ingress := usage.Key{Node: "edge_01", Epoch: "epoch_01", Environment: record.EnvironmentID, Route: record.RouteID, Revision: record.RouteRevision, Direction: "ingress"}
	egress := usage.Key{Node: "edge_01", Epoch: "epoch_01", Environment: record.EnvironmentID, Route: record.RouteID, Revision: record.RouteRevision, Direction: "egress"}
	if counters.Get(ingress) != record.BytesToHost || counters.Get(egress) != record.BytesToInitiator {
		t.Fatalf("ingress=%d egress=%d", counters.Get(ingress), counters.Get(egress))
	}
}
