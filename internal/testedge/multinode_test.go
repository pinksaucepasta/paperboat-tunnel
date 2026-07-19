package testedge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestTwoNodeReassignmentFencesStaleOwner(t *testing.T) {
	stateOne, stateTwo := node.New("edge_one"), node.New("edge_two")
	if !stateOne.MarkReady() || !stateTwo.MarkReady() {
		t.Fatal("nodes did not become ready")
	}
	nodeOne, err := node.NewManager(stateOne, 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeTwo, err := node.NewManager(stateTwo, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeOne.AdmitConnector("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := nodeTwo.AdmitConnector("connector", 2); err != nil {
		t.Fatal(err)
	}
	registry := route.NewRegistry()
	first := route.Attachment{ID: "route", Revision: 1, Environment: "env", Node: "edge_one", Generation: 1, Kind: route.PreviewHTTPSWSS, Host: "preview.example.test", Target: "127.0.0.1:3000"}
	second := first
	second.Revision, second.Node, second.Generation = 2, "edge_two", 2
	if _, err := registry.Attach(first); err != nil {
		t.Fatal(err)
	}
	fake := New()
	if err := fake.SetRoute(control.RouteAssignment{RouteID: "route", Revision: 2, Environment: "env", Generation: 2, NodeID: "edge_two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Attach(second); err != nil {
		t.Fatal(err)
	}
	if err := registry.Detach(first.ID, first.Revision); !errors.Is(err, route.ErrStale) {
		t.Fatalf("stale detach = %v", err)
	}
	current, ok := registry.Get("route")
	if !ok || current.Node != "edge_two" || current.Revision != 2 {
		t.Fatalf("current route = %+v, %v", current, ok)
	}
	if err := nodeOne.OpenStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := nodeTwo.OpenStream("connector", 2); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	if !stateOne.BeginDrain(deadline) {
		t.Fatal("old node did not begin drain")
	}
	if err := nodeOne.OpenStream("connector", 1); !errors.Is(err, node.ErrDraining) {
		t.Fatalf("old node accepted stream: %v", err)
	}
	if err := nodeOne.CloseStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if forced := nodeOne.Drain(context.Background(), deadline); forced {
		t.Fatal("old node drain forced unexpectedly")
	}
	if stateOne.Snapshot().Ready {
		t.Fatal("old node remained ready")
	}
	if err := nodeTwo.CloseStream("connector", 2); err != nil {
		t.Fatal(err)
	}
	if forced := nodeTwo.Drain(context.Background(), time.Now().Add(time.Second)); forced {
		t.Fatal("new node drain forced unexpectedly")
	}
	if got := nodeTwo.Snapshot(); got.Streams != 0 {
		t.Fatalf("new node streams remain: %+v", got)
	}
}
