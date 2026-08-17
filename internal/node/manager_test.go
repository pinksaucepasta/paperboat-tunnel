package node

import (
	"context"
	"testing"
	"time"
)

func readyManager(t *testing.T, capacity uint32) *Manager {
	t.Helper()
	state := New("edge_test_01")
	if !state.MarkReady() {
		t.Fatal("ready transition failed")
	}
	manager, err := NewManager(state, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestCapacityReplacementAndStaleGeneration(t *testing.T) {
	manager := readyManager(t, 1)
	if err := manager.AdmitConnector("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.AdmitConnector("other", 1); err != ErrCapacity {
		t.Fatalf("capacity = %v", err)
	}
	if err := manager.OpenStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReplaceConnector("connector", 2); err != nil {
		t.Fatalf("replace active = %v", err)
	}
	if err := manager.OpenStream("connector", 2); err != nil {
		t.Fatal("new generation rejected")
	}
	if err := manager.OpenStream("connector", 1); err == nil {
		t.Fatal("old generation accepted")
	}
	if err := manager.CloseStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.OpenStream("connector", 2); err != nil {
		t.Fatal(err)
	}
}

func TestDrainRejectsNewWorkAndWaitsForExistingStreams(t *testing.T) {
	manager := readyManager(t, 2)
	if err := manager.AdmitConnector("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.OpenStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	manager.state.BeginDrain(deadline)
	done := make(chan bool, 1)
	go func() { done <- manager.Drain(context.Background(), deadline) }()
	if err := manager.AdmitConnector("new", 1); err != ErrNotReady {
		t.Fatalf("new assignment = %v", err)
	}
	if err := manager.CloseStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if forced := <-done; forced {
		t.Fatal("drain forced despite stream close")
	}
}

func TestDrainDeadlineFencesAllOwnership(t *testing.T) {
	manager := readyManager(t, 1)
	if err := manager.AdmitConnector("connector", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.OpenStream("connector", 1); err != nil {
		t.Fatal(err)
	}
	if forced := manager.Drain(context.Background(), time.Now().Add(10*time.Millisecond)); !forced {
		t.Fatal("drain did not force")
	}
	if got := manager.Snapshot(); len(got.Connectors) != 0 || got.Streams != 0 {
		t.Fatalf("ownership remains: %+v", got)
	}
}

func TestAggregateStreamCountsSaturateWithoutAppearingEmpty(t *testing.T) {
	manager := readyManager(t, 2)
	manager.connectors["first"] = &connector{generation: 1, streams: ^uint32(0), retired: make(map[uint64]uint32)}
	manager.connectors["second"] = &connector{generation: 1, streams: 1, retired: map[uint64]uint32{2: 1}}

	if got := manager.Snapshot().Streams; got != ^uint32(0) {
		t.Fatalf("snapshot streams=%d", got)
	}
	manager.mu.Lock()
	total := manager.totalStreamsLocked()
	manager.mu.Unlock()
	if total != ^uint32(0) {
		t.Fatalf("drain stream total=%d", total)
	}
}
