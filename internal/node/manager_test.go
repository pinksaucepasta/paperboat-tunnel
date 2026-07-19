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
