package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/store"
)

func TestPersistenceRestoresBeforeSaving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge-state.json")
	want := store.State{Version: store.CurrentVersion, CounterEpoch: "old_epoch"}
	if err := store.Save(path, want); err != nil {
		t.Fatal(err)
	}
	var restored store.State
	component := Persistence{Path: path, Restore: func(state store.State) error { restored = state; return nil }, Snapshot: func() store.State { return store.State{Version: store.CurrentVersion, CounterEpoch: "new_epoch"} }}
	if err := component.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restored.CounterEpoch != "old_epoch" {
		t.Fatalf("restored = %+v", restored)
	}
	if err := component.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.CounterEpoch != "new_epoch" {
		t.Fatalf("saved = %+v", saved)
	}
}

func TestPersistenceFailsClosedOnCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge-state.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	component := Persistence{Path: path, Restore: func(store.State) error { return nil }, Snapshot: func() store.State { return store.State{Version: store.CurrentVersion} }}
	if err := component.Start(context.Background()); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("error = %v", err)
	}
}
