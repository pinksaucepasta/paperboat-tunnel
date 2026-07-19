package route

import "testing"

func TestRegistryRevisionAndHostOwnership(t *testing.T) {
	r := NewRegistry()
	a := Attachment{ID: "r1", Revision: 1, Environment: "e1", Node: "n1", Generation: 1, Host: "Preview.Example.Test.", Target: "127.0.0.1:3000", Kind: PreviewHTTPSWSS}
	if _, err := r.Attach(a); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Attach(a); err != nil {
		t.Fatal(err)
	}
	stale := a
	stale.Revision = 0
	if _, err := r.Attach(stale); err != ErrInvalid {
		t.Fatalf("got %v", err)
	}
	conflict := a
	conflict.ID = "r2"
	conflict.Host = "preview.example.test"
	if _, err := r.Attach(conflict); err != ErrConflict {
		t.Fatalf("got %v", err)
	}
	if err := r.Detach("r1", 0); err != ErrStale {
		t.Fatalf("got %v", err)
	}
	if err := r.Detach("r1", 2); err != ErrStale {
		t.Fatalf("future detach got %v", err)
	}
}

func TestRegistryReplaceRejectsStaleSnapshotWithoutMutation(t *testing.T) {
	registry := NewRegistry()
	current := Attachment{ID: "route", Revision: 3, Environment: "env", Node: "edge", Generation: 2, Host: "app.example.test", Target: "127.0.0.1:8080", Kind: HelperHTTPSWSS}
	if _, err := registry.Attach(current); err != nil {
		t.Fatal(err)
	}
	stale := current
	stale.Revision = 2
	if err := registry.Replace([]Attachment{stale}); err != ErrStale {
		t.Fatalf("replace error = %v", err)
	}
	got, ok := registry.Get(current.ID)
	if !ok || got != current {
		t.Fatalf("registry mutated: %+v, present=%v", got, ok)
	}
}

func TestRegistryReplaceRejectsConflictWithoutMutation(t *testing.T) {
	registry := NewRegistry()
	current := Attachment{ID: "route", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Host: "old.example.test", Target: "127.0.0.1:8080", Kind: HelperHTTPSWSS}
	if _, err := registry.Attach(current); err != nil {
		t.Fatal(err)
	}
	first := current
	first.Revision = 2
	first.Host = "new.example.test"
	second := first
	second.ID = "other"
	if err := registry.Replace([]Attachment{first, second}); err != ErrConflict {
		t.Fatalf("replace error = %v", err)
	}
	got, ok := registry.Get(current.ID)
	if !ok || got != current {
		t.Fatalf("registry mutated: %+v, present=%v", got, ok)
	}
}
