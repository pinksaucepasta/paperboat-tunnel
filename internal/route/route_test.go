package route

import (
	"testing"
	"time"
)

func TestRegistryRevisionAndHostOwnership(t *testing.T) {
	r := NewRegistry("example.test", "helper.example.test")
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

func TestRegistryRejectsRouteKindDomainMismatch(t *testing.T) {
	registry := NewRegistry("preview.example.test", "helper.example.test")
	base := Attachment{ID: "route", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Target: "127.0.0.1:8080"}
	for _, attachment := range []Attachment{
		func() Attachment { a := base; a.Kind = HelperHTTPSWSS; a.Host = "app.preview.example.test"; return a }(),
		func() Attachment { a := base; a.Kind = PreviewHTTPSWSS; a.Host = "app.helper.example.test"; return a }(),
	} {
		if _, err := registry.Attach(attachment); err != ErrInvalid {
			t.Fatalf("mismatched route accepted: %+v, err=%v", attachment, err)
		}
	}
}

func TestRegistryReplaceRejectsStaleSnapshotWithoutMutation(t *testing.T) {
	registry := NewRegistry("preview.example.test", "example.test")
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
	registry := NewRegistry("preview.example.test", "example.test")
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

func TestRegistryChangedIsHostScopedAndMaterial(t *testing.T) {
	registry := NewRegistry("preview.example.test", "example.test")
	first := Attachment{ID: "first", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Host: "first.example.test", Target: "127.0.0.1:8080", Kind: HelperHTTPSWSS}
	second := Attachment{ID: "second", Revision: 1, Environment: "env", Node: "edge", Generation: 1, Host: "second.example.test", Target: "127.0.0.1:8081", Kind: HelperHTTPSWSS}
	firstChanged := registry.Changed(first.Host)
	secondChanged := registry.Changed(second.Host)
	if _, err := registry.Attach(first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstChanged:
	default:
		t.Fatal("changed host was not signaled")
	}
	select {
	case <-secondChanged:
		t.Fatal("unrelated host was signaled")
	default:
	}
	stable := registry.Changed(first.Host)
	if _, err := registry.Attach(first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stable:
		t.Fatal("idempotent attachment was signaled")
	case <-time.After(10 * time.Millisecond):
	}
	if err := registry.Replace([]Attachment{first, second}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stable:
		t.Fatal("unchanged host was signaled by replacement")
	default:
	}
}
