package route

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func matcherRule(id, host, matchType, pathPrefix string, priority int) RouteRule {
	rule := RouteRule{ID: id, Kind: HelperHTTPSWSS, MatchType: matchType, Hostname: host, PathPrefix: pathPrefix, Priority: priority, Target: "127.0.0.1:8080", OriginScheme: "http", ObservedState: "ready"}
	if matchType == MatchOneLabelWildcard {
		rule.Hostname = ""
		rule.WildcardSuffix = host
	}
	return rule
}

func activateMatcher(t *testing.T, registry *GenerationRegistry, generation uint64, rules []RouteRule) {
	t.Helper()
	if err := registry.StageGeneration(generation, rules); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkGenerationReady(generation); err != nil {
		t.Fatal(err)
	}
	if err := registry.ActivateGeneration(context.Background(), generation, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationRegistryPrecedenceAndPathBoundaries(t *testing.T) {
	registry := NewGenerationRegistry(16)
	activateMatcher(t, registry, 1, []RouteRule{
		matcherRule("catch", "", MatchCatchAll, "/", 1000),
		matcherRule("wild", "example.test", MatchOneLabelWildcard, "/", 100),
		matcherRule("nested-wild", "foo.example.test", MatchOneLabelWildcard, "/", 100),
		matcherRule("exact", "app.example.test", MatchExact, "/", 100),
		matcherRule("api", "app.example.test", MatchExact, "/api", 100),
		matcherRule("api-v1", "app.example.test", MatchExact, "/api/v1", 100),
	})
	tests := []struct {
		host, path, id string
	}{
		{"app.example.test", "/", "exact"},
		{"app.example.test", "/api", "api"},
		{"app.example.test", "/api/v1/users", "api-v1"},
		{"app.example.test", "/apix", "exact"},
		{"other.example.test", "/any", "wild"},
		{"a.b.foo.example.test", "/any", "catch"},
	}
	for _, test := range tests {
		match, err := registry.Match(test.host, test.path)
		if err != nil || match.Rule.ID != test.id {
			t.Fatalf("match %s%s = %s/%v, want %s", test.host, test.path, match.Rule.ID, err, test.id)
		}
	}
	if _, err := registry.Match("other.foo.example.test", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Match("other.foo.example.test", "/bad//path"); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("invalid path error = %v", err)
	}
}

func TestGenerationRegistryRejectsEqualPrecedenceOverlapAndInvalidWildcard(t *testing.T) {
	registry := NewGenerationRegistry(16)
	conflict := []RouteRule{
		matcherRule("first", "app.example.test", MatchExact, "/api", 10),
		matcherRule("second", "app.example.test", MatchExact, "/api", 10),
	}
	if err := registry.StageGeneration(1, conflict); !errors.Is(err, ErrMatchConflict) {
		t.Fatalf("equal overlap error = %v", err)
	}
	invalid := matcherRule("recursive", "*.example.test", MatchOneLabelWildcard, "/", 1)
	invalid.WildcardSuffix = "*.example.test"
	if err := registry.StageGeneration(1, []RouteRule{invalid}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("recursive wildcard error = %v", err)
	}
	if _, err := registry.Match("a.b.example.test", "/"); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("inactive match = %v", err)
	}
}

func TestGenerationRegistryIDNAAndTiePriority(t *testing.T) {
	registry := NewGenerationRegistry(8)
	rule := matcherRule("unicode", "xn--bcher-kva.example.test", MatchExact, "/", 10)
	activateMatcher(t, registry, 1, []RouteRule{rule})
	match, err := registry.Match("bücher.example.test.", "/")
	if err != nil || match.Rule.ID != "unicode" {
		t.Fatalf("IDNA match = %+v, %v", match, err)
	}
	if err := registry.StageGeneration(2, []RouteRule{matcherRule("bad", "bad..example.test", MatchExact, "/", 1)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid IDNA error = %v", err)
	}
	if err := registry.StageGeneration(2, []RouteRule{
		matcherRule("low", "same.example.test", MatchExact, "/", 20),
		matcherRule("high", "same.example.test", MatchExact, "/", 10),
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkGenerationReady(2); err != nil {
		t.Fatal(err)
	}
	if err := registry.ActivateGeneration(context.Background(), 2, time.Second); err != nil {
		t.Fatal(err)
	}
	match, err = registry.Match("same.example.test", "/")
	if err != nil || match.Rule.ID != "high" {
		t.Fatalf("priority match = %+v, %v", match, err)
	}
}

func TestGenerationRegistryReadyThenAtomicDrainHandoff(t *testing.T) {
	registry := NewGenerationRegistry(8)
	activateMatcher(t, registry, 1, []RouteRule{matcherRule("old", "app.example.test", MatchExact, "/", 1)})
	oldLease, oldMatch, err := registry.Acquire(context.Background(), "app.example.test", "/")
	if err != nil || oldMatch.Rule.ID != "old" {
		t.Fatalf("old lease = %+v, %v", oldMatch, err)
	}
	if err := registry.StageGeneration(2, []RouteRule{matcherRule("new", "app.example.test", MatchExact, "/", 1)}); err != nil {
		t.Fatal(err)
	}
	if err := registry.MarkGenerationReady(2); err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	go func() { activated <- registry.ActivateGeneration(context.Background(), 2, time.Second) }()
	deadline := time.Now().Add(time.Second)
	for registry.Generation() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("new generation was not atomically promoted")
		}
		time.Sleep(time.Millisecond)
	}
	newMatch, err := registry.Match("app.example.test", "/")
	if err != nil || newMatch.Rule.ID != "new" || newMatch.Generation != 2 {
		t.Fatalf("new match = %+v, %v", newMatch, err)
	}
	select {
	case err := <-activated:
		t.Fatalf("activation drained before old close: %v", err)
	default:
	}
	if err := oldLease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-activated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old generation did not drain")
	}
	select {
	case <-oldLease.Done():
	default:
		t.Fatal("old lease did not close")
	}
}

func TestGenerationRegistryDrainTimeoutAndFailedReadinessPreserveActive(t *testing.T) {
	registry := NewGenerationRegistry(8)
	activateMatcher(t, registry, 1, []RouteRule{matcherRule("old", "app.example.test", MatchExact, "/", 1)})
	if err := registry.ApplyGeneration(context.Background(), 2, []RouteRule{matcherRule("failed", "app.example.test", MatchExact, "/", 1)}, func(context.Context, []RouteRule) error {
		return errors.New("origin not ready")
	}, time.Millisecond); err == nil {
		t.Fatal("failed readiness activated")
	}
	match, err := registry.Match("app.example.test", "/")
	if err != nil || match.Rule.ID != "old" {
		t.Fatalf("failed readiness changed active = %+v, %v", match, err)
	}
	oldLease, _, err := registry.Acquire(context.Background(), "app.example.test", "/")
	if err != nil {
		t.Fatal(err)
	}
	activateErr := make(chan error, 1)
	go func() {
		activateErr <- registry.ApplyGeneration(context.Background(), 3, []RouteRule{matcherRule("next", "app.example.test", MatchExact, "/", 1)}, func(context.Context, []RouteRule) error { return nil }, 5*time.Millisecond)
	}()
	select {
	case err := <-activateErr:
		if !errors.Is(err, ErrDrainTimeout) {
			t.Fatalf("drain error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain timeout did not fire")
	}
	if _, err := registry.Match("app.example.test", "/"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldLease.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timed out old lease was not canceled")
	}
	_ = oldLease.Close()
}

func TestGenerationRegistryConcurrentAcquireRelease(t *testing.T) {
	registry := NewGenerationRegistry(8)
	activateMatcher(t, registry, 1, []RouteRule{matcherRule("route", "app.example.test", MatchExact, "/", 1)})
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 50; j++ {
				lease, _, err := registry.Acquire(context.Background(), "app.example.test", "/")
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				if !strings.HasPrefix(lease.Match().Rule.ID, "route") {
					t.Errorf("unexpected match: %+v", lease.Match())
				}
				_ = lease.Close()
			}
		}()
	}
	wait.Wait()
}
