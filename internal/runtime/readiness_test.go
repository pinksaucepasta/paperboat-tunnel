package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReadinessRetriesUntilDependencyIsReady(t *testing.T) {
	calls := 0
	ready := Readiness{Timeout: time.Second, Interval: time.Millisecond, Probe: func() error {
		calls++
		if calls < 3 {
			return errors.New("not ready")
		}
		return nil
	}}
	if err := ready.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestReadinessIsBoundedAndCancellable(t *testing.T) {
	probe := func() error { return errors.New("not ready") }
	if err := (Readiness{Timeout: 5 * time.Millisecond, Interval: time.Millisecond, Probe: probe}).Start(context.Background()); !errors.Is(err, ErrReadinessTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Readiness{Timeout: time.Second, Interval: time.Millisecond, Probe: probe}).Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
