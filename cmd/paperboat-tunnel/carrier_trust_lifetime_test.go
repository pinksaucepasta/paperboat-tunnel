package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

func TestCarrierTrustLifetimeRequestsBoundedProcessReplacement(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	trust, err := control.NewProcessCarrierServerTrust("edge_1", "epoch_1", "edge.example.test", now, 4*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, err := newCarrierTrustLifetime(trust.Certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	// A four-minute certificate refreshes one minute before expiry.
	lifetime.now = func() time.Time { return now.Add(3 * time.Minute) }
	if err := lifetime.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lifetime.Done():
		if !errors.Is(err, errCarrierTrustRefreshRequired) {
			t.Fatalf("done error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier trust replacement was not requested")
	}
	if err := lifetime.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCarrierTrustLifetimeShutdownCancelsTimer(t *testing.T) {
	now := time.Now().UTC()
	trust, err := control.NewProcessCarrierServerTrust("edge_1", "epoch_1", "edge.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, err := newCarrierTrustLifetime(trust.Certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifetime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := lifetime.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lifetime.Done():
		t.Fatalf("unexpected refresh after shutdown: %v", err)
	default:
	}
}
