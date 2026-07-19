package node

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadinessFirstDrain(t *testing.T) {
	state := New("edge_test_01")
	assertHealth(t, state, "/livez", http.StatusOK)
	assertHealth(t, state, "/readyz", http.StatusServiceUnavailable)
	if !state.MarkReady() {
		t.Fatal("ready transition rejected")
	}
	assertHealth(t, state, "/readyz", http.StatusOK)
	if !state.SetControlAvailable(false) {
		t.Fatal("control partition transition rejected")
	}
	assertHealth(t, state, "/readyz", http.StatusServiceUnavailable)
	assertHealth(t, state, "/livez", http.StatusOK)
	if !state.SetControlAvailable(true) {
		t.Fatal("control recovery transition rejected")
	}
	assertHealth(t, state, "/readyz", http.StatusOK)
	deadline := time.Unix(100, 0).UTC()
	if !state.BeginDrain(deadline) {
		t.Fatal("drain transition rejected")
	}
	snapshot := state.Snapshot()
	if snapshot.Ready || !snapshot.Live || snapshot.DrainDeadline != deadline {
		t.Fatalf("unexpected drain snapshot: %+v", snapshot)
	}
	assertHealth(t, state, "/livez", http.StatusOK)
	assertHealth(t, state, "/readyz", http.StatusServiceUnavailable)
}

func assertHealth(t *testing.T, state *State, path string, want int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	state.HealthHandler().ServeHTTP(recorder, request)
	if recorder.Code != want {
		t.Fatalf("%s status = %d, want %d", path, recorder.Code, want)
	}
}
