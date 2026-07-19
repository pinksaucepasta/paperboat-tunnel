package node

import (
	"encoding/json"
	"net/http"
)

func (s *State) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, s.Snapshot(), false)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, s.Snapshot(), true)
	})
	return mux
}

func writeHealth(w http.ResponseWriter, snapshot Snapshot, readiness bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if (readiness && !snapshot.Ready) || (!readiness && !snapshot.Live) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(snapshot)
}
