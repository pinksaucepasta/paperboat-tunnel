package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

type edgeVector struct {
	Case          string `json:"case"`
	Valid         bool   `json:"valid"`
	Kind          string `json:"kind"`
	Error         string `json:"error"`
	Mutated       bool   `json:"mutated"`
	PreviousBytes uint64 `json:"previous_bytes"`
	Delta         uint64 `json:"delta"`
	Input         struct {
		CounterEpoch string `json:"counter_epoch"`
		Bytes        uint64 `json:"bytes"`
	} `json:"input"`
}

func TestEdgeControlVectors(t *testing.T) {
	required := map[string]bool{
		"admit-current-generation": false, "admit-stale-generation": false,
		"admit-replayed-jti": false, "attach-route": false,
		"detach-stale-revision": false, "usage-first": false,
		"usage-increase": false, "usage-lower-duplicate": false,
		"usage-new-epoch": false,
	}
	f, err := os.Open("../../testdata/contracts/fixtures/edge/control.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var vector edgeVector
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if _, ok := required[vector.Case]; !ok {
			t.Fatalf("unknown edge vector %q", vector.Case)
		}
		if !vector.Valid && (vector.Error == "" || vector.Mutated) {
			t.Fatalf("negative vector must fail before mutation: %#v", vector)
		}
		if vector.Kind == "usage" {
			got := usageDelta(vector.PreviousBytes, vector.Input.Bytes)
			if got != vector.Delta {
				t.Errorf("%s: delta=%d, want %d", vector.Case, got, vector.Delta)
			}
		}
		required[vector.Case] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for name, seen := range required {
		if !seen {
			t.Errorf("missing edge vector %q", name)
		}
	}
}

func usageDelta(previous, observed uint64) uint64 {
	if observed <= previous {
		return 0
	}
	return observed - previous
}
