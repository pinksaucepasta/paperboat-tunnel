package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

func TestPreviewTunnelV1EdgeOwnership(t *testing.T) {
	fixtures, err := os.Open("../../testdata/contracts/preview-tunnel-v1/fixtures/resources.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer fixtures.Close()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(fixtures)
	for scanner.Scan() {
		var vector struct {
			Case     string         `json:"case"`
			Valid    bool           `json:"valid"`
			Resource map[string]any `json:"resource"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if !vector.Valid {
			continue
		}
		kind, _ := vector.Resource["kind"].(string)
		switch kind {
		case "route":
			host, _ := vector.Resource["host_match"].(map[string]any)
			origin, _ := vector.Resource["origin"].(map[string]any)
			if host["type"] == "one_label_wildcard" && (host["wildcard_labels"] != float64(1) || origin["preserve_host"] != true) {
				t.Fatalf("%s: unsafe wildcard or Host forwarding contract", vector.Case)
			}
			seen[kind] = true
		case "domain_binding":
			if vector.Resource["wildcard_labels"] != float64(1) {
				t.Fatalf("%s: domain wildcard must match exactly one label", vector.Case)
			}
			seen[kind] = true
		case "connector":
			if vector.Resource["id"] == vector.Resource["tunnel_id"] || vector.Resource["credential_reference"] == "" {
				t.Fatalf("%s: connector and durable tunnel identity are conflated", vector.Case)
			}
			seen[kind] = true
		case "health":
			dimensions, _ := vector.Resource["dimensions"].(map[string]any)
			for _, name := range []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"} {
				if _, ok := dimensions[name]; !ok {
					t.Fatalf("%s: missing health dimension %q", vector.Case, name)
				}
			}
			seen[kind] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"route", "domain_binding", "connector", "health"} {
		if !seen[kind] {
			t.Errorf("missing edge contract vector %q", kind)
		}
	}
}
