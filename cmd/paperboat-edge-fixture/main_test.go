package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelectsTransportListener(t *testing.T) {
	for protocol, wantPort := range map[string]int{"tcp": 26022, "quic": 26023} {
		t.Run(protocol, func(t *testing.T) {
			directory := t.TempDir()
			if err := generate(directory, protocol, time.Unix(1_700_000_000, 0)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(directory, "frpc.json"))
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				ServerPort int `json:"serverPort"`
				Transport  struct {
					Protocol string `json:"protocol"`
				} `json:"transport"`
			}
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			if config.ServerPort != wantPort || config.Transport.Protocol != protocol {
				t.Fatalf("config = %+v, want port %d protocol %s", config, wantPort, protocol)
			}
		})
	}
}

func TestGenerateParameterizedLifecycleFixture(t *testing.T) {
	directory := t.TempDir()
	options := fixtureOptions{Protocol: "quic", NodeID: "edge_test_02", TCPPort: 27022, QUICPort: 27023, Generation: 7, Revision: 9, Revoked: true, IncludeRoute: false, LoseUsageAck: true}
	if err := generateFixture(directory, options, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "fake-control.seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var seed struct {
		Assignments []struct {
			Generation uint64 `json:"connector_generation"`
			Revoked    bool   `json:"revoked"`
			NodeID     string `json:"edge_node_id"`
		} `json:"assignments"`
		Routes       []any `json:"routes"`
		LoseUsageAck bool  `json:"lose_next_usage_ack"`
	}
	if err := json.Unmarshal(data, &seed); err != nil {
		t.Fatal(err)
	}
	if len(seed.Assignments) != 1 || seed.Assignments[0].Generation != 7 || seed.Assignments[0].NodeID != "edge_test_02" || !seed.Assignments[0].Revoked || len(seed.Routes) != 0 || !seed.LoseUsageAck {
		t.Fatalf("seed = %+v", seed)
	}
}
