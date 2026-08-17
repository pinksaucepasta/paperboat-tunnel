package config

import (
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

func TestParseRestrictiveConfiguration(t *testing.T) {
	cfg, err := Parse([]string{"--node-id=edge_test_01", "--health-address=127.0.0.1:19090"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeID != "edge_test_01" || cfg.EdgePool != "default" || cfg.RelayID != "edge_test_01" || cfg.RelayRegion != "default" || cfg.RelayName != "default" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseExplicitRelayMetadata(t *testing.T) {
	cfg, err := Parse([]string{"--node-id=pprbt-mumbai", "--edge-pool=default", "--relay-id=pprbt-mumbai", "--relay-region=mumbai", "--relay-name= Mumbai "})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RelayID != "pprbt-mumbai" || cfg.RelayRegion != "mumbai" || cfg.RelayName != "Mumbai" {
		t.Fatalf("unexpected relay metadata: %+v", cfg)
	}
}

func TestParseRejectsUnsafeConfiguration(t *testing.T) {
	tests := [][]string{
		{},
		{"--node-id=edge_test_01", "--health-address=0.0.0.0:9090"},
		{"--node-id=edge_test_01", "--health-address=localhost:9090"},
		{"--node-id=edge_test_01", "--shutdown-timeout=0"},
		{"--node-id=edge_test_01", "--relay-region=Not-A-Region"},
		{"--node-id=edge_test_01", "--relay-name=line\nbreak"},
		{"--node-id=edge_test_01", "positional"},
	}
	for _, args := range tests {
		_, err := Parse(args)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", args)
		}
		var typed *edgeerrors.Error
		if !errors.As(err, &typed) || typed.Code != edgeerrors.CodeConfigInvalid {
			t.Fatalf("Parse(%q) error = %v", args, err)
		}
	}
}
