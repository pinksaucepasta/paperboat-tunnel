package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRequiresPrivateCompleteFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	body := `{"control_url":"https://control.test","control_credential":"` + strings.Repeat("x", 32) + `","control_ca_file":"/tmp/ca.pem","edge_node_id":"edge_1","edge_pool":"default","process_epoch":"epoch_1","environment_id":"env_1","machine_id":"machine_1","connector_id":"runtime","connector_generation":1,"route_id":"route_1","route_revision":1,"usage_key_id":"key_1","usage_seed_base64url":"seed","counter_epoch":"counter_1","usage_operation_id":"op_usage_1","expected_revoked_key_id":"revoked_1","now":"2026-07-20T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("public conformance config accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigRejectsDuplicateKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	body := `{"control_url":"https://control.test","control_url":"https://attacker.test"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("duplicate config key accepted")
	}
}
