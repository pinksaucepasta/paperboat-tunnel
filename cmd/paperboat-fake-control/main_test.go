package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateConfigurationLoading(t *testing.T) {
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential")
	if err := os.WriteFile(credentialPath, []byte("01234567890123456789012345678901\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if credential, err := readPrivateCredential(credentialPath); err != nil || len(credential) != 32 {
		t.Fatalf("credential = %q, %v", credential, err)
	}
	seedPath := filepath.Join(directory, "seed.json")
	data := `{"assignments":[{"environment_id":"env","helper_id":"helper","connector_generation":1,"edge_pool":"default","edge_node_id":"edge","revoked":false}],"routes":[]}`
	if err := os.WriteFile(seedPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := readSeed(seedPath)
	if err != nil || len(value.Assignments) != 1 {
		t.Fatalf("seed = %+v, %v", value, err)
	}
}

func TestRejectsUnsafeFakeControlConfiguration(t *testing.T) {
	for _, address := range []string{"0.0.0.0:18081", "localhost:18081", "127.0.0.1:0", ":18081"} {
		if validateLoopback(address) == nil {
			t.Fatalf("address %q accepted", address)
		}
	}
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential")
	if err := os.WriteFile(credentialPath, []byte("01234567890123456789012345678901"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCredential(credentialPath); err == nil {
		t.Fatal("public credential file accepted")
	}
	seedPath := filepath.Join(directory, "seed.json")
	if err := os.WriteFile(seedPath, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeed(seedPath); err == nil {
		t.Fatal("unknown seed field accepted")
	}
}
