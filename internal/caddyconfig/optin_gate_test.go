package caddyconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaddyValidationTargetRequiresUnambiguousOptIn(t *testing.T) {
	if target, err := caddyValidationTarget("", ""); err != nil || target != (caddyValidationSelection{}) {
		t.Fatalf("empty target = %+v, %v", target, err)
	}
	if _, err := caddyValidationTarget("/tmp/caddy", "ghcr.io/example/caddy:latest"); err == nil {
		t.Fatal("ambiguous Caddy opt-in was accepted")
	}
	for _, value := range []string{"/tmp/caddy\n", "registry/caddy image", "registry/caddy\x00image"} {
		if _, err := caddyValidationTarget("", value); err == nil {
			t.Fatalf("malformed CADDY_IMAGE %q was accepted", value)
		}
	}
}

func TestCaddyValidationTargetRequiresExecutableBinary(t *testing.T) {
	directory := t.TempDir()
	if _, err := caddyValidationTarget(filepath.Join(directory, "missing"), ""); err == nil {
		t.Fatal("missing CADDY_BIN was accepted")
	}
	nonExecutable := filepath.Join(directory, "caddy")
	if err := os.WriteFile(nonExecutable, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := caddyValidationTarget(nonExecutable, ""); err == nil {
		t.Fatal("non-executable CADDY_BIN was accepted")
	}
	executable := filepath.Join(directory, "caddy-executable")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target, err := caddyValidationTarget(executable, "")
	if err != nil || target.binary != executable || target.image != "" {
		t.Fatalf("executable target = %+v, %v", target, err)
	}
}
