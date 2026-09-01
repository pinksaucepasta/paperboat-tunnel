package edgehttp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateCaddyOptInRejectsMalformedOrUnsafePath(t *testing.T) {
	for _, path := range []string{"", " /tmp/caddy", "/tmp/caddy ", "/tmp/caddy\n", "/tmp/caddy\x00"} {
		if err := validatePrivateCaddyBinaryPath(path); err == nil {
			t.Fatalf("invalid Caddy path %q was accepted", path)
		}
	}
	directory := t.TempDir()
	if err := validatePrivateCaddyBinaryPath(directory); err == nil {
		t.Fatal("directory Caddy path was accepted")
	}
	nonExecutable := filepath.Join(directory, "caddy")
	if err := os.WriteFile(nonExecutable, []byte("caddy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateCaddyBinaryPath(nonExecutable); err == nil {
		t.Fatal("non-executable Caddy path was accepted")
	}
}
