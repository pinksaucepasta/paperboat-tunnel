package main

import (
	"os"
	"testing"
)

func TestGenerateIsDeterministicAndInventoriesArtifacts(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	artifacts := []artifact{{"paperboat-tunnel", executable, "test", "MIT", "NOASSERTION"}, {"frps", executable, "test", "Apache-2.0", "NOASSERTION"}, {"caddy", executable, "test", "Apache-2.0", "NOASSERTION"}, {"paperboat-fake-control", executable, "test", "MIT", "NOASSERTION"}}
	first, err := generate(artifacts, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate(artifacts, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if first.Namespace != second.Namespace || first.SPDXVersion != "SPDX-2.3" || len(first.Files) != 4 || len(first.Packages) < 4 || len(first.Relationships) < 8 {
		t.Fatalf("document = %+v", first)
	}
}
