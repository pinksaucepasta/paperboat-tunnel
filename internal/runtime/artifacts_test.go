package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
)

func bundleSpec(t *testing.T) BundleSpec {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "artifact")
	if err := os.WriteFile(binary, []byte("artifact"), 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("artifact"))
	checksum := hex.EncodeToString(digest[:])
	return BundleSpec{Directory: filepath.Join(directory, "config"), CaddyBinary: binary, CaddySHA256: checksum, MaxOutputBytes: 1024,
		Caddy: caddyconfig.Input{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", SignalingHost: "signal.example.test", PrivateUpstream: "127.0.0.1:8080", ListenAddress: ":443", PrivateAccessListenAddress: "127.0.0.1:9443", PrivateAccessToken: "private-access-token-0123456789abcdef", HTTPListenAddress: ":80", AdminAddress: "127.0.0.1:2019", TrustedProxies: []string{"10.0.0.0/8"}, IssuerModule: "internal"}}
}

func TestPrepareBundleRejectsChecksumMismatch(t *testing.T) {
	spec := bundleSpec(t)
	spec.CaddySHA256 = strings.Repeat("0", 64)
	if _, err := PrepareBundle(spec); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
}

func TestPrepareBundleWritesPrivateConfigsAndSecretFreeArguments(t *testing.T) {
	spec := bundleSpec(t)
	bundle, err := PrepareBundle(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bundle.CaddyConfigPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	if bundle.CaddyMetadata.Version != caddyconfig.CaddyVersion || bundle.CaddyMetadata.Commit != caddyconfig.CaddyCommit || bundle.CaddyMetadata.LinuxAMD64SHA256 != caddyconfig.CaddyLinuxAMD64SHA256 || bundle.CaddyMetadata.LinuxARM64SHA256 != caddyconfig.CaddyLinuxARM64SHA256 || bundle.CaddyMetadata.MacARM64SHA256 != caddyconfig.CaddyMacARM64SHA256 {
		t.Fatalf("Caddy provenance missing: %+v", bundle.CaddyMetadata)
	}
	caddyConfig, err := os.ReadFile(bundle.CaddyConfigPath)
	if err != nil || !strings.Contains(string(caddyConfig), `"signal.example.test"`) || !strings.Contains(string(caddyConfig), `"/v1/peer-signaling"`) {
		t.Fatalf("peer signaling route missing: %v", err)
	}
	second, err := PrepareBundle(spec)
	if err != nil || second.CaddyMetadata != bundle.CaddyMetadata {
		t.Fatalf("bundle is not deterministic: %+v, %v", second, err)
	}
}

func TestPrepareBundleRejectsUnsafeArtifacts(t *testing.T) {
	spec := bundleSpec(t)
	nonExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	spec.CaddyBinary = nonExecutable
	if _, err := PrepareBundle(spec); err == nil {
		t.Fatal("non-executable artifact accepted")
	}
	spec = bundleSpec(t)
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(spec.CaddyBinary, symlink); err != nil {
		t.Fatal(err)
	}
	spec.CaddyBinary = symlink
	if _, err := PrepareBundle(spec); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}
