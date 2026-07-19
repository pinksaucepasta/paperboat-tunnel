package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/frpconfig"
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
	return BundleSpec{Directory: filepath.Join(directory, "config"), FRPSBinary: binary, CaddyBinary: binary, FRPSSHA256: checksum, CaddySHA256: checksum, MaxOutputBytes: 1024,
		FRPS:  frpconfig.Input{BindAddr: "127.0.0.1", BindPort: 7000, QUICBindPort: 7001, PrivateProxyAddr: "127.0.0.1", VhostHTTPPort: 8080, HookAddr: "127.0.0.1:19000", HookPath: "/paperboat/hook/0123456789abcdef", InternalAuthToken: "internal-token-012345678901234567890123456789"},
		Caddy: caddyconfig.Input{WildcardHost: "*.preview.example.test", PrivateUpstream: "127.0.0.1:8080", ListenAddress: ":443", AdminAddress: "127.0.0.1:2019", TrustedProxies: []string{"10.0.0.0/8"}, IssuerModule: "internal"}}
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
	for _, path := range []string{bundle.FRPSConfigPath, bundle.CaddyConfigPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	args := strings.Join(append(bundle.FRPSProcess.Args, bundle.CaddyProcess.Args...), " ")
	if strings.Contains(args, spec.FRPS.InternalAuthToken) || strings.Contains(args, spec.FRPS.HookPath) {
		t.Fatalf("secret appears in argv: %s", args)
	}
	if bundle.FRPSMetadata.ConfigSHA256 == "" {
		t.Fatal("frps provenance missing")
	}
	if bundle.CaddyMetadata.Version != caddyconfig.CaddyVersion || bundle.CaddyMetadata.Commit != caddyconfig.CaddyCommit || bundle.CaddyMetadata.LinuxAMD64SHA256 != caddyconfig.CaddyLinuxAMD64SHA256 || bundle.CaddyMetadata.LinuxARM64SHA256 != caddyconfig.CaddyLinuxARM64SHA256 || bundle.CaddyMetadata.MacARM64SHA256 != caddyconfig.CaddyMacARM64SHA256 {
		t.Fatalf("Caddy provenance missing: %+v", bundle.CaddyMetadata)
	}
	second, err := PrepareBundle(spec)
	if err != nil || second.FRPSMetadata != bundle.FRPSMetadata {
		t.Fatalf("bundle is not deterministic: %+v, %v", second, err)
	}
}

func TestPrepareBundleRejectsUnsafeArtifacts(t *testing.T) {
	spec := bundleSpec(t)
	nonExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	spec.FRPSBinary = nonExecutable
	if _, err := PrepareBundle(spec); err == nil {
		t.Fatal("non-executable artifact accepted")
	}
	spec = bundleSpec(t)
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(spec.FRPSBinary, symlink); err != nil {
		t.Fatal(err)
	}
	spec.CaddyBinary = symlink
	if _, err := PrepareBundle(spec); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}
