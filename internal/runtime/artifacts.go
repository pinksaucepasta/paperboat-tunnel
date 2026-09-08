package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
)

type BundleSpec struct {
	Directory      string
	CaddyBinary    string
	CaddySHA256    string
	Caddy          caddyconfig.Input
	MaxOutputBytes int64
}

type Bundle struct {
	CaddyConfigPath string
	CaddyMetadata   CaddyArtifactMetadata
	CaddyProcess    ProcessSpec
}

type CaddyArtifactMetadata struct{ Version, Commit, LinuxAMD64SHA256, LinuxARM64SHA256, MacARM64SHA256 string }

func PrepareBundle(spec BundleSpec) (Bundle, error) {
	if spec.Directory == "" || spec.MaxOutputBytes < 0 {
		return Bundle{}, ErrProcessInvalid
	}
	if err := validateExecutable(spec.CaddyBinary); err != nil {
		return Bundle{}, fmt.Errorf("Caddy artifact: %w", err)
	}
	if err := verifySHA256(spec.CaddyBinary, spec.CaddySHA256); err != nil {
		return Bundle{}, fmt.Errorf("Caddy artifact checksum: %w", err)
	}
	caddyData, err := caddyconfig.Generate(spec.Caddy)
	if err != nil {
		return Bundle{}, err
	}
	if err := os.MkdirAll(spec.Directory, 0700); err != nil {
		return Bundle{}, err
	}
	caddyDataDirectory := filepath.Join(spec.Directory, "caddy-data")
	caddyConfigDirectory := filepath.Join(spec.Directory, "caddy-config")
	for _, directory := range []string{caddyDataDirectory, caddyConfigDirectory} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return Bundle{}, err
		}
	}
	if err := os.Chmod(spec.Directory, 0700); err != nil {
		return Bundle{}, err
	}
	caddyPath := filepath.Join(spec.Directory, "caddy.json")
	if err := atomicConfigWrite(caddyPath, caddyData); err != nil {
		return Bundle{}, err
	}
	return Bundle{CaddyConfigPath: caddyPath, CaddyMetadata: CaddyArtifactMetadata{Version: caddyconfig.CaddyVersion, Commit: caddyconfig.CaddyCommit, LinuxAMD64SHA256: caddyconfig.CaddyLinuxAMD64SHA256, LinuxARM64SHA256: caddyconfig.CaddyLinuxARM64SHA256, MacARM64SHA256: caddyconfig.CaddyMacARM64SHA256},
		CaddyProcess: ProcessSpec{Name: "caddy", Path: spec.CaddyBinary, Args: []string{"run", "--config", caddyPath}, Env: environmentWith(os.Environ(), map[string]string{"XDG_DATA_HOME": caddyDataDirectory, "XDG_CONFIG_HOME": caddyConfigDirectory}), MaxOutputBytes: spec.MaxOutputBytes, StartupGrace: 500 * time.Millisecond, RestartLimit: 3, RestartBackoff: 250 * time.Millisecond, RestartMaxWait: 2 * time.Second}}, nil
}

func environmentWith(current []string, values map[string]string) []string {
	result := make([]string, 0, len(current)+len(values))
	for _, item := range current {
		name, _, _ := strings.Cut(item, "=")
		if _, replace := values[name]; !replace {
			result = append(result, item)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func verifySHA256(path, expected string) error {
	if expected == "" {
		return nil
	}
	if len(expected) != sha256.Size*2 {
		return ErrProcessInvalid
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return ErrProcessInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return ErrProcessInvalid
	}
	return nil
}

func validateExecutable(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return ErrProcessInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 {
		return ErrProcessInvalid
	}
	return nil
}

func atomicConfigWrite(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
