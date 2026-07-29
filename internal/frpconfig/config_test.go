package frpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func validInput() Input {
	return Input{BindAddr: "0.0.0.0", BindPort: 7000, QUICBindPort: 7001, PrivateProxyAddr: "127.0.0.1", VhostHTTPPort: 8080, HookAddr: "127.0.0.1:19000", HookPath: "/paperboat/hook/0123456789abcdef", StreamBrokerPath: "/run/paperboat/frps-stream.sock", InternalAuthToken: "internal-token-012345678901234567890123456789"}
}

func TestGenerateIsDeterministicAndRestrictive(t *testing.T) {
	first, metadata, err := Generate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	second, metadata2, err := Generate(validInput())
	if err != nil || !bytes.Equal(first, second) || metadata != metadata2 {
		t.Fatalf("not deterministic")
	}
	var decoded map[string]any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["vhostHTTPSPort"].(float64) != 0 || decoded["tcpmuxHTTPConnectPort"].(float64) != 0 || decoded["kcpBindPort"].(float64) != 0 || decoded["enablePrometheus"].(bool) {
		t.Fatalf("unsafe surfaces enabled: %s", first)
	}
	if decoded["vhostHTTPPreserveXForwardedProto"] != true {
		t.Fatalf("trusted public scheme is not preserved: %s", first)
	}
	if decoded["paperboatStreamBrokerPath"] != "/run/paperboat/frps-stream.sock" {
		t.Fatalf("private stream broker is not configured: %s", first)
	}
	if _, present := decoded["vhostHTTPDisableKeepAlives"]; present {
		t.Fatalf("global keepalive disabling is configured: %s", first)
	}
	plugins := decoded["httpPlugins"].([]any)
	ops := plugins[0].(map[string]any)["ops"].([]any)
	if ops[len(ops)-1] != "Traffic" {
		t.Fatalf("asynchronous traffic reporting is not configured: %s", first)
	}
	logConfig, ok := decoded["log"].(map[string]any)
	if !ok || logConfig["to"] != "console" || logConfig["level"] != "error" || logConfig["disablePrintColor"] != true {
		t.Fatalf("unsafe child logging: %s", first)
	}
	if metadata.ConfigSHA256 == "" || metadata.FRPCommit != FRPCommit {
		t.Fatalf("metadata = %+v", metadata)
	}
}

func TestGenerateRejectsUnsafeListenersAndSecrets(t *testing.T) {
	tests := []Input{
		func() Input { i := validInput(); i.PrivateProxyAddr = "0.0.0.0"; return i }(),
		func() Input { i := validInput(); i.HookAddr = "0.0.0.0:19000"; return i }(),
		func() Input { i := validInput(); i.HookPath = "/short"; return i }(),
		func() Input { i := validInput(); i.InternalAuthToken = "short"; return i }(),
		func() Input { i := validInput(); i.LogLevel = "debug"; return i }(),
		func() Input { i := validInput(); i.TCPMuxHTTPPortForTest(); return i }(),
	}
	for _, input := range tests {
		if _, _, err := Generate(input); err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("input accepted: %+v, err=%v", input, err)
		}
	}
}

func TestGenerateAllowsPrivateBridgeVhost(t *testing.T) {
	input := validInput()
	input.PrivateProxyAddr = "172.20.0.1"
	if _, _, err := Generate(input); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateAllowsDedicatedTCPWorkConnections(t *testing.T) {
	input := validInput()
	disabled := false
	input.TCPMux = &disabled
	encoded, _, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"tcpMux": false`)) {
		t.Fatalf("tcpMux is not disabled: %s", encoded)
	}
}

func TestGeneratedConfigPassesPinnedFrpsVerifier(t *testing.T) {
	frps := filepath.Join("..", "..", "bin", "frps")
	if _, err := os.Stat(frps); err != nil {
		t.Skip("local frps artifact is not built")
	}
	config, _, err := Generate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "frps.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(frps, "verify", "--config", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("frps rejected generated config: %v\n%s", err, output)
	}
}

// Keeps the excluded-listener test explicit without adding an exposed production field.
func (i *Input) TCPMuxHTTPPortForTest() { i.BindPort = 0 }
