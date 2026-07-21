package caddyconfig

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func validInput() Input {
	return Input{WildcardHost: "*.preview.example.test", PrivateUpstream: "127.0.0.1:8080", ListenAddress: ":443", AdminAddress: "127.0.0.1:2019", TrustedProxies: []string{"10.0.0.0/8", "fd00::/8"}, IssuerModule: "internal"}
}

func TestGenerateCaddyPolicy(t *testing.T) {
	data, err := Generate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "0.0.0.0:2019") || strings.Contains(string(data), "X-Forwarded-For\"") && !strings.Contains(string(data), "delete") {
		t.Fatalf("unsafe policy: %s", data)
	}
	apps := document["apps"].(map[string]any)
	logging := document["logging"].(map[string]any)["logs"].(map[string]any)["default"].(map[string]any)
	if logging["level"] != "PANIC" {
		t.Fatalf("request-bearing Caddy logs are enabled: %v", logging)
	}
	pki := apps["pki"].(map[string]any)["certificate_authorities"].(map[string]any)["local"].(map[string]any)
	if pki["install_trust"] != false {
		t.Fatalf("private issuer installs host trust: %v", pki)
	}
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	server := servers["paperboat_public"].(map[string]any)
	if server["trusted_proxies_strict"].(float64) != 1 {
		t.Fatal("trusted proxy strict mode disabled")
	}
	clientIPHeaders := server["client_ip_headers"].([]any)
	if len(clientIPHeaders) != 1 || clientIPHeaders[0] != "X-Forwarded-For" {
		t.Fatalf("trusted client IP source = %v", clientIPHeaders)
	}
	routes := server["routes"].([]any)
	route := routes[0].(map[string]any)
	handlers := route["handle"].([]any)
	proxy := handlers[1].(map[string]any)
	if proxy["flush_interval"].(float64) != -1 {
		t.Fatal("streaming flush disabled")
	}
	keepAlive := proxy["transport"].(map[string]any)["keep_alive"].(map[string]any)
	if keepAlive["enabled"] != false {
		t.Fatalf("Caddy may reuse stale authorized streams: %v", keepAlive)
	}
	requestHeaders := proxy["headers"].(map[string]any)["request"].(map[string]any)
	set := requestHeaders["set"].(map[string]any)
	proto := set["X-Forwarded-Proto"].([]any)
	if len(proto) != 1 || proto[0] != "https" {
		t.Fatalf("trusted public scheme is not replaced: %v", set)
	}
	if _, exists := set["X-Forwarded-For"]; exists {
		t.Fatalf("Caddy native trusted proxy chain is overridden: %v", set)
	}
	deleted := requestHeaders["delete"].([]any)
	for _, required := range []string{"Forwarded", "X-Real-IP", "X-Paperboat-Environment"} {
		found := false
		for _, value := range deleted {
			if value == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("header %s is not stripped", required)
		}
	}
	for _, value := range deleted {
		if value == "X-Forwarded-For" {
			t.Fatal("trusted proxy chain is deleted before Caddy can forward it")
		}
	}
}

func TestGenerateAcceptsPrivateUpstream(t *testing.T) {
	input := validInput()
	input.PrivateUpstream = "172.20.0.1:8080"
	if _, err := Generate(input); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
}

func TestRejectsHostConfusionAndPublicAdmin(t *testing.T) {
	tests := []Input{
		func() Input { i := validInput(); i.WildcardHost = "preview.example.test"; return i }(),
		func() Input { i := validInput(); i.WildcardHost = "*.127.0.0.1"; return i }(),
		func() Input { i := validInput(); i.AdminAddress = "0.0.0.0:2019"; return i }(),
		func() Input { i := validInput(); i.PrivateUpstream = "0.0.0.0:8080"; return i }(),
		func() Input { i := validInput(); i.TrustedProxies = []string{"not-a-cidr"}; return i }(),
	}
	for _, input := range tests {
		if _, err := Generate(input); err == nil || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrPublicAdmin)) {
			t.Fatalf("input accepted: %+v, err=%v", input, err)
		}
	}
}

func TestGeneratedConfigPassesNativeCaddy(t *testing.T) {
	binary := os.Getenv("CADDY_BIN")
	if binary == "" {
		t.Skip("CADDY_BIN not set")
	}
	data, err := Generate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "caddy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "validate", "--config", path)
	command.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(t.TempDir(), "data"), "XDG_CONFIG_HOME="+filepath.Join(t.TempDir(), "config"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("caddy rejected generated config: %v\n%s", err, output)
	}
}
