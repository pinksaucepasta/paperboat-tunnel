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
	return Input{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", PrivateUpstream: "127.0.0.1:8080", ListenAddress: ":443", HTTPListenAddress: ":80", AdminAddress: "127.0.0.1:2019", TrustedProxies: []string{"10.0.0.0/8", "fd00::/8"}, IssuerModule: "internal", CertificateAskURL: "http://127.0.0.1:8080/private/certificate-ask", StreamBrokerPath: "/run/paperboat/frps-stream.sock"}
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
	quicApp := apps["paperboat_quic"].(map[string]any)
	if quicApp["listen"] != ":443" || quicApp["http_server"] != "paperboat_public" || quicApp["broker_socket"] != "/run/paperboat/frps-stream.sock" {
		t.Fatalf("native QUIC app = %v", quicApp)
	}
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	automation := apps["tls"].(map[string]any)["automation"].(map[string]any)
	permission := automation["on_demand"].(map[string]any)["permission"].(map[string]any)
	if permission["module"] != "http" || permission["endpoint"] != "http://127.0.0.1:8080/private/certificate-ask" || policies[0].(map[string]any)["on_demand"] != true {
		t.Fatalf("on-demand certificate authorization = %v %v", permission, policies[0])
	}
	subjects := policies[0].(map[string]any)["subjects"].([]any)
	if len(subjects) != 2 || subjects[0] != "*.preview.example.test" || subjects[1] != "*.helper.example.test" {
		t.Fatalf("TLS subjects = %v", subjects)
	}
	logging := document["logging"].(map[string]any)["logs"].(map[string]any)["default"].(map[string]any)
	if logging["level"] != "PANIC" {
		t.Fatalf("request-bearing Caddy logs are enabled: %v", logging)
	}
	pki := apps["pki"].(map[string]any)["certificate_authorities"].(map[string]any)["local"].(map[string]any)
	if pki["install_trust"] != false {
		t.Fatalf("private issuer installs host trust: %v", pki)
	}
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	redirect := servers["paperboat_redirect"].(map[string]any)
	if redirect["listen"].([]any)[0] != ":80" {
		t.Fatalf("HTTP redirect listener = %v", redirect)
	}
	server := servers["paperboat_public"].(map[string]any)
	protocols := server["protocols"].([]any)
	if len(protocols) != 2 || protocols[0] != "h1" || protocols[1] != "h2" {
		t.Fatalf("normal HTTP server protocols = %v", protocols)
	}
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
	if _, exists := proxy["flush_interval"]; exists {
		t.Fatal("terminal flush workaround remains configured")
	}
	if _, exists := proxy["transport"]; exists {
		t.Fatalf("global reverse-proxy transport workaround remains: %v", proxy["transport"])
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

func TestGenerateCloudflareDNSChallenge(t *testing.T) {
	input := validInput()
	input.IssuerModule = "acme"
	input.DNSProvider = "cloudflare"
	data, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"name": "cloudflare"`) || !strings.Contains(string(data), `"api_token": "{env.CLOUDFLARE_API_TOKEN}"`) {
		t.Fatalf("Cloudflare DNS challenge missing: %s", data)
	}
}

func TestGenerateExactHostPublicRoutesBeforeManagedWildcards(t *testing.T) {
	input := validInput()
	input.PublicRoutes = []PublicRoute{
		{Host: "api.example.test", PathPrefix: "/helper-releases", StripPrefix: true, Upstream: "127.0.0.1:8081"},
		{Host: "api.example.test", Upstream: "127.0.0.1:8082"},
	}
	data, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	apps := document["apps"].(map[string]any)
	routes := apps["http"].(map[string]any)["servers"].(map[string]any)["paperboat_public"].(map[string]any)["routes"].([]any)
	if len(routes) != 3 {
		t.Fatalf("routes = %v", routes)
	}
	first := routes[0].(map[string]any)
	match := first["match"].([]any)[0].(map[string]any)
	if match["host"].([]any)[0] != "api.example.test" || match["path"].([]any)[0] != "/helper-releases/*" {
		t.Fatalf("first route match = %v", match)
	}
	handlers := first["handle"].([]any)
	if handlers[0].(map[string]any)["strip_path_prefix"] != "/helper-releases" || handlers[1].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("first route handlers = %v", handlers)
	}
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	if len(policies) != 2 || policies[1].(map[string]any)["subjects"].([]any)[0] != "api.example.test" {
		t.Fatalf("exact-host TLS policy = %v", policies)
	}
	if _, exists := policies[1].(map[string]any)["on_demand"]; exists {
		t.Fatal("exact-host certificates unexpectedly depend on dynamic route authorization")
	}
}

func TestGenerateAcceptsPrivateServiceRouteUpstream(t *testing.T) {
	input := validInput()
	input.PublicRoutes = []PublicRoute{{Host: "api.example.test", Upstream: "server:8080"}}
	if _, err := Generate(input); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsHostConfusionAndPublicAdmin(t *testing.T) {
	tests := []Input{
		func() Input { i := validInput(); i.PreviewBaseDomain = "*.preview.example.test"; return i }(),
		func() Input { i := validInput(); i.HelperBaseDomain = "127.0.0.1"; return i }(),
		func() Input { i := validInput(); i.PreviewBaseDomain = "Preview.example.test"; return i }(),
		func() Input { i := validInput(); i.HelperBaseDomain = i.PreviewBaseDomain; return i }(),
		func() Input { i := validInput(); i.HelperBaseDomain = "internal." + i.PreviewBaseDomain; return i }(),
		func() Input { i := validInput(); i.AdminAddress = "0.0.0.0:2019"; return i }(),
		func() Input { i := validInput(); i.PrivateUpstream = "0.0.0.0:8080"; return i }(),
		func() Input { i := validInput(); i.TrustedProxies = []string{"not-a-cidr"}; return i }(),
		func() Input {
			i := validInput()
			i.PublicRoutes = []PublicRoute{{Host: "x.preview.example.test", Upstream: "127.0.0.1:8080"}}
			return i
		}(),
		func() Input {
			i := validInput()
			i.PublicRoutes = []PublicRoute{{Host: "api.example.test", Upstream: "8.8.8.8:80"}}
			return i
		}(),
		func() Input {
			i := validInput()
			i.PublicRoutes = []PublicRoute{{Host: "api.example.test", StripPrefix: true, Upstream: "127.0.0.1:8080"}}
			return i
		}(),
	}
	for _, input := range tests {
		if _, err := Generate(input); err == nil || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrPublicAdmin)) {
			t.Fatalf("input accepted: %+v, err=%v", input, err)
		}
	}
}

func TestGeneratedConfigPassesNativeCaddy(t *testing.T) {
	binary := os.Getenv("CADDY_BIN")
	image := os.Getenv("CADDY_IMAGE")
	if binary == "" && image == "" {
		t.Skip("CADDY_BIN or CADDY_IMAGE not set")
	}
	cloudflare := validInput()
	cloudflare.IssuerModule, cloudflare.DNSProvider = "acme", "cloudflare"
	for _, input := range []Input{validInput(), cloudflare} {
		data, err := Generate(input)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "caddy.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		var command *exec.Cmd
		if image != "" {
			command = exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/local/bin/caddy", "-e", "CLOUDFLARE_API_TOKEN=0123456789abcdef0123456789abcdef01234567", "-v", filepath.Dir(path)+":/test-config:ro", image, "validate", "--config", "/test-config/caddy.json")
		} else {
			command = exec.Command(binary, "validate", "--config", path)
			command.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(t.TempDir(), "data"), "XDG_CONFIG_HOME="+filepath.Join(t.TempDir(), "config"), "CLOUDFLARE_API_TOKEN=0123456789abcdef0123456789abcdef01234567")
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("caddy rejected generated config: %v\n%s", err, output)
		}
	}
}
