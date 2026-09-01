package caddyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validInput() Input {
	return Input{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", SignalingHost: "signal.example.test", PrivateUpstream: "127.0.0.1:8080", ListenAddress: ":443", PrivateAccessListenAddress: "127.0.0.1:9443", PrivateAccessToken: "private-access-token-0123456789abcdef", HTTPListenAddress: ":80", AdminAddress: "127.0.0.1:2019", TrustedProxies: []string{"10.0.0.0/8", "fd00::/8"}, IssuerModule: "internal", StreamBrokerPath: "/run/paperboat/frps-stream.sock"}
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
	if strings.Contains(string(data), "/v1/public-preview-relay") {
		t.Fatalf("obsolete public preview relay route remains: %s", data)
	}
	if strings.Contains(string(data), "0.0.0.0:2019") || strings.Contains(string(data), "X-Forwarded-For\"") && !strings.Contains(string(data), "delete") {
		t.Fatalf("unsafe policy: %s", data)
	}
	apps := document["apps"].(map[string]any)
	quicApp := apps["paperboat_quic"].(map[string]any)
	if quicApp["listen"] != ":443" || quicApp["http_server"] != "paperboat_public" || quicApp["broker_socket"] != "/run/paperboat/frps-stream.sock" {
		t.Fatalf("native QUIC app = %v", quicApp)
	}
	if quicApp["max_streams_per_connection"].(float64) != 3 || quicApp["max_http3_streams_per_connection"].(float64) != 64 {
		t.Fatalf("QUIC stream limits=%v", quicApp)
	}
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	automation := apps["tls"].(map[string]any)["automation"].(map[string]any)
	if _, exists := automation["on_demand"]; exists {
		t.Fatalf("unconfigured edge on-demand certificate authorization = %v", automation["on_demand"])
	}
	if len(policies) != 1 || policies[0].(map[string]any)["subjects"].([]any)[0] != "signal.example.test" {
		t.Fatalf("TLS signaling policy = %v", policies)
	}
	wildcardRoutes := apps["http"].(map[string]any)["servers"].(map[string]any)["paperboat_public"].(map[string]any)["routes"].([]any)
	wildcardRoute := wildcardRoutes[4].(map[string]any)
	wildcardMatch := wildcardRoute["match"].([]any)[0].(map[string]any)
	wantWildcardHosts := []any{"*.preview.example.test", "*.tunnels.example.test", "*.runtime.example.test"}
	if got := wildcardMatch["host"].([]any); !reflect.DeepEqual(got, wantWildcardHosts) {
		t.Fatalf("HTTPS wildcard host matcher = %v, want %v", got, wantWildcardHosts)
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
	probeRoute := routes[0].(map[string]any)
	probeMatch := probeRoute["match"].([]any)[0].(map[string]any)
	if probeMatch["path"].([]any)[0] != "/network-check/v1" || probeMatch["method"].([]any)[0] != "GET" {
		t.Fatalf("network check route = %v", probeRoute)
	}
	route := routes[1].(map[string]any)
	match := route["match"].([]any)[0].(map[string]any)
	paths := match["path"].([]any)
	if len(paths) != 1 || paths[0] != "/v1/peer-relay" {
		t.Fatalf("peer service paths = %v", paths)
	}
	handlers := route["handle"].([]any)
	relayHeaders := handlers[0].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
	marker := relayHeaders["X-Paperboat-Relay-Carrier"].([]any)
	if len(marker) != 1 || marker[0] != "{http.request.proto}" {
		t.Fatalf("relay carrier marker=%v", marker)
	}
	proxy := handlers[1].(map[string]any)
	if proxy["flush_interval"].(float64) != -1 {
		t.Fatalf("peer relay is not configured for immediate duplex flushing: %v", proxy["flush_interval"])
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
	privateServer := servers["paperboat_private_access"].(map[string]any)
	if privateServer["listen"].([]any)[0] != "127.0.0.1:9443" {
		t.Fatalf("private access listener = %v", privateServer["listen"])
	}
	privateProxy := privateServer["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	privateHeaders := privateProxy["headers"].(map[string]any)["request"].(map[string]any)
	privateToken := privateHeaders["set"].(map[string]any)["X-Paperboat-Private-Carrier"].([]any)
	if len(privateToken) != 1 || privateToken[0] != "private-access-token-0123456789abcdef" {
		t.Fatalf("private carrier token = %v", privateToken)
	}
	publicDeleted := requestHeaders["delete"].([]any)
	privateMarkerDeleted := false
	for _, value := range publicDeleted {
		if value == "X-Paperboat-Private-Carrier" {
			privateMarkerDeleted = true
		}
	}
	if !privateMarkerDeleted {
		t.Fatal("public listener does not strip spoofed private carrier marker")
	}
}

func TestGenerateUsesBrokerAsSoleManagedCertificateSource(t *testing.T) {
	input := validInput()
	input.CertificateBrokerSocket = "/tmp/paperboat-certificate.sock"
	input.PublicRoutes = []PublicRoute{{Host: "api.example.test", Upstream: "127.0.0.1:8081"}}
	data, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	automation := document["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)
	if _, exists := automation["on_demand"]; exists {
		t.Fatal("broker mode retained on-demand certificate permission")
	}
	policies := automation["policies"].([]any)
	if len(policies) != 4 {
		t.Fatalf("broker policies = %v", policies)
	}
	wantWildcardSubjects := []any{"*.preview.example.test", "*.tunnels.example.test", "*.runtime.example.test"}
	wildcardPolicy := policies[0].(map[string]any)
	if got := wildcardPolicy["subjects"].([]any); !reflect.DeepEqual(got, wantWildcardSubjects) {
		t.Fatalf("broker wildcard TLS subjects = %v, want %v", got, wantWildcardSubjects)
	}
	if _, exists := wildcardPolicy["issuers"]; exists {
		t.Fatalf("managed wildcard policy retained issuer fallback: %v", wildcardPolicy)
	}
	if _, exists := wildcardPolicy["on_demand"]; exists {
		t.Fatalf("managed wildcard policy retained on-demand fallback: %v", wildcardPolicy)
	}
	for _, raw := range policies {
		policy := raw.(map[string]any)
		subjects, hasSubjects := policy["subjects"].([]any)
		if !hasSubjects {
			if _, exists := policy["issuers"]; exists {
				t.Fatalf("dynamic catch-all retained issuer fallback: %v", policy)
			}
			if _, exists := policy["on_demand"]; exists {
				t.Fatalf("dynamic catch-all retained on-demand fallback: %v", policy)
			}
			getCertificate := policy["get_certificate"].([]any)
			if len(getCertificate) != 1 || getCertificate[0].(map[string]any)["via"] != "paperboat" {
				t.Fatalf("dynamic catch-all broker = %v", policy)
			}
			continue
		}
		if len(subjects) > 0 && subjects[0] == "api.example.test" {
			issuers := policy["issuers"].([]any)
			if len(issuers) != 1 || issuers[0].(map[string]any)["module"] != input.IssuerModule {
				t.Fatalf("infrastructure route issuer = %v", policy)
			}
			if _, exists := policy["get_certificate"]; exists {
				t.Fatalf("infrastructure route incorrectly depends on managed broker: %v", policy)
			}
			continue
		}
		managed := len(subjects) > 0 && (subjects[0] == "*.preview.example.test" || subjects[0] == "*.tunnels.example.test" || subjects[0] == "*.runtime.example.test")
		if !managed {
			continue
		}
		if _, exists := policy["issuers"]; exists {
			t.Fatalf("managed policy retained issuer fallback: %v", policy)
		}
		if _, exists := policy["on_demand"]; exists {
			t.Fatalf("managed policy retained on-demand fallback: %v", policy)
		}
		getCertificate := policy["get_certificate"].([]any)
		if len(getCertificate) != 1 || getCertificate[0].(map[string]any)["via"] != "paperboat" || getCertificate[0].(map[string]any)["socket"] != input.CertificateBrokerSocket {
			t.Fatalf("managed policy broker = %v", policy)
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

func TestGenerateNeverEmitsEdgeDNSCredentialsOrOnDemandFallback(t *testing.T) {
	input := validInput()
	input.IssuerModule = "acme"
	data, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "CLOUDFLARE_API_TOKEN") || strings.Contains(string(data), "certificate-ask") || strings.Contains(string(data), "on_demand") {
		t.Fatalf("edge certificate fallback or DNS credential remained: %s", data)
	}
}

func TestGenerateExactHostPublicRoutesBeforeManagedWildcards(t *testing.T) {
	input := validInput()
	input.CertificateBrokerSocket = "/tmp/paperboat-certificate.sock"
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
	if len(routes) != 9 {
		t.Fatalf("routes = %v", routes)
	}
	first := routes[4].(map[string]any)
	match := first["match"].([]any)[0].(map[string]any)
	paths := match["path"].([]any)
	if match["host"].([]any)[0] != "api.example.test" || len(paths) != 2 || paths[0] != "/helper-releases" || paths[1] != "/helper-releases/*" {
		t.Fatalf("first route match = %v", match)
	}
	handlers := first["handle"].([]any)
	if handlers[0].(map[string]any)["strip_path_prefix"] != "/helper-releases" || handlers[1].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("first route handlers = %v", handlers)
	}
	reject := routes[6].(map[string]any)
	if reject["handle"].([]any)[0].(map[string]any)["status_code"].(float64) != 404 {
		t.Fatalf("static-host fallback = %v", reject)
	}
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	if len(policies) != 4 || policies[1].(map[string]any)["subjects"].([]any)[0] != "api.example.test" || policies[2].(map[string]any)["subjects"].([]any)[0] != "signal.example.test" {
		t.Fatalf("exact-host TLS policy = %v", policies)
	}
	if _, exists := policies[3].(map[string]any)["subjects"]; exists {
		t.Fatalf("dynamic TLS catch-all unexpectedly constrained to static subjects: %v", policies[3])
	}
	if _, exists := policies[2].(map[string]any)["on_demand"]; exists {
		t.Fatal("exact-host certificates unexpectedly depend on dynamic route authorization")
	}
}

func TestGenerateIsolatesPeerSignalingHost(t *testing.T) {
	data, err := Generate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	routes := document["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["paperboat_public"].(map[string]any)["routes"].([]any)
	if len(routes) != 6 {
		t.Fatalf("routes = %v", routes)
	}
	probe := routes[0].(map[string]any)
	probeMatch := probe["match"].([]any)[0].(map[string]any)
	if probeMatch["path"].([]any)[0] != "/network-check/v1" || probeMatch["method"].([]any)[0] != "GET" {
		t.Fatalf("network-check route = %v", probe)
	}
	exact := routes[2].(map[string]any)
	match := exact["match"].([]any)[0].(map[string]any)
	if match["host"].([]any)[0] != "signal.example.test" || match["path"].([]any)[0] != "/v1/peer-signaling" || exact["handle"].([]any)[1].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("signaling route = %v", exact)
	}
	catchAll := routes[3].(map[string]any)
	if catchAll["match"].([]any)[0].(map[string]any)["host"].([]any)[0] != "signal.example.test" || catchAll["handle"].([]any)[0].(map[string]any)["status_code"].(float64) != 404 {
		t.Fatalf("signaling catch-all = %v", catchAll)
	}
	dynamic := routes[5].(map[string]any)
	if _, exists := dynamic["match"]; exists || !dynamic["terminal"].(bool) || dynamic["handle"].([]any)[0].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("dynamic host catch-all = %v", dynamic)
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
		func() Input { i := validInput(); i.TunnelBaseDomain = "127.0.0.1"; return i }(),
		func() Input { i := validInput(); i.PreviewBaseDomain = "Preview.example.test"; return i }(),
		func() Input { i := validInput(); i.TunnelBaseDomain = i.PreviewBaseDomain; return i }(),
		func() Input { i := validInput(); i.TunnelBaseDomain = "internal." + i.PreviewBaseDomain; return i }(),
		func() Input { i := validInput(); i.SignalingHost = "SIGNAL.example.test"; return i }(),
		func() Input { i := validInput(); i.SignalingHost = "x." + i.PreviewBaseDomain; return i }(),
		func() Input {
			i := validInput()
			i.PublicRoutes = []PublicRoute{{Host: i.SignalingHost, Upstream: "127.0.0.1:8080"}}
			return i
		}(),
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
	target, err := caddyValidationTarget(os.Getenv("CADDY_BIN"), os.Getenv("CADDY_IMAGE"))
	if err != nil {
		t.Fatal(err)
	}
	if target.binary == "" && target.image == "" {
		t.Skip("CADDY_BIN or CADDY_IMAGE not set")
	}
	if target.image != "" {
		if _, err := exec.LookPath("docker"); err != nil {
			t.Fatalf("CADDY_IMAGE is enabled but docker is unavailable: %v", err)
		}
	}
	for _, input := range []Input{validInput()} {
		data, err := Generate(input)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "caddy.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		var command *exec.Cmd
		if target.image != "" {
			command = exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/local/bin/caddy", "-v", filepath.Dir(path)+":/test-config:ro", target.image, "validate", "--config", "/test-config/caddy.json")
		} else {
			command = exec.Command(target.binary, "validate", "--config", path)
			command.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(t.TempDir(), "data"), "XDG_CONFIG_HOME="+filepath.Join(t.TempDir(), "config"))
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("caddy rejected generated config: %v\n%s", err, output)
		}
	}
}

type caddyValidationSelection struct {
	binary string
	image  string
}

// caddyValidationTarget keeps the optional native-Caddy gate explicit. An
// ambiguous or malformed opt-in must fail the test rather than silently
// selecting one value or falling back to the ordinary unit suite.
func caddyValidationTarget(binary, image string) (caddyValidationSelection, error) {
	if binary != "" && strings.TrimSpace(binary) != binary || image != "" && strings.TrimSpace(image) != image {
		return caddyValidationSelection{}, errors.New("CADDY_BIN and CADDY_IMAGE must not contain surrounding whitespace")
	}
	if binary != "" && image != "" {
		return caddyValidationSelection{}, errors.New("set exactly one of CADDY_BIN or CADDY_IMAGE")
	}
	if binary == "" && image == "" {
		return caddyValidationSelection{}, nil
	}
	value := binary
	name := "CADDY_BIN"
	if image != "" {
		value = image
		name = "CADDY_IMAGE"
	}
	if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") || strings.IndexFunc(value, func(r rune) bool { return r == ' ' || r == '\t' }) >= 0 {
		return caddyValidationSelection{}, fmt.Errorf("%s is malformed", name)
	}
	if binary != "" {
		info, err := os.Stat(binary)
		if err != nil {
			return caddyValidationSelection{}, fmt.Errorf("CADDY_BIN is unavailable: %w", err)
		}
		if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			return caddyValidationSelection{}, errors.New("CADDY_BIN must name an executable file")
		}
		return caddyValidationSelection{binary: binary}, nil
	}
	return caddyValidationSelection{image: image}, nil
}
