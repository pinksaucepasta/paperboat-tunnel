package caddyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid Caddy ingress configuration")
	ErrPublicAdmin = errors.New("Caddy admin must be private")
)

const (
	CaddyVersion          = "v2.11.4"
	CaddyCommit           = "e2eee6a7fce366321294c9c2a79f3146891dcbdf"
	CaddyLinuxAMD64SHA256 = "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9"
	CaddyLinuxARM64SHA256 = "52d42ae12b3462097e9868da6dfed3c9648ae12edd3b3638102312af84cb6904"
	CaddyMacARM64SHA256   = "9efb0af2d6cf09cfb5053c0e51721b9b3d4956d346234f39368d943d25a3c9a7"
)

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type Input struct {
	PreviewBaseDomain string
	HelperBaseDomain  string
	PrivateUpstream   string
	ListenAddress     string
	HTTPListenAddress string
	AdminAddress      string
	TrustedProxies    []string
	IssuerModule      string
	DNSProvider       string
	CertificateAskURL string
	StreamBrokerPath  string
	PublicRoutes      []PublicRoute
}

type PublicRoute struct {
	Host        string
	PathPrefix  string
	StripPrefix bool
	Upstream    string
}

func Generate(input Input) ([]byte, error) {
	if err := validate(input); err != nil {
		return nil, err
	}
	wildcardHosts := []string{"*." + input.PreviewBaseDomain, "*." + input.HelperBaseDomain}
	publicRoutes := make([]any, 0, len(input.PublicRoutes)+1)
	staticHosts := make([]string, 0, len(input.PublicRoutes))
	seenStaticHosts := make(map[string]struct{}, len(input.PublicRoutes))
	for _, route := range input.PublicRoutes {
		match := map[string]any{"host": []string{route.Host}}
		if route.PathPrefix != "" {
			match["path"] = []string{strings.TrimSuffix(route.PathPrefix, "/") + "/*"}
		}
		handlers := make([]any, 0, 2)
		if route.StripPrefix {
			handlers = append(handlers, map[string]any{"handler": "rewrite", "strip_path_prefix": strings.TrimSuffix(route.PathPrefix, "/")})
		}
		handlers = append(handlers, reverseProxy(route.Upstream))
		publicRoutes = append(publicRoutes, map[string]any{"match": []any{match}, "handle": handlers, "terminal": true})
		if _, exists := seenStaticHosts[route.Host]; !exists {
			seenStaticHosts[route.Host] = struct{}{}
			staticHosts = append(staticHosts, route.Host)
		}
	}
	publicRoutes = append(publicRoutes, map[string]any{
		"match": []any{map[string]any{"host": wildcardHosts}},
		"handle": []any{
			map[string]any{"handler": "headers", "response": map[string]any{"set": map[string][]string{
				"X-Content-Type-Options": {"nosniff"}, "Referrer-Policy": {"no-referrer"}, "X-Frame-Options": {"DENY"},
			}}},
			reverseProxy(input.PrivateUpstream),
		},
		"terminal": true,
	})
	config := map[string]any{
		"admin":   map[string]any{"listen": input.AdminAddress},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "PANIC"}}},
		"apps": map[string]any{
			"paperboat_quic": map[string]any{
				"listen": input.ListenAddress, "http_server": "paperboat_public", "broker_socket": input.StreamBrokerPath,
				"max_connections": 4096, "max_connections_per_ip": 32, "max_streams_per_connection": 3,
				"idle_timeout": 120_000_000_000, "handshake_timeout": 10_000_000_000,
			},
			"http": map[string]any{
				"servers": map[string]any{
					"paperboat_redirect": map[string]any{
						"listen": []string{input.HTTPListenAddress}, "protocols": []string{"h1"},
						"routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string][]string{"Location": {"https://{http.request.host}{http.request.uri}"}}}}}},
					},
					"paperboat_public": map[string]any{
						"listen":                 []string{input.ListenAddress},
						"protocols":              []string{"h1", "h2", "h3"},
						"allow_0rtt":             false,
						"automatic_https":        map[string]any{"disable_redirects": true},
						"trusted_proxies":        map[string]any{"source": "static", "ranges": input.TrustedProxies},
						"trusted_proxies_strict": 1,
						"client_ip_headers":      []string{"X-Forwarded-For"},
						"routes":                 publicRoutes,
					},
				},
			},
		},
	}
	if input.IssuerModule != "" {
		issuer := map[string]any{"module": input.IssuerModule}
		if input.DNSProvider != "" {
			issuer["challenges"] = map[string]any{"dns": map[string]any{"provider": map[string]any{"name": input.DNSProvider, "api_token": "{env.CLOUDFLARE_API_TOKEN}"}}}
		}
		policies := []any{map[string]any{"subjects": wildcardHosts, "issuers": []any{issuer}, "on_demand": true}}
		if len(staticHosts) > 0 {
			policies = append(policies, map[string]any{"subjects": staticHosts, "issuers": []any{issuer}})
		}
		config["apps"].(map[string]any)["tls"] = map[string]any{"automation": map[string]any{
			"on_demand": map[string]any{"permission": map[string]any{"module": "http", "endpoint": input.CertificateAskURL}},
			"policies":  policies,
		}}
		if input.IssuerModule == "internal" {
			config["apps"].(map[string]any)["pki"] = map[string]any{"certificate_authorities": map[string]any{"local": map[string]any{"install_trust": false}}}
		}
	}
	return json.MarshalIndent(config, "", "  ")
}

func reverseProxy(upstream string) map[string]any {
	return map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream}}, "headers": map[string]any{"request": map[string]any{"delete": []string{"Forwarded", "X-Forwarded-Host", "X-Real-IP", "X-Paperboat-Environment", "X-Paperboat-Route"}, "set": map[string][]string{"X-Forwarded-Proto": {"https"}, "X-Real-IP": {"{http.request.client_ip}"}}}}}
}

func validate(input Input) error {
	for _, baseHost := range []string{input.PreviewBaseDomain, input.HelperBaseDomain} {
		if baseHost != strings.ToLower(baseHost) || !domainPattern.MatchString(baseHost) || net.ParseIP(baseHost) != nil {
			return ErrInvalid
		}
	}
	if input.PreviewBaseDomain == input.HelperBaseDomain || strings.HasSuffix(input.PreviewBaseDomain, "."+input.HelperBaseDomain) || strings.HasSuffix(input.HelperBaseDomain, "."+input.PreviewBaseDomain) {
		return ErrInvalid
	}
	if err := validatePrivateEndpoint(input.PrivateUpstream); err != nil {
		return err
	}
	if input.ListenAddress == "" || input.HTTPListenAddress == "" || input.ListenAddress == input.HTTPListenAddress || input.AdminAddress == "" || !filepath.IsAbs(input.StreamBrokerPath) || len(input.StreamBrokerPath) > 100 {
		return ErrInvalid
	}
	ask, err := url.Parse(input.CertificateAskURL)
	if err != nil || ask.Scheme != "http" || ask.Path != "/private/certificate-ask" || ask.RawQuery != "" || ask.Fragment != "" || validateLoopbackEndpoint(ask.Host) != nil {
		return ErrInvalid
	}
	if err := validateLoopbackEndpoint(input.AdminAddress); err != nil {
		return ErrPublicAdmin
	}
	for _, proxy := range input.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return ErrInvalid
		}
	}
	seenRoutes := make(map[string]struct{}, len(input.PublicRoutes))
	for _, route := range input.PublicRoutes {
		key := route.Host + "\x00" + route.PathPrefix
		if route.Host != strings.ToLower(route.Host) || !domainPattern.MatchString(route.Host) || net.ParseIP(route.Host) != nil || strings.HasSuffix(route.Host, "."+input.PreviewBaseDomain) || strings.HasSuffix(route.Host, "."+input.HelperBaseDomain) || validatePrivateRouteEndpoint(route.Upstream) != nil {
			return ErrInvalid
		}
		if _, exists := seenRoutes[key]; exists {
			return ErrInvalid
		}
		seenRoutes[key] = struct{}{}
		if route.PathPrefix != "" && (!strings.HasPrefix(route.PathPrefix, "/") || strings.Contains(route.PathPrefix, "..") || strings.ContainsAny(route.PathPrefix, "?#")) || route.StripPrefix && route.PathPrefix == "" {
			return ErrInvalid
		}
	}
	if input.DNSProvider != "" && input.DNSProvider != "cloudflare" {
		return ErrInvalid
	}
	return nil
}

func validateLoopbackEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" || port == "0" {
		return fmt.Errorf("%w: private endpoint", ErrInvalid)
	}
	return nil
}

func validatePrivateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) || port == "" || port == "0" {
		return fmt.Errorf("%w: private endpoint", ErrInvalid)
	}
	return nil
}

func validatePrivateRouteEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || port == "" || port == "0" {
		return ErrInvalid
	}
	if net.ParseIP(host) != nil {
		return validatePrivateEndpoint(endpoint)
	}
	if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(host) {
		return ErrInvalid
	}
	return nil
}
