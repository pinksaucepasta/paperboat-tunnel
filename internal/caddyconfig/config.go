package caddyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	PreviewBaseDomain          string
	TunnelBaseDomain           string
	RuntimeBaseDomain          string
	SignalingHost              string
	PrivateUpstream            string
	ListenAddress              string
	PrivateAccessListenAddress string
	PrivateAccessToken         string
	HTTPListenAddress          string
	AdminAddress               string
	TrustedProxies             []string
	IssuerModule               string
	StreamBrokerPath           string
	// CertificateBrokerSocket is the private runtime-to-Caddy certificate
	// selector. When set, Caddy never falls back to disk-backed certificates.
	CertificateBrokerSocket string
	PublicRoutes            []PublicRoute
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
	// The platform certificate worker owns exactly these two wildcard
	// families. Runtime control hosts are legacy infrastructure and are not a
	// managed durable-tunnel endpoint namespace.
	wildcardHosts := []string{"*." + input.PreviewBaseDomain, "*." + input.TunnelBaseDomain}
	publicRoutes := make([]any, 0, len(input.PublicRoutes)+1)
	staticHosts := make([]string, 0, len(input.PublicRoutes))
	seenStaticHosts := make(map[string]struct{}, len(input.PublicRoutes))
	publicRoutes = append(publicRoutes,
		map[string]any{
			"match":    []any{map[string]any{"host": []string{input.SignalingHost}, "path": []string{"/network-check/v1"}, "method": []string{"GET"}}},
			"handle":   []any{reverseProxy(input.PrivateUpstream)},
			"terminal": true,
		},
		map[string]any{
			"match": []any{map[string]any{"host": []string{input.SignalingHost}, "path": []string{"/v1/peer-relay"}}},
			"handle": []any{map[string]any{"handler": "headers", "request": map[string]any{"set": map[string][]string{"X-Paperboat-Relay-Carrier": {"{http.request.proto}"}}}, "response": map[string]any{"set": map[string][]string{
				"X-Content-Type-Options": {"nosniff"}, "Referrer-Policy": {"no-referrer"}, "X-Frame-Options": {"DENY"},
			}}}, relayReverseProxy(input.PrivateUpstream)},
			"terminal": true,
		},
		map[string]any{
			"match": []any{map[string]any{"host": []string{input.SignalingHost}, "path": []string{"/v1/peer-signaling"}}},
			"handle": []any{map[string]any{"handler": "headers", "response": map[string]any{"set": map[string][]string{
				"X-Content-Type-Options": {"nosniff"}, "Referrer-Policy": {"no-referrer"}, "X-Frame-Options": {"DENY"},
			}}}, reverseProxy(input.PrivateUpstream)},
			"terminal": true,
		},
		map[string]any{
			"match":  []any{map[string]any{"host": []string{input.SignalingHost}}},
			"handle": []any{map[string]any{"handler": "static_response", "status_code": 404}}, "terminal": true,
		},
	)
	for _, route := range input.PublicRoutes {
		match := map[string]any{"host": []string{route.Host}}
		if route.PathPrefix != "" {
			prefix := strings.TrimSuffix(route.PathPrefix, "/")
			match["path"] = []string{prefix, prefix + "/*"}
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
	if len(staticHosts) > 0 {
		publicRoutes = append(publicRoutes, map[string]any{
			"match": []any{map[string]any{"host": staticHosts}},
			"handle": []any{map[string]any{
				"handler": "static_response", "status_code": 404,
			}},
			"terminal": true,
		})
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
	// Dynamic custom domains arrive through the authenticated route-assignment
	// feed after this process starts, so they cannot be enumerated in the
	// generated host list. Leave the final route host-agnostic and let the
	// authoritative edge gateway perform the route/ownership check. Unknown
	// hosts therefore receive its generic rejection while a known dynamic host
	// can still reach the same streaming path.
	publicRoutes = append(publicRoutes, map[string]any{
		"handle":   []any{reverseProxy(input.PrivateUpstream)},
		"terminal": true,
	})
	config := map[string]any{
		"admin":   map[string]any{"listen": input.AdminAddress},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "PANIC"}}},
		"apps": map[string]any{
			"paperboat_quic": map[string]any{
				"listen": input.ListenAddress, "http_server": "paperboat_public", "broker_socket": input.StreamBrokerPath,
				"max_connections": 4096, "max_connections_per_ip": 32, "max_streams_per_connection": 3, "max_http3_streams_per_connection": 64,
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
						"protocols":              []string{"h1", "h2"},
						"allow_0rtt":             false,
						"automatic_https":        map[string]any{"disable_redirects": true},
						"trusted_proxies":        map[string]any{"source": "static", "ranges": input.TrustedProxies},
						"trusted_proxies_strict": 1,
						"client_ip_headers":      []string{"X-Forwarded-For"},
						"routes":                 publicRoutes,
					},
					"paperboat_private_access": map[string]any{
						"listen":                  []string{input.PrivateAccessListenAddress},
						"protocols":               []string{"h1", "h2"},
						"allow_0rtt":              false,
						"automatic_https":         map[string]any{"disable_redirects": true},
						"tls_connection_policies": []any{map[string]any{}},
						"routes": []any{map[string]any{
							"handle":   []any{privateAccessReverseProxy(input.PrivateUpstream, input.PrivateAccessToken)},
							"terminal": true,
						}},
					},
				},
			},
		},
	}
	if input.IssuerModule != "" || input.CertificateBrokerSocket != "" {
		issuer := map[string]any(nil)
		if input.IssuerModule != "" {
			issuer = map[string]any{"module": input.IssuerModule}
		}
		certificateManager := []any(nil)
		if input.CertificateBrokerSocket != "" {
			certificateManager = []any{map[string]any{"via": "paperboat", "socket": input.CertificateBrokerSocket}}
		}
		policies := make([]any, 0, 3)
		if certificateManager != nil {
			// User-managed wildcard and exact route certificates are served only
			// from the authenticated in-memory broker. In particular, do not
			// leave Caddy issuers, on-demand permission, or disk storage as a
			// fallback after a revoke or broker outage.
			wildcardPolicy := map[string]any{"subjects": wildcardHosts, "get_certificate": certificateManager}
			policies = append(policies, wildcardPolicy)
			if len(staticHosts) > 0 {
				// Deployment PublicRoutes are infrastructure endpoints such as the
				// control API and release service. They must remain reachable before
				// the server-managed route certificate broker has delivered any
				// preview certificate. User preview/tunnel/custom names below remain
				// broker-only and never inherit this issuer.
				if issuer != nil {
					policies = append(policies, map[string]any{"subjects": staticHosts, "issuers": []any{issuer}})
				} else {
					policies = append(policies, map[string]any{"subjects": staticHosts, "get_certificate": certificateManager})
				}
			}
			// Signaling is infrastructure-owned. It may use the explicit
			// issuer when configured, but never grants that issuer to managed
			// preview domains.
			if issuer != nil {
				policies = append(policies, map[string]any{"subjects": []string{input.SignalingHost}, "issuers": []any{issuer}})
			} else {
				policies = append(policies, map[string]any{"subjects": []string{input.SignalingHost}, "get_certificate": certificateManager})
			}
			// Dynamic exact/apex/wildcard route assignments are not available
			// when this static Caddy document is generated. An empty-subject
			// broker-only policy is the deliberate catch-all for those names;
			// it has no issuer, on-demand permission, or storage fallback.
			policies = append(policies, map[string]any{"get_certificate": certificateManager})
		} else if issuer != nil {
			// Without the Paperboat broker, managed route certificates have no
			// certificate source and must fail closed. Keep an optional issuer
			// policy only for the explicitly separate signaling host.
			policies = append(policies, map[string]any{"subjects": []string{input.SignalingHost}, "issuers": []any{issuer}})
		}
		automation := map[string]any{"policies": policies}
		config["apps"].(map[string]any)["tls"] = map[string]any{"automation": automation}
		if input.IssuerModule == "internal" {
			config["apps"].(map[string]any)["pki"] = map[string]any{"certificate_authorities": map[string]any{"local": map[string]any{"install_trust": false}}}
		}
	}
	return json.MarshalIndent(config, "", "  ")
}

func reverseProxy(upstream string) map[string]any {
	return map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream}}, "headers": map[string]any{"request": map[string]any{"delete": []string{"Forwarded", "X-Forwarded-Host", "X-Real-IP", "X-Paperboat-Environment", "X-Paperboat-Route", "X-Paperboat-Private-Carrier", "X-Paperboat-Private-Connection"}, "set": map[string][]string{"X-Forwarded-Proto": {"https"}, "X-Real-IP": {"{http.request.client_ip}"}}}}}
}

func privateAccessReverseProxy(upstream, token string) map[string]any {
	proxy := reverseProxy(upstream)
	request := proxy["headers"].(map[string]any)["request"].(map[string]any)
	deletions := request["delete"].([]string)
	filtered := deletions[:0]
	for _, header := range deletions {
		if header != "X-Paperboat-Private-Carrier" && header != "X-Paperboat-Private-Connection" {
			filtered = append(filtered, header)
		}
	}
	request["delete"] = filtered
	request["set"].(map[string][]string)["X-Paperboat-Private-Carrier"] = []string{token}
	request["set"].(map[string][]string)["X-Paperboat-Private-Connection"] = []string{"{http.request.remote}"}
	return proxy
}

func relayReverseProxy(upstream string) map[string]any {
	result := reverseProxy(upstream)
	result["flush_interval"] = -1
	return result
}

func validate(input Input) error {
	for _, baseHost := range []string{input.PreviewBaseDomain, input.TunnelBaseDomain, input.RuntimeBaseDomain, input.SignalingHost} {
		if baseHost != strings.ToLower(baseHost) || !domainPattern.MatchString(baseHost) || net.ParseIP(baseHost) != nil {
			return ErrInvalid
		}
	}
	if overlappingDomains(input.PreviewBaseDomain, input.TunnelBaseDomain) || input.RuntimeBaseDomain != "" && (overlappingDomains(input.PreviewBaseDomain, input.RuntimeBaseDomain) || overlappingDomains(input.TunnelBaseDomain, input.RuntimeBaseDomain)) {
		return ErrInvalid
	}
	if overlapsManagedDomain(input.SignalingHost, []string{input.PreviewBaseDomain, input.TunnelBaseDomain, input.RuntimeBaseDomain}) {
		return ErrInvalid
	}
	if err := validatePrivateEndpoint(input.PrivateUpstream); err != nil {
		return err
	}
	if input.ListenAddress == "" || input.PrivateAccessListenAddress == "" || input.HTTPListenAddress == "" || input.ListenAddress == input.HTTPListenAddress || input.ListenAddress == input.PrivateAccessListenAddress || input.HTTPListenAddress == input.PrivateAccessListenAddress || input.AdminAddress == "" || !filepath.IsAbs(input.StreamBrokerPath) || len(input.StreamBrokerPath) > 100 {
		return ErrInvalid
	}
	if validateLoopbackEndpoint(input.PrivateAccessListenAddress) != nil || len(input.PrivateAccessToken) < 32 || len(input.PrivateAccessToken) > 256 || strings.TrimSpace(input.PrivateAccessToken) != input.PrivateAccessToken || strings.ContainsAny(input.PrivateAccessToken, "\r\n\x00") {
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
		if route.Host != strings.ToLower(route.Host) || !domainPattern.MatchString(route.Host) || net.ParseIP(route.Host) != nil || route.Host == input.SignalingHost || overlapsManagedDomain(route.Host, []string{input.PreviewBaseDomain, input.TunnelBaseDomain, input.RuntimeBaseDomain}) || validatePrivateRouteEndpoint(route.Upstream) != nil {
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
	if input.CertificateBrokerSocket != "" && (!filepath.IsAbs(input.CertificateBrokerSocket) || len(input.CertificateBrokerSocket) > 100 || input.CertificateBrokerSocket == string(filepath.Separator) || strings.ContainsAny(input.CertificateBrokerSocket, "\x00\r\n")) {
		return ErrInvalid
	}
	return nil
}

func overlappingDomains(first, second string) bool {
	return first == second || strings.HasSuffix(first, "."+second) || strings.HasSuffix(second, "."+first)
}

func overlapsManagedDomain(host string, domains []string) bool {
	for _, domain := range domains {
		if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain) || strings.HasSuffix(domain, "."+host)) {
			return true
		}
	}
	return false
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
