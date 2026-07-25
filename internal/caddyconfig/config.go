package caddyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	AdminAddress      string
	TrustedProxies    []string
	IssuerModule      string
	DNSProvider       string
}

func Generate(input Input) ([]byte, error) {
	if err := validate(input); err != nil {
		return nil, err
	}
	wildcardHosts := []string{"*." + input.PreviewBaseDomain, "*." + input.HelperBaseDomain}
	config := map[string]any{
		"admin":   map[string]any{"listen": input.AdminAddress},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "PANIC"}}},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"paperboat_public": map[string]any{
						"listen":                 []string{input.ListenAddress},
						"automatic_https":        map[string]any{"disable_redirects": true},
						"trusted_proxies":        map[string]any{"source": "static", "ranges": input.TrustedProxies},
						"trusted_proxies_strict": 1,
						"client_ip_headers":      []string{"X-Forwarded-For"},
						"routes": []any{map[string]any{
							"match": []any{map[string]any{"host": wildcardHosts}},
							"handle": []any{
								map[string]any{"handler": "headers", "response": map[string]any{"set": map[string][]string{
									"X-Content-Type-Options": {"nosniff"},
									"Referrer-Policy":        {"no-referrer"},
									"X-Frame-Options":        {"DENY"},
								}}},
								map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": input.PrivateUpstream}}, "transport": map[string]any{"protocol": "http", "versions": []string{"1.1"}, "keep_alive": map[string]any{"enabled": false}}, "headers": map[string]any{"request": map[string]any{"delete": []string{"Forwarded", "X-Forwarded-Host", "X-Real-IP", "X-Paperboat-Environment", "X-Paperboat-Route"}, "set": map[string][]string{"X-Forwarded-Proto": {"https"}, "X-Real-IP": {"{http.request.client_ip}"}}}}, "flush_interval": -1},
							},
							"terminal": true,
						}},
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
		config["apps"].(map[string]any)["tls"] = map[string]any{"automation": map[string]any{"policies": []any{map[string]any{"subjects": wildcardHosts, "issuers": []any{issuer}}}}}
		if input.IssuerModule == "internal" {
			config["apps"].(map[string]any)["pki"] = map[string]any{"certificate_authorities": map[string]any{"local": map[string]any{"install_trust": false}}}
		}
	}
	return json.MarshalIndent(config, "", "  ")
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
	if input.ListenAddress == "" || input.AdminAddress == "" {
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
