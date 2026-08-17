package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const maxDeploymentBytes = 1 << 20

var routeBaseDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type Deployment struct {
	ControlURL                   string        `json:"control_url"`
	CredentialIssuer             string        `json:"credential_issuer"`
	ControlCredentialFile        string        `json:"control_credential_file"`
	ControlCAFile                string        `json:"control_ca_file"`
	JWKSFile                     string        `json:"jwks_file"`
	RevocationsFile              string        `json:"revocations_file"`
	UsageSigningKeyFile          string        `json:"usage_signing_key_file"`
	FRPSBinary                   string        `json:"frps_binary"`
	FRPSSHA256                   string        `json:"frps_sha256"`
	FRPSLogLevel                 string        `json:"frps_log_level,omitempty"`
	CaddyBinary                  string        `json:"caddy_binary"`
	CaddySHA256                  string        `json:"caddy_sha256"`
	RuntimeDirectory             string        `json:"runtime_directory"`
	HookAddress                  string        `json:"hook_address"`
	HookPath                     string        `json:"hook_path"`
	ConnectorBindAddress         string        `json:"connector_bind_address"`
	ConnectorAdvertiseHost       string        `json:"connector_advertise_host"`
	ConnectorTCPPort             int           `json:"connector_tcp_port"`
	ConnectorQUICPort            int           `json:"connector_quic_port"`
	STUNListenAddress            string        `json:"stun_listen_address"`
	ConnectorTCPMux              *bool         `json:"connector_tcp_mux,omitempty"`
	PrivateVhostAddress          string        `json:"private_vhost_address"`
	EdgeGatewayAddress           string        `json:"edge_gateway_address"`
	CaddyListenAddress           string        `json:"caddy_listen_address"`
	CaddyHTTPListenAddress       string        `json:"caddy_http_listen_address"`
	CaddyAdminAddress            string        `json:"caddy_admin_address"`
	PreviewBaseDomain            string        `json:"preview_base_domain"`
	HelperBaseDomain             string        `json:"helper_base_domain"`
	SignalingHost                string        `json:"signaling_host"`
	SignalingCapacity            uint32        `json:"signaling_capacity"`
	TrustedProxyCIDRs            []string      `json:"trusted_proxy_cidrs"`
	CertificateIssuer            string        `json:"certificate_issuer"`
	CertificateDNSProvider       string        `json:"certificate_dns_provider,omitempty"`
	CertificateDNSCredentialFile string        `json:"certificate_dns_credential_file,omitempty"`
	PublicRoutes                 []PublicRoute `json:"public_routes,omitempty"`
	NodeCapacity                 uint32        `json:"node_capacity"`
	ControlInterval              time.Duration `json:"control_interval"`
	UsageInterval                time.Duration `json:"usage_interval"`
	ControlTimeout               time.Duration `json:"control_timeout"`
}

type PublicRoute struct {
	Host        string `json:"host"`
	PathPrefix  string `json:"path_prefix,omitempty"`
	StripPrefix bool   `json:"strip_prefix,omitempty"`
	Upstream    string `json:"upstream"`
}

func LoadDeployment(path string) (Deployment, error) {
	file, err := os.Open(path)
	if err != nil {
		return Deployment{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDeploymentBytes+1))
	if err != nil || len(data) > maxDeploymentBytes {
		return Deployment{}, invalid("deployment config", errors.New("document is unavailable or oversized"))
	}
	var deployment Deployment
	if err := strictjson.Decode(data, &deployment, 64); err != nil {
		return Deployment{}, invalid("deployment config", err)
	}
	if deployment.CredentialIssuer == "" {
		deployment.CredentialIssuer = deployment.ControlURL
	}
	if deployment.FRPSLogLevel == "" {
		deployment.FRPSLogLevel = "error"
	}
	if deployment.ConnectorTCPMux == nil {
		enabled := true
		deployment.ConnectorTCPMux = &enabled
	}
	if err := deployment.validate(); err != nil {
		return Deployment{}, invalid("deployment config", err)
	}
	return deployment, nil
}

func (d Deployment) validate() error {
	control, err := url.Parse(d.ControlURL)
	if err != nil || control.Scheme != "https" || control.Host == "" || control.User != nil || control.RawQuery != "" || control.Fragment != "" {
		return errors.New("control_url must be a private HTTPS URL")
	}
	issuer, err := url.Parse(d.CredentialIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("credential_issuer must be an HTTPS origin")
	}
	for _, path := range []string{d.ControlCredentialFile, d.JWKSFile, d.RevocationsFile, d.UsageSigningKeyFile, d.FRPSBinary, d.CaddyBinary, d.RuntimeDirectory} {
		if path == "" || !filepath.IsAbs(path) || len(path) > 4096 {
			return errors.New("deployment paths must be bounded and absolute")
		}
	}
	if d.ControlCAFile != "" && (!filepath.IsAbs(d.ControlCAFile) || len(d.ControlCAFile) > 4096) {
		return errors.New("control_ca_file must be a bounded absolute path")
	}
	if d.CertificateDNSCredentialFile != "" && (!filepath.IsAbs(d.CertificateDNSCredentialFile) || len(d.CertificateDNSCredentialFile) > 4096) {
		return errors.New("certificate_dns_credential_file must be a bounded absolute path")
	}
	for _, digest := range []string{d.FRPSSHA256, d.CaddySHA256} {
		if digest == "" {
			continue
		}
		if len(digest) != sha256.Size*2 {
			return errors.New("artifact checksums must be SHA-256")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("artifact checksums must be SHA-256")
		}
	}
	if d.FRPSLogLevel != "error" && d.FRPSLogLevel != "warn" && d.FRPSLogLevel != "info" {
		return errors.New("frps_log_level is invalid")
	}
	if err := privateEndpoint(d.HookAddress); err != nil {
		return err
	}
	if err := privateEndpoint(d.PrivateVhostAddress); err != nil {
		return err
	}
	if err := privateEndpoint(d.EdgeGatewayAddress); err != nil {
		return err
	}
	if err := privateEndpoint(d.CaddyAdminAddress); err != nil {
		return err
	}
	if d.HookPath == "" || !strings.HasPrefix(d.HookPath, "/") || len(d.HookPath) > 256 {
		return errors.New("hook_path is invalid")
	}
	if net.ParseIP(d.ConnectorBindAddress) == nil || d.ConnectorTCPPort < 1 || d.ConnectorTCPPort > 65535 || d.ConnectorQUICPort < 1 || d.ConnectorQUICPort > 65535 {
		return errors.New("connector listener configuration is invalid")
	}
	if err := publicUDPEndpoint(d.STUNListenAddress); err != nil || endpointPort(d.STUNListenAddress) == d.ConnectorQUICPort {
		return errors.New("STUN listener configuration is invalid")
	}
	if d.ConnectorAdvertiseHost == "" || len(d.ConnectorAdvertiseHost) > 253 || strings.ContainsAny(d.ConnectorAdvertiseHost, "/:@") {
		return errors.New("connector advertised host is invalid")
	}
	if _, _, err := net.SplitHostPort(d.CaddyListenAddress); err != nil {
		return errors.New("Caddy listener is invalid")
	}
	if _, _, err := net.SplitHostPort(d.CaddyHTTPListenAddress); err != nil || d.CaddyHTTPListenAddress == d.CaddyListenAddress {
		return errors.New("Caddy HTTP listener is invalid")
	}
	for _, domain := range []string{d.PreviewBaseDomain, d.HelperBaseDomain} {
		if !routeBaseDomainPattern.MatchString(domain) || net.ParseIP(domain) != nil {
			return errors.New("route base domain is invalid")
		}
	}
	if d.PreviewBaseDomain == d.HelperBaseDomain || strings.HasSuffix(d.PreviewBaseDomain, "."+d.HelperBaseDomain) || strings.HasSuffix(d.HelperBaseDomain, "."+d.PreviewBaseDomain) {
		return errors.New("route base domains must not overlap")
	}
	if !routeBaseDomainPattern.MatchString(d.SignalingHost) || net.ParseIP(d.SignalingHost) != nil || d.SignalingHost != strings.ToLower(d.SignalingHost) || d.SignalingHost == d.PreviewBaseDomain || d.SignalingHost == d.HelperBaseDomain || strings.HasSuffix(d.SignalingHost, "."+d.PreviewBaseDomain) || strings.HasSuffix(d.SignalingHost, "."+d.HelperBaseDomain) || strings.HasSuffix(d.PreviewBaseDomain, "."+d.SignalingHost) || strings.HasSuffix(d.HelperBaseDomain, "."+d.SignalingHost) {
		return errors.New("signaling host is invalid or overlaps managed routes")
	}
	for _, cidr := range d.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return errors.New("trusted proxy CIDR is invalid")
		}
	}
	seenPublicHosts := make(map[string]struct{}, len(d.PublicRoutes))
	for _, route := range d.PublicRoutes {
		if route.Host != strings.ToLower(route.Host) || !routeBaseDomainPattern.MatchString(route.Host) || net.ParseIP(route.Host) != nil || route.Host == d.SignalingHost || strings.HasSuffix(route.Host, "."+d.PreviewBaseDomain) || strings.HasSuffix(route.Host, "."+d.HelperBaseDomain) {
			return errors.New("public route host is invalid or overlaps managed routes")
		}
		key := route.Host + "\x00" + route.PathPrefix
		if _, exists := seenPublicHosts[key]; exists {
			return errors.New("public route is duplicated")
		}
		seenPublicHosts[key] = struct{}{}
		if err := privateRouteEndpoint(route.Upstream); err != nil {
			return errors.New("public route upstream must use a private address or service name")
		}
		if route.PathPrefix != "" && (!strings.HasPrefix(route.PathPrefix, "/") || strings.Contains(route.PathPrefix, "..") || strings.ContainsAny(route.PathPrefix, "?#")) {
			return errors.New("public route path prefix is invalid")
		}
		if route.StripPrefix && route.PathPrefix == "" {
			return errors.New("public route cannot strip an empty prefix")
		}
	}
	if d.CertificateIssuer == "" || (d.CertificateDNSProvider != "" && (d.CertificateIssuer != "acme" || d.CertificateDNSCredentialFile == "")) || d.NodeCapacity == 0 || d.NodeCapacity > 10000 || d.SignalingCapacity == 0 || d.SignalingCapacity > 10000 || d.ControlInterval <= 0 || d.ControlInterval > time.Minute || d.UsageInterval <= 0 || d.UsageInterval > time.Minute || d.ControlTimeout <= 0 || d.ControlTimeout > 30*time.Second {
		return errors.New("deployment bounds are invalid")
	}
	return nil
}

func publicUDPEndpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	value, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || ip.IsMulticast() || portErr != nil || value < 1 || value > 65535 {
		return errors.New("public UDP endpoint must use an explicit IP and fixed nonzero port")
	}
	return nil
}

func endpointPort(address string) int {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}

func privateEndpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) || port == "" || port == "0" {
		return errors.New("private endpoint must use a fixed loopback or private address")
	}
	return nil
}

func privateRouteEndpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || port == "0" {
		return errors.New("private route endpoint is invalid")
	}
	if net.ParseIP(host) != nil {
		return privateEndpoint(address)
	}
	if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(host) {
		return errors.New("private route service name is invalid")
	}
	return nil
}
