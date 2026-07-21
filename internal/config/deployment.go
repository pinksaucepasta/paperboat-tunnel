package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxDeploymentBytes = 1 << 20

type Deployment struct {
	ControlURL             string        `json:"control_url"`
	CredentialIssuer       string        `json:"credential_issuer"`
	ControlCredentialFile  string        `json:"control_credential_file"`
	ControlCAFile          string        `json:"control_ca_file"`
	JWKSFile               string        `json:"jwks_file"`
	RevocationsFile        string        `json:"revocations_file"`
	UsageSigningKeyFile    string        `json:"usage_signing_key_file"`
	FRPSBinary             string        `json:"frps_binary"`
	FRPSSHA256             string        `json:"frps_sha256"`
	FRPSLogLevel           string        `json:"frps_log_level,omitempty"`
	CaddyBinary            string        `json:"caddy_binary"`
	CaddySHA256            string        `json:"caddy_sha256"`
	RuntimeDirectory       string        `json:"runtime_directory"`
	HookAddress            string        `json:"hook_address"`
	HookPath               string        `json:"hook_path"`
	ConnectorBindAddress   string        `json:"connector_bind_address"`
	ConnectorAdvertiseHost string        `json:"connector_advertise_host"`
	ConnectorTCPPort       int           `json:"connector_tcp_port"`
	ConnectorQUICPort      int           `json:"connector_quic_port"`
	PrivateVhostAddress    string        `json:"private_vhost_address"`
	CaddyListenAddress     string        `json:"caddy_listen_address"`
	CaddyAdminAddress      string        `json:"caddy_admin_address"`
	WildcardHost           string        `json:"wildcard_host"`
	TrustedProxyCIDRs      []string      `json:"trusted_proxy_cidrs"`
	CertificateIssuer      string        `json:"certificate_issuer"`
	NodeCapacity           uint32        `json:"node_capacity"`
	ControlInterval        time.Duration `json:"control_interval"`
	UsageInterval          time.Duration `json:"usage_interval"`
	ControlTimeout         time.Duration `json:"control_timeout"`
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&deployment); err != nil {
		return Deployment{}, invalid("deployment config", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Deployment{}, invalid("deployment config", errors.New("trailing JSON"))
	}
	if deployment.CredentialIssuer == "" {
		deployment.CredentialIssuer = deployment.ControlURL
	}
	if deployment.FRPSLogLevel == "" {
		deployment.FRPSLogLevel = "error"
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
	for _, digest := range []string{d.FRPSSHA256, d.CaddySHA256} {
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
	if err := privateEndpoint(d.CaddyAdminAddress); err != nil {
		return err
	}
	if d.HookPath == "" || !strings.HasPrefix(d.HookPath, "/") || len(d.HookPath) > 256 {
		return errors.New("hook_path is invalid")
	}
	if net.ParseIP(d.ConnectorBindAddress) == nil || d.ConnectorTCPPort < 1 || d.ConnectorTCPPort > 65535 || d.ConnectorQUICPort < 1 || d.ConnectorQUICPort > 65535 || d.ConnectorTCPPort == d.ConnectorQUICPort {
		return errors.New("connector listener configuration is invalid")
	}
	if d.ConnectorAdvertiseHost == "" || len(d.ConnectorAdvertiseHost) > 253 || strings.ContainsAny(d.ConnectorAdvertiseHost, "/:@") {
		return errors.New("connector advertised host is invalid")
	}
	if _, _, err := net.SplitHostPort(d.CaddyListenAddress); err != nil {
		return errors.New("Caddy listener is invalid")
	}
	if !strings.HasPrefix(d.WildcardHost, "*.") || strings.Count(d.WildcardHost, "*") != 1 {
		return errors.New("wildcard_host is invalid")
	}
	for _, cidr := range d.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return errors.New("trusted proxy CIDR is invalid")
		}
	}
	if d.CertificateIssuer == "" || d.NodeCapacity == 0 || d.NodeCapacity > 10000 || d.ControlInterval <= 0 || d.ControlInterval > time.Minute || d.UsageInterval <= 0 || d.UsageInterval > time.Minute || d.ControlTimeout <= 0 || d.ControlTimeout > 30*time.Second {
		return errors.New("deployment bounds are invalid")
	}
	return nil
}

func privateEndpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) || port == "" || port == "0" {
		return errors.New("private endpoint must use a fixed loopback or private address")
	}
	return nil
}
