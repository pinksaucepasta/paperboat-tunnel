package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDeploymentStrictProfile(t *testing.T) {
	path := writeDeployment(t, validDeploymentJSON())
	deployment, err := LoadDeployment(path)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.ConnectorTCPPort != 26022 || deployment.PreviewBaseDomain != "preview.hexwagon.com" || deployment.HelperBaseDomain != "helper.hexwagon.com" || deployment.NodeCapacity != 128 {
		t.Fatalf("deployment = %+v", deployment)
	}
}

func TestLoadDeploymentRejectsUnsafeProfiles(t *testing.T) {
	for _, mutate := range []func(string) string{
		func(value string) string { return strings.Replace(value, "https://", "http://", 1) },
		func(value string) string { return strings.Replace(value, "127.0.0.1:18082", "0.0.0.0:18082", 1) },
		func(value string) string {
			return strings.Replace(value, `"frps_sha256":"`+strings.Repeat("a", 64)+`"`, `"frps_sha256":"bad"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"node_capacity":128`, `"node_capacity":0`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"preview_base_domain":"preview.hexwagon.com"`, `"preview_base_domain":"PREVIEW.hexwagon.com"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"helper_base_domain":"helper.hexwagon.com"`, `"helper_base_domain":"hexwagon.com"`, 1)
		},
		func(value string) string { return strings.TrimSuffix(value, "}") + `,"unknown":true}` },
	} {
		if _, err := LoadDeployment(writeDeployment(t, mutate(validDeploymentJSON()))); err == nil {
			t.Fatal("unsafe deployment accepted")
		}
	}
}

func validDeploymentJSON() string {
	return `{"control_url":"https://edge-control.hexwagon.com","control_credential_file":"/opt/paperboat-tunnel/private/control.credential","jwks_file":"/opt/paperboat-tunnel/private/jwks.json","revocations_file":"/opt/paperboat-tunnel/private/revocations.json","usage_signing_key_file":"/opt/paperboat-tunnel/private/usage.key","frps_binary":"/opt/paperboat-tunnel/bin/frps","frps_sha256":"` + strings.Repeat("a", 64) + `","caddy_binary":"/opt/paperboat-tunnel/bin/caddy","caddy_sha256":"` + strings.Repeat("b", 64) + `","runtime_directory":"/opt/paperboat-tunnel/runtime","hook_address":"127.0.0.1:18082","hook_path":"/private/paperboat-hook-0123456789abcdef","connector_bind_address":"0.0.0.0","connector_advertise_host":"edge.hexwagon.com","connector_tcp_port":26022,"connector_quic_port":26023,"private_vhost_address":"127.0.0.1:18083","edge_gateway_address":"127.0.0.1:18085","caddy_listen_address":"127.0.0.1:18443","caddy_admin_address":"127.0.0.1:18084","preview_base_domain":"preview.hexwagon.com","helper_base_domain":"helper.hexwagon.com","trusted_proxy_cidrs":["127.0.0.1/32"],"certificate_issuer":"internal","node_capacity":128,"control_interval":5000000000,"usage_interval":10000000000,"control_timeout":5000000000}`
}

func writeDeployment(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
