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
	if deployment.ConnectorTCPPort != 26023 || deployment.ConnectorQUICPort != 26023 || deployment.STUNListenAddress != "0.0.0.0:3478" || deployment.PreviewBaseDomain != "preview.example.test" || deployment.HelperBaseDomain != "helper.example.test" || deployment.SignalingHost != "signal.example.test" || deployment.SignalingCapacity != 4096 || deployment.NodeCapacity != 128 {
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
			return strings.Replace(value, `"stun_listen_address":"0.0.0.0:3478"`, `"stun_listen_address":"0.0.0.0:26023"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"preview_base_domain":"preview.example.test"`, `"preview_base_domain":"PREVIEW.example.test"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"helper_base_domain":"helper.example.test"`, `"helper_base_domain":"example.test"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"signaling_host":"signal.example.test"`, `"signaling_host":"SIGNAL.example.test"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"signaling_host":"signal.example.test"`, `"signaling_host":"x.preview.example.test"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"signaling_capacity":4096`, `"signaling_capacity":0`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"signaling_capacity":4096`, `"signaling_capacity":10001`, 1)
		},
		func(value string) string { return strings.TrimSuffix(value, "}") + `,"unknown":true}` },
		func(value string) string {
			return strings.TrimSuffix(value, "}") + `,"node_capacity":64}`
		},
		func(value string) string {
			return strings.TrimSuffix(value, "}") + `,"public_routes":[{"host":"x.preview.example.test","upstream":"127.0.0.1:8080"}]}`
		},
		func(value string) string {
			return strings.TrimSuffix(value, "}") + `,"public_routes":[{"host":"api.example.test","host":"other.example.test","upstream":"127.0.0.1:8080"}]}`
		},
		func(value string) string {
			return strings.TrimSuffix(value, "}") + `,"public_routes":[{"host":"api.example.test","upstream":"8.8.8.8:80"}]}`
		},
		func(value string) string {
			return strings.TrimSuffix(value, "}") + `,"public_routes":[{"host":"signal.example.test","upstream":"127.0.0.1:8080"}]}`
		},
	} {
		if _, err := LoadDeployment(writeDeployment(t, mutate(validDeploymentJSON()))); err == nil {
			t.Fatal("unsafe deployment accepted")
		}
	}
}

func TestLoadDeploymentAcceptsBoundedPublicRoutes(t *testing.T) {
	value := strings.TrimSuffix(validDeploymentJSON(), "}") + `,"public_routes":[{"host":"api.example.test","path_prefix":"/helper-releases","strip_prefix":true,"upstream":"releases:8081"},{"host":"api.example.test","upstream":"server:8082"}]}`
	deployment, err := LoadDeployment(writeDeployment(t, value))
	if err != nil {
		t.Fatal(err)
	}
	if len(deployment.PublicRoutes) != 2 || deployment.PublicRoutes[0].PathPrefix != "/helper-releases" || !deployment.PublicRoutes[0].StripPrefix {
		t.Fatalf("public routes = %+v", deployment.PublicRoutes)
	}
}

func validDeploymentJSON() string {
	return `{"control_url":"https://edge-control.example.test","control_credential_file":"/opt/paperboat-tunnel/private/control.credential","jwks_file":"/opt/paperboat-tunnel/private/jwks.json","revocations_file":"/opt/paperboat-tunnel/private/revocations.json","usage_signing_key_file":"/opt/paperboat-tunnel/private/usage.key","frps_binary":"/opt/paperboat-tunnel/bin/frps","frps_sha256":"` + strings.Repeat("a", 64) + `","caddy_binary":"/opt/paperboat-tunnel/bin/caddy","caddy_sha256":"` + strings.Repeat("b", 64) + `","runtime_directory":"/opt/paperboat-tunnel/runtime","hook_address":"127.0.0.1:18082","hook_path":"/private/paperboat-hook-0123456789abcdef","connector_bind_address":"0.0.0.0","connector_advertise_host":"edge.example.test","connector_tcp_port":26023,"connector_quic_port":26023,"stun_listen_address":"0.0.0.0:3478","private_vhost_address":"127.0.0.1:18083","edge_gateway_address":"127.0.0.1:18085","caddy_listen_address":"127.0.0.1:18443","caddy_http_listen_address":"127.0.0.1:18080","caddy_admin_address":"127.0.0.1:18084","preview_base_domain":"preview.example.test","helper_base_domain":"helper.example.test","signaling_host":"signal.example.test","signaling_capacity":4096,"trusted_proxy_cidrs":["127.0.0.1/32"],"certificate_issuer":"internal","node_capacity":128,"control_interval":5000000000,"usage_interval":10000000000,"control_timeout":5000000000}`
}

func writeDeployment(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
