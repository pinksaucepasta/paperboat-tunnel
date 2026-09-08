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
	if deployment.CarrierTCPListenAddress != "0.0.0.0:27443" || deployment.CarrierQUICListenAddress != "0.0.0.0:27444" || deployment.STUNListenAddress != "0.0.0.0:3478" || deployment.PreviewBaseDomain != "preview.example.test" || deployment.TunnelBaseDomain != "tunnels.example.test" || deployment.RuntimeBaseDomain != "runtime.example.test" || deployment.SignalingHost != "signal.example.test" || deployment.SignalingCapacity != 4096 || deployment.NodeCapacity != 128 {
		t.Fatalf("deployment = %+v", deployment)
	}
}

func TestBrowserRolloutRequiresDistributedHostnameIsolation(t *testing.T) {
	// Neither DNS readiness nor an operator's enable flag substitutes for the
	// browser public-suffix boundary. Existing public/native startup stays valid.
	base := strings.TrimSuffix(validDeploymentJSON(), "}")
	if _, err := LoadDeployment(writeDeployment(t, base+`,"browser_access_enabled":true,"browser_login_origin":"https://login.example.test"}`)); err == nil {
		t.Fatal("enabled browser access without PSL isolation")
	}
	if _, err := LoadDeployment(writeDeployment(t, base+`,"browser_access_enabled":false,"browser_login_origin":"https://login.example.test"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDeploymentRejectsUnsafeProfiles(t *testing.T) {
	for _, mutate := range []func(string) string{
		func(value string) string { return strings.Replace(value, "https://", "http://", 1) },
		func(value string) string { return strings.Replace(value, "127.0.0.1:18085", "0.0.0.0:18085", 1) },
		func(value string) string {
			return strings.Replace(value, `"caddy_sha256":"`+strings.Repeat("b", 64)+`"`, `"caddy_sha256":"bad"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"node_capacity":128`, `"node_capacity":0`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"stun_listen_address":"0.0.0.0:3478"`, `"stun_listen_address":"0.0.0.0:27444"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"preview_base_domain":"preview.example.test"`, `"preview_base_domain":"PREVIEW.example.test"`, 1)
		},
		func(value string) string {
			return strings.Replace(value, `"tunnel_base_domain":"tunnels.example.test"`, `"tunnel_base_domain":"example.test"`, 1)
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
	return `{"control_url":"https://edge-control.example.test","control_credential_file":"/opt/paperboat-tunnel/private/control.credential","jwks_file":"/opt/paperboat-tunnel/private/jwks.json","revocations_file":"/opt/paperboat-tunnel/private/revocations.json","usage_signing_key_file":"/opt/paperboat-tunnel/private/usage.key","caddy_binary":"/opt/paperboat-tunnel/bin/caddy","caddy_sha256":"` + strings.Repeat("b", 64) + `","runtime_directory":"/opt/paperboat-tunnel/runtime","connector_advertise_host":"edge.example.test","carrier_tcp_listen_address":"0.0.0.0:27443","carrier_quic_listen_address":"0.0.0.0:27444","stun_listen_address":"0.0.0.0:3478","edge_gateway_address":"127.0.0.1:18085","caddy_listen_address":"127.0.0.1:18443","caddy_private_access_listen_address":"127.0.0.1:19443","caddy_http_listen_address":"127.0.0.1:18080","caddy_admin_address":"127.0.0.1:18084","preview_base_domain":"preview.example.test","tunnel_base_domain":"tunnels.example.test","runtime_base_domain":"runtime.example.test","signaling_host":"signal.example.test","signaling_capacity":4096,"trusted_proxy_cidrs":["127.0.0.1/32"],"certificate_issuer":"internal","node_capacity":128,"control_interval":5000000000,"usage_interval":10000000000,"control_timeout":5000000000}`
}

func writeDeployment(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
