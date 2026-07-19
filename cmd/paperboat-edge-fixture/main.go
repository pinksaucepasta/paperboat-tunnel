package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var directory, protocol string
	var generation, revision uint64
	var revoked, includeRoute, loseUsageAck bool
	flag.StringVar(&directory, "directory", "", "owner-only fixture directory")
	flag.StringVar(&protocol, "protocol", "tcp", "frp transport: tcp or quic")
	flag.Uint64Var(&generation, "generation", 1, "connector generation")
	flag.Uint64Var(&revision, "route-revision", 1, "route revision")
	flag.BoolVar(&revoked, "revoked", false, "mark the authoritative assignment revoked")
	flag.BoolVar(&includeRoute, "include-route", true, "include the authoritative route")
	flag.BoolVar(&loseUsageAck, "lose-usage-ack", false, "lose the first usage acknowledgment")
	flag.Parse()
	if directory == "" || (protocol != "tcp" && protocol != "quic") || generation == 0 || revision == 0 {
		fatal("invalid fixture arguments")
	}
	if err := generateFixture(directory, fixtureOptions{Protocol: protocol, Generation: generation, Revision: revision, Revoked: revoked, IncludeRoute: includeRoute, LoseUsageAck: loseUsageAck}, time.Now().UTC()); err != nil {
		fatal(err.Error())
	}
}

func generate(directory, protocol string, now time.Time) error {
	return generateFixture(directory, fixtureOptions{Protocol: protocol, Generation: 1, Revision: 1, IncludeRoute: true}, now)
}

type fixtureOptions struct {
	Protocol     string
	Generation   uint64
	Revision     uint64
	Revoked      bool
	IncludeRoute bool
	LoseUsageAck bool
}

func generateFixture(directory string, options fixtureOptions, now time.Time) error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	usagePublic, usagePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	header := map[string]any{"alg": "EdDSA", "kid": "phase3-fixture", "typ": "paperboat-credential+jwt"}
	claims := map[string]any{"iss": "https://pb.hexwagon.com", "aud": "paperboat-edge", "sub": "env_phase3_01", "jti": fmt.Sprintf("jti_phase3_%04d", options.Generation), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": []string{"connector:admit"}, "credential_class": "connector_admission", "environment_id": "env_phase3_01", "helper_id": "helper_phase3_01", "connector_generation": options.Generation, "edge_pool": "default", "edge_node_id": "edge-vps-01"}
	encodedHeader, _ := json.Marshal(header)
	encodedClaims, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(encodedClaims)
	credential := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(unsigned)))
	route := map[string]any{"route_id": "route_phase3_01", "route_revision": options.Revision, "kind": "helper_https_wss", "public_host": "phase3.hexwagon.com", "proxy_name": "phase3_proxy", "target": map[string]any{"host": "127.0.0.1", "port": 18085}}
	handoff, _ := json.Marshal(map[string]any{"operation_id": fmt.Sprintf("op_phase3_admit_%04d", options.Generation), "credential": credential, "environment_id": "env_phase3_01", "helper_id": "helper_phase3_01", "connector_generation": options.Generation, "edge_pool": "default", "edge_node_id": "edge-vps-01", "routes": []any{route}})
	serverPort := 26022
	if options.Protocol == "quic" {
		serverPort = 26023
	}
	frpc := map[string]any{"serverAddr": "127.0.0.1", "serverPort": serverPort, "loginFailExit": true, "log": map[string]any{"to": "console", "level": "debug"}, "auth": map[string]any{"method": "token", "token": credential}, "metadatas": map[string]string{"paperboat.admission": string(handoff)}, "transport": map[string]any{"protocol": options.Protocol}, "proxies": []any{map[string]any{"name": "phase3_proxy", "type": "http", "localIP": "127.0.0.1", "localPort": 18085, "customDomains": []string{"phase3.hexwagon.com"}}}}
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "phase3-fixture", "x": base64.RawURLEncoding.EncodeToString(public)}}}
	desiredRoutes := []any{}
	if options.IncludeRoute {
		desiredRoutes = append(desiredRoutes, map[string]any{"route_id": "route_phase3_01", "route_revision": options.Revision, "environment_id": "env_phase3_01", "connector_generation": options.Generation, "edge_node_id": "edge-vps-01", "kind": "helper_https_wss", "public_host": "phase3.hexwagon.com", "target": map[string]any{"host": "127.0.0.1", "port": 18085}})
	}
	seed := map[string]any{"assignments": []any{map[string]any{"environment_id": "env_phase3_01", "helper_id": "helper_phase3_01", "connector_generation": options.Generation, "edge_pool": "default", "edge_node_id": "edge-vps-01", "revoked": options.Revoked}}, "routes": desiredRoutes, "usage_keys": []any{map[string]any{"key_id": "phase3-usage", "public_key": base64.RawURLEncoding.EncodeToString(usagePublic)}}, "lose_next_usage_ack": options.LoseUsageAck}
	usageKey := map[string]any{"key_id": "phase3-usage", "private_key": base64.RawURLEncoding.EncodeToString(usagePrivate)}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	for name, value := range map[string]any{"jwks.json": jwks, "fake-control.seed.json": seed, "frpc.json": frpc, "usage.key.json": usageKey} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, name), append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
