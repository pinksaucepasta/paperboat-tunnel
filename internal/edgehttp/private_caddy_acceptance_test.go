package edgehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"golang.org/x/net/http2"
)

// TestPrivateAccessThroughRealCaddy is deliberately opt-in because it starts
// the exact custom Caddy binary supplied by the caller. It needs no browser,
// cookie, public listener, Docker, or external network service.
func TestPrivateAccessThroughRealCaddy(t *testing.T) {
	caddy := os.Getenv("PAPERBOAT_TEST_CADDY_BINARY")
	if caddy == "" {
		t.Skip("set PAPERBOAT_TEST_CADDY_BINARY to the custom Paperboat Caddy binary")
	}
	if err := validatePrivateCaddyBinaryPath(caddy); err != nil {
		t.Fatal(err)
	}

	const (
		hostA = "private-a.acceptance.example.test"
		hostB = "private-b.acceptance.example.test"
		token = "private-access-token-trk17-0123456789abcdef"
	)
	routes := route.NewRegistry("preview.example.test", "runtime.example.test")
	rule := func(id, host, path string) route.RouteRule {
		return route.RouteRule{ID: id, Revision: 7, Generation: 1, RouteID: id, RouteGeneration: 7,
			AssignmentGeneration: 9, ResourceKind: "tunnel", SessionGeneration: 4,
			AccountID: "account_1", HostID: "connector_host_1", TunnelID: "tunnel_1",
			ConnectorID: "connector_1", ConnectorSessionID: "session_1",
			ConnectorProcessGeneration: 2, ConfigGeneration: 3, Node: "edge_1",
			EdgeProcessEpoch: "epoch_1", Kind: route.TunnelHTTPSWSS, MatchType: route.MatchExact,
			Hostname: host, PathPrefix: path, Target: "carrier://tunnel_1/" + id,
			Protocol: "http", AccessMode: "private", DesiredState: "active", ObservedState: "ready"}
	}
	if err := routes.StageGeneration(1, []route.RouteRule{rule("route_a", hostA, "/a"), rule("route_b", hostA, "/b"), rule("route_c", hostB, "/a")}); err != nil {
		t.Fatal(err)
	}
	if err := routes.MarkGenerationReady(1); err != nil {
		t.Fatal(err)
	}
	if err := routes.ActivateGeneration(context.Background(), 1, time.Second); err != nil {
		t.Fatal(err)
	}
	connections, err := NewPrivateAccessConnectionRegistry(16)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := New(Config{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: routes, PrivateAccessToken: token, PrivateAccessConnections: connections}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Accepted-Protocol", r.Proto)
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	upstream := listenTCP(t)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Caddy private connection header=%q remote=%q", r.Header.Get("X-Paperboat-Private-Connection"), r.RemoteAddr)
		policy.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = server.Serve(upstream) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	privateAddress := listenAddress(t)
	adminAddress := listenAddress(t)
	publicAddress := listenAddress(t)
	httpAddress := listenAddress(t)
	input := caddyconfig.Input{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", SignalingHost: "signal.example.test", PrivateUpstream: upstream.Addr().String(), ListenAddress: publicAddress, PrivateAccessListenAddress: privateAddress, PrivateAccessToken: token, HTTPListenAddress: httpAddress, AdminAddress: adminAddress, TrustedProxies: []string{"127.0.0.0/8"}, IssuerModule: "internal", PublicRoutes: []caddyconfig.PublicRoute{{Host: hostA, Upstream: upstream.Addr().String()}, {Host: hostB, Upstream: upstream.Addr().String()}}}
	configuration, err := caddyconfig.Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "caddy.json")
	if err := os.WriteFile(configPath, configuration, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(caddy, "run", "--config", configPath)
	command.Env = append(os.Environ(), "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	output := &boundedTestOutput{maximum: 64 << 10}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
		_, _ = command.Process.Wait()
	})
	waitForTCP(t, privateAddress, command, output)

	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			client, local := privateCaddyClient(t, privateAddress, hostA, tc.h2)
			expires := time.Now().UTC().Add(time.Minute)
			request := connectorprotocol.PrivateAccessRequest{AccountID: "account_1", ResourceKind: "tunnel", ResourceID: "tunnel_1", RouteID: "route_a", Audience: "paperboat-tunnel-http", DeviceID: "accessor_machine_2", SessionID: "installation_4", InstallationGeneration: 4, ExpiresAt: expires, Nonce: "nonce_1", CarrierSessionID: "session_1", ConnectorID: "connector_1", RouteGeneration: 7, ProcessGeneration: 2, ConfigGeneration: 3, SessionGeneration: 4, AssignmentGeneration: 9, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_1", Protocol: "http", Method: http.MethodConnect, Host: hostA, Path: "/a", IdempotencyKey: "access_1", RequestID: "request_1", CorrelationID: "correlation_1"}
			oldToken, err := connections.Register(local, request, expires)
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := connections.Register(local, request, expires)
			if err != nil {
				t.Fatal(err)
			}
			connections.Remove(local, oldToken)
			t.Cleanup(func() { connections.Remove(local, replacement) })
			assertCaddyStatus(t, client, hostA, "/a/ok", http.StatusNoContent)
			assertCaddyStatus(t, client, hostA, "/b/denied", http.StatusForbidden)
			otherClient, otherLocal := privateCaddyClient(t, privateAddress, hostB, tc.h2)
			otherToken, err := connections.Register(otherLocal, request, expires)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { connections.Remove(otherLocal, otherToken) })
			assertCaddyStatus(t, otherClient, hostB, "/a/denied", http.StatusForbidden)
		})
	}

	spoof := httptest.NewRequest(http.MethodGet, "https://"+hostA+"/a/spoof", nil)
	spoof.Host = hostA
	spoof.Header.Set("X-Paperboat-Private-Carrier", token)
	spoof.Header.Set("X-Paperboat-Private-Connection", "127.0.0.1:65530")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, spoof)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("public header spoof status=%d, want 401", recorder.Code)
	}
}

func validatePrivateCaddyBinaryPath(path string) error {
	if path == "" || strings.TrimSpace(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("PAPERBOAT_TEST_CADDY_BINARY must be an exact path without surrounding whitespace or control characters")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("PAPERBOAT_TEST_CADDY_BINARY is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("PAPERBOAT_TEST_CADDY_BINARY must name an executable regular file")
	}
	return nil
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func listenAddress(t *testing.T) string {
	t.Helper()
	l := listenTCP(t)
	address := l.Addr().String()
	_ = l.Close()
	return address
}
func privateCaddyClient(t *testing.T, target, serverName string, h2 bool) (*http.Client, string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tlsConfig := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // isolated internal-CA acceptance only
	if h2 {
		tlsConfig.NextProtos = []string{"h2"}
	} else {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}
	raw, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(raw, tlsConfig)
	if err := connection.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	used := false
	provide := func() (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if used {
			return nil, fmt.Errorf("acceptance connection already consumed")
		}
		used = true
		return connection, nil
	}
	if h2 {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http2.Transport{TLSClientConfig: tlsConfig, DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) { return provide() }}}, raw.LocalAddr().String()
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return provide() }, ForceAttemptHTTP2: false}}, raw.LocalAddr().String()
}
func assertCaddyStatus(t *testing.T, client *http.Client, host, path string, want int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		t.Fatalf("%s%s status=%d, want %d", host, path, res.StatusCode, want)
	}
}

type boundedTestOutput struct {
	data    []byte
	maximum int
}

func (b *boundedTestOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data) < b.maximum {
		remaining := b.maximum - len(b.data)
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *boundedTestOutput) String() string { return string(b.data) }
func waitForTCP(t *testing.T, address string, command *exec.Cmd, output fmt.Stringer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if command.ProcessState != nil {
			t.Fatalf("Caddy exited: %s", output.String())
		}
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Caddy did not listen on %s: %s", address, output.String())
}
