package edgehttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

type task26Descriptor struct{ Address, CACert, ClientCert, ClientKey, AuthorityURL, AuthorityCA, OriginsPath, ReadyPath, StopPath string }
type task26Origins struct{ Address, URL string }
type task26Stats struct{ Hits, Active, Stopped int32 }
type task26BrowserAuthority struct {
	current func() connectorprotocol.IngressDecision
	revoked atomic.Bool
}

func (*task26BrowserAuthority) Begin(context.Context, string, string) (control.BrowserBegin, error) {
	return control.BrowserBegin{}, control.ErrBrowserDenied
}
func (*task26BrowserAuthority) Redeem(context.Context, string, string, string, string) (control.BrowserSession, error) {
	return control.BrowserSession{}, control.ErrBrowserDenied
}
func (a *task26BrowserAuthority) Authorize(_ context.Context, r control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	if r.Token != "fixture-session" || r.Host != "app.preview.example.test" || r.ResourceKind != "preview" || r.ResourceID != "preview_browser" || r.RouteID != "route_browser" || a.revoked.Load() {
		return connectorprotocol.IngressDecision{}, control.ErrBrowserDenied
	}
	return a.current(), nil
}

// The authority server is an explicit protocol seam. This proves the actual
// edge/daemon H2 connector behavior, not database grants or production login.
func TestTask26CrossRepositoryRestrictedBrowserHTTP2(t *testing.T) {
	binary := os.Getenv("PAPERBOAT_TASK26_DAEMON_TEST_BINARY")
	if binary == "" {
		t.Skip("requires explicitly built preview test binary")
	}
	_, serverTLS, ca, clientCert, clientKey := task24Certificates(t)
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := datacarrier.EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (datacarrier.Identity, error) { return identity, nil }}
	config := datacarrier.ServiceConfig{TCP: &endpoint, Carrier: datacarrier.DefaultConfig()}
	config.Carrier.Authorize = datacarrier.AuthorizerFunc(func(_ context.Context, _ datacarrier.Identity, open datacarrier.StreamOpen) error {
		return open.Validate()
	})
	service, err := datacarrier.NewHTTPService(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var mu sync.RWMutex
	var decision connectorprotocol.IngressDecision
	current := func() connectorprotocol.IngressDecision {
		mu.RLock()
		d := decision
		mu.RUnlock()
		d.IssuedAt = time.Now().UTC()
		d.ExpiresAt = d.IssuedAt.Add(10 * time.Second)
		return d
	}
	browser := &task26BrowserAuthority{current: current}
	var daemonDenied, controlLost atomic.Bool
	var machineCalls atomic.Int32
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machineCalls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/browser-access/ingress/authorize" || r.Header.Get("Authorization") != "Bearer task26-machine-fixture" || r.Header.Get("X-Paperboat-Machine-Identity") != "task26-machine-fixture" || r.Header.Get("X-Paperboat-Machine-Proof") == "" || r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "invalid machine proof fixture", 401)
			return
		}
		if controlLost.Load() {
			http.Error(w, "control unavailable", 503)
			return
		}
		if daemonDenied.Load() || browser.revoked.Load() {
			http.NotFound(w, r)
			return
		}
		var input struct {
			Decision connectorprotocol.IngressDecision `json:"decision"`
			Open     connectorprotocol.StreamOpen      `json:"open"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&input) != nil {
			http.Error(w, "invalid input", 400)
			return
		}
		d := current()
		claim := input.Decision
		claim.IssuedAt, claim.ExpiresAt = d.IssuedAt, d.ExpiresAt
		if input.Open.Kind != "http_browser" || claim.Authorize(d, input.Open, d.EdgeNodeID, d.EdgeProcessEpoch, time.Now()) != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": d})
	}))
	defer authority.Close()
	directory := t.TempDir()
	descriptorPath := filepath.Join(directory, "descriptor.json")
	d := task26Descriptor{Address: service.TCPAddr().String(), CACert: string(ca), ClientCert: string(clientCert), ClientKey: string(clientKey), AuthorityURL: authority.URL, AuthorityCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate().Raw})), OriginsPath: filepath.Join(directory, "origins.json"), ReadyPath: filepath.Join(directory, "ready"), StopPath: filepath.Join(directory, "stop")}
	encoded, _ := json.Marshal(d)
	if err = os.WriteFile(descriptorPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := exec.CommandContext(ctx, binary, "-test.run=^TestTask26CrossRepositoryBrowserDaemon$", "-test.count=1")
	command.Env = append(os.Environ(), "PAPERBOAT_TASK26_DESCRIPTOR="+descriptorPath)
	command.Stdout = &output
	command.Stderr = &output
	childDone := make(chan struct{})
	var childErr error
	go func() { childErr = command.Run(); close(childDone) }()
	defer func() {
		cancel()
		<-childDone
		if childErr != nil && !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("daemon: %v %s", childErr, output.String())
		}
	}()
	waitFile := func(path string) []byte {
		t.Helper()
		for {
			if raw, err := os.ReadFile(path); err == nil {
				return raw
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-childDone:
				t.Fatalf("daemon exited: %v %s", childErr, output.String())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	var origins task26Origins
	if json.Unmarshal(waitFile(d.OriginsPath), &origins) != nil {
		t.Fatal("invalid origins")
	}
	now := time.Now().UTC()
	mu.Lock()
	decision = connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_task26", AccountID: identity.AccountID, TunnelID: identity.TunnelID, Lifecycle: "ephemeral", ResourceGeneration: 1, RouteID: "route_browser", RouteGeneration: 1, TargetID: "route_browser", TargetGeneration: 1, HostID: identity.HostID, InstallationGeneration: 1, Audience: "team", ConnectionMethod: "edge", Protocol: "http", Hostname: "app.preview.example.test", PathPrefix: "/", OriginScheme: "http", OriginAddress: origins.Address, TLSVerification: "not_applicable", PublicationID: "preview_browser", PublicationGeneration: 1}, DecisionID: "decision_browser", PolicyGeneration: 1, EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, AssignmentGeneration: 1, PrincipalID: "viewer_browser", GrantID: "grant_browser", GrantGeneration: 1, MembershipGeneration: 1, Action: "view", IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	mu.Unlock()
	server, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	waitFile(d.ReadyPath)
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "epoch_0001", MaximumRoutes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err = registry.Attach(DataCarrierPreviewRoute{RouteID: "route_browser", Hostname: "app.preview.example.test", Kind: dataCarrierPreviewPrivateRouteKind, Revision: 1, Server: server, PreviewID: "preview_browser", AccessMode: "team", EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	transport, err := NewDataCarrierPreviewTransport(DataCarrierPreviewTransportConfig{Registry: registry, StreamOpenTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGatewayWithTransports(Config{BrowserAccess: &BrowserAccess{Authority: browser, LoginOrigin: "https://login.example.test"}, PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: NewCompositeRouteMatcher(NewPreviewCarrierRouteMatcher(registry)), RequestID: func() string { return "task26-request" }}, "127.0.0.1:1", transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(gateway)
	defer web.Close()
	client := &http.Client{Timeout: 12 * time.Second}
	request := func(path string) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, "GET", web.URL+path, nil)
		r.Host = "app.preview.example.test"
		r.Header.Set("Cookie", "__Host-pb-edge=fixture-session; app=keep")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	stats := func() task26Stats {
		t.Helper()
		response, err := client.Get(origins.URL + "/stats")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var s task26Stats
		if json.NewDecoder(response.Body).Decode(&s) != nil {
			t.Fatal("invalid origin stats")
		}
		return s
	}
	response := request("/hello")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "task26-browser-origin-ok" {
		t.Fatalf("browser response=%d %q", response.StatusCode, body)
	}
	before := stats().Hits
	daemonDenied.Store(true)
	response = request("/hello")
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode < 400 || stats().Hits != before {
		t.Fatal("daemon-denied request reached origin")
	}
	daemonDenied.Store(false)
	for _, failure := range []string{"revoked", "daemon-control-loss"} {
		t.Run(failure, func(t *testing.T) {
			response := request("/stream")
			if response.StatusCode != 200 {
				response.Body.Close()
				t.Fatalf("stream status %d", response.StatusCode)
			}
			initial := make([]byte, len("data: active\n\n"))
			if _, err := io.ReadFull(response.Body, initial); err != nil {
				t.Fatal(err)
			}
			if failure == "revoked" {
				browser.revoked.Store(true)
			} else {
				controlLost.Store(true)
			}
			started := time.Now()
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			for stats().Active != 0 && time.Since(started) < 11*time.Second {
				time.Sleep(10 * time.Millisecond)
			}
			if stats().Active != 0 || time.Since(started) > 11*time.Second {
				t.Fatal("active origin did not close within authority freshness bound")
			}
			browser.revoked.Store(false)
			controlLost.Store(false)
			recovery := request("/hello")
			payload, _ := io.ReadAll(recovery.Body)
			recovery.Body.Close()
			if recovery.StatusCode != 200 || string(payload) != "task26-browser-origin-ok" {
				t.Fatal("authorized recovery failed")
			}
		})
	}
	if machineCalls.Load() < 5 || stats().Stopped != 2 {
		t.Fatalf("independent machine checks=%d origin stats=%+v", machineCalls.Load(), stats())
	}
	if err = os.WriteFile(d.StopPath, []byte("stop"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-childDone:
		if childErr != nil {
			t.Fatalf("daemon: %v %s", childErr, output.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
