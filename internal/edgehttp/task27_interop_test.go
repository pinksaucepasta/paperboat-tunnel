package edgehttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

type task27Descriptor struct {
	Address, CACert, ClientCert, ClientKey string
	AuthorityURL, AuthorityCA              string
	ReadyPath, StopPath                    string
	MachineID, AccountID, HostID           string
	TunnelID, ConnectorID, SessionID       string
	EdgeNodeID, EdgeProcessEpoch           string
	BootID                                 string
	InstallationGeneration                 int64
}

type task27Ready struct {
	DispatchURL            string `json:"dispatch_url"`
	OriginAddress          string `json:"origin_address"`
	BootID                 string `json:"boot_id"`
	InstallationGeneration int64  `json:"installation_generation"`
}

type task27State struct {
	State      string `json:"state"`
	Generation int64  `json:"generation"`
	OriginHits int64  `json:"origin_hits"`
	Stopped    bool   `json:"stopped"`
}

type task27LazyBinding struct {
	PolicyID               string `json:"policy_id"`
	PolicyGeneration       int64  `json:"policy_generation"`
	InstallationGeneration int64  `json:"installation_generation"`
	BootID                 string `json:"boot_id"`
}

type task27Target struct {
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
}

type task27Dispatch struct {
	Lazy               *task27LazyBinding `json:"lazy,omitempty"`
	Schema             string             `json:"schema"`
	Kind               string             `json:"kind"`
	PreviewID          string             `json:"preview_id"`
	OperationID        string             `json:"operation_id"`
	AccountID          string             `json:"account_id"`
	ActorID            string             `json:"actor_id"`
	OwnerDeviceID      string             `json:"owner_device_id"`
	OwnerSessionID     string             `json:"owner_session_id"`
	Target             task27Target       `json:"target"`
	AccessMode         string             `json:"access_mode"`
	Endpoint           string             `json:"endpoint"`
	LeaseDeadline      time.Time          `json:"lease_deadline"`
	UserDeadline       *time.Time         `json:"user_deadline,omitempty"`
	LeaseETag          string             `json:"lease_etag"`
	State              string             `json:"state"`
	AllocationState    string             `json:"allocation_state"`
	EdgeState          string             `json:"edge_state"`
	OriginState        string             `json:"origin_state"`
	CreatedAt          time.Time          `json:"created_at"`
	LastRenewedAt      time.Time          `json:"last_renewed_at"`
	ExpectedGeneration int64              `json:"expected_generation"`
	IdempotencyKey     string             `json:"idempotency_key"`
	RequestID          string             `json:"request_id"`
	CorrelationID      string             `json:"correlation_id"`
	RequestHash        string             `json:"request_hash"`
}

func (d *task27Dispatch) setHash() error {
	canonical := struct {
		Lazy               *task27LazyBinding `json:"lazy,omitempty"`
		Schema             string             `json:"schema"`
		Kind               string             `json:"kind"`
		PreviewID          string             `json:"preview_id"`
		OperationID        string             `json:"operation_id"`
		AccountID          string             `json:"account_id"`
		ActorID            string             `json:"actor_id"`
		OwnerDeviceID      string             `json:"owner_device_id"`
		OwnerSessionID     string             `json:"owner_session_id"`
		Target             task27Target       `json:"target"`
		AccessMode         string             `json:"access_mode"`
		Endpoint           string             `json:"endpoint"`
		LeaseDeadline      time.Time          `json:"lease_deadline"`
		UserDeadline       *time.Time         `json:"user_deadline,omitempty"`
		LeaseETag          string             `json:"lease_etag"`
		State              string             `json:"state"`
		AllocationState    string             `json:"allocation_state"`
		EdgeState          string             `json:"edge_state"`
		OriginState        string             `json:"origin_state"`
		CreatedAt          time.Time          `json:"created_at"`
		LastRenewedAt      time.Time          `json:"last_renewed_at"`
		ExpectedGeneration int64              `json:"expected_generation"`
		IdempotencyKey     string             `json:"idempotency_key"`
		RequestID          string             `json:"request_id"`
		CorrelationID      string             `json:"correlation_id"`
	}{d.Lazy, d.Schema, d.Kind, d.PreviewID, d.OperationID, d.AccountID, d.ActorID, d.OwnerDeviceID, d.OwnerSessionID, d.Target, d.AccessMode, d.Endpoint, d.LeaseDeadline.UTC(), d.UserDeadline, d.LeaseETag, d.State, d.AllocationState, d.EdgeState, d.OriginState, d.CreatedAt.UTC(), d.LastRenewedAt.UTC(), d.ExpectedGeneration, d.IdempotencyKey, d.RequestID, d.CorrelationID}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	d.RequestHash = hex.EncodeToString(digest[:])
	return nil
}

type task27Authority struct {
	current         func() connectorprotocol.IngressDecision
	activate        func(context.Context) error
	activationCalls atomic.Int32
}

func (*task27Authority) Begin(context.Context, string, string) (control.BrowserBegin, error) {
	return control.BrowserBegin{}, control.ErrBrowserDenied
}
func (*task27Authority) Redeem(context.Context, string, string, string, string) (control.BrowserSession, error) {
	return control.BrowserSession{}, control.ErrBrowserDenied
}
func (a *task27Authority) Authorize(_ context.Context, r control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	d := a.current()
	if r.Token != "fixture-session" || r.Host != d.Binding.Hostname || r.ResourceKind != "preview" || r.ResourceID != d.Binding.PublicationID || r.RouteID != d.Binding.RouteID {
		return connectorprotocol.IngressDecision{}, control.ErrBrowserDenied
	}
	return d, nil
}
func (a *task27Authority) Activate(ctx context.Context, r control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	a.activationCalls.Add(1)
	if r.Token != "fixture-session" || r.ResourceKind != "lazy_policy" || r.ResourceID != "" || r.RouteID != "" || r.Host != a.current().Binding.Hostname {
		return connectorprotocol.IngressDecision{}, control.ErrBrowserDenied
	}
	if err := a.activate(ctx); err != nil {
		return connectorprotocol.IngressDecision{}, err
	}
	return a.current(), nil
}

// TestTask27CrossRepositoryLazyActivation uses an explicit in-process policy
// authority seam. It proves the real edge carrier, daemon dispatch/lifecycle,
// daemon ingress authorization, and exact loopback origin path; SQL policy and
// multi-node activation coalescing are covered by server-side tests.
func TestTask27CrossRepositoryLazyActivation(t *testing.T) {
	binary := os.Getenv("PAPERBOAT_TASK27_DAEMON_TEST_BINARY")
	if binary == "" {
		t.Skip("requires the precompiled Task27 preview test binary")
	}
	_, serverTLS, ca, clientCert, clientKey := task24Certificates(t)
	identity := replicaIdentity("host_task27", "connector_task27", "session_task27", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	endpoint := datacarrier.EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (datacarrier.Identity, error) { return identity, nil }}
	carrierConfig := datacarrier.ServiceConfig{TCP: &endpoint, Carrier: datacarrier.DefaultConfig()}
	var openMu sync.Mutex
	var observedOpen datacarrier.StreamOpen
	carrierConfig.Carrier.Authorize = datacarrier.AuthorizerFunc(func(_ context.Context, _ datacarrier.Identity, open datacarrier.StreamOpen) error {
		openMu.Lock()
		observedOpen = open
		openMu.Unlock()
		return open.Validate()
	})
	service, err := datacarrier.NewHTTPService(ctx, carrierConfig)
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
	var machineCalls atomic.Int32
	machineAuthority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machineCalls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/browser-access/ingress/authorize" || r.Header.Get("X-Paperboat-Machine-Proof") == "" {
			http.Error(w, "invalid machine proof", 401)
			return
		}
		var input struct {
			Decision connectorprotocol.IngressDecision `json:"decision"`
			Open     connectorprotocol.StreamOpen      `json:"open"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&input) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		d := current()
		claim := input.Decision
		claim.IssuedAt, claim.ExpiresAt = d.IssuedAt, d.ExpiresAt
		if authorizationErr := claim.Authorize(d, input.Open, d.EdgeNodeID, d.EdgeProcessEpoch, time.Now().UTC()); authorizationErr != nil {
			t.Logf("daemon ingress rejected: %v open=%+v claim=%+v authority=%+v", authorizationErr, input.Open, claim, d)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": d})
	}))
	defer machineAuthority.Close()
	directory := t.TempDir()
	descriptorPath := filepath.Join(directory, "descriptor.json")
	descriptor := task27Descriptor{Address: service.TCPAddr().String(), CACert: string(ca), ClientCert: string(clientCert), ClientKey: string(clientKey), AuthorityURL: machineAuthority.URL, AuthorityCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: machineAuthority.Certificate().Raw})), ReadyPath: filepath.Join(directory, "ready.json"), StopPath: filepath.Join(directory, "stop"), MachineID: identity.HostID, AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, EdgeNodeID: "edge_task27", EdgeProcessEpoch: "epoch_task27_12345678", BootID: "task27-boot-0123456789abcdef", InstallationGeneration: 7}
	raw, _ := json.Marshal(descriptor)
	if err = os.WriteFile(descriptorPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := exec.CommandContext(ctx, binary, "-test.run=^TestTask27LazyDaemonInterop$", "-test.count=1")
	command.Env = append(os.Environ(), "PAPERBOAT_TASK27_DESCRIPTOR="+descriptorPath)
	command.Stdout = &output
	command.Stderr = &output
	childDone := make(chan struct{})
	var childErr error
	go func() { childErr = command.Run(); close(childDone) }()
	defer func() {
		_ = os.WriteFile(descriptor.StopPath, []byte("stop"), 0600)
		select {
		case <-childDone:
		case <-time.After(3 * time.Second):
			cancel()
			<-childDone
		}
		if childErr != nil && !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("daemon: %v %s", childErr, output.String())
		}
	}()
	server, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	waitReady := func() task27Ready {
		for {
			if data, e := os.ReadFile(descriptor.ReadyPath); e == nil {
				var ready task27Ready
				if json.Unmarshal(data, &ready) == nil {
					return ready
				}
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
	ready := waitReady()
	host := "p3000-abcdefghijklmnop.preview.example.test"
	now := time.Now().UTC()
	decision = connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_task27", AccountID: identity.AccountID, TunnelID: identity.TunnelID, Lifecycle: "ephemeral", ResourceGeneration: 1, RouteID: "preview_task27", RouteGeneration: 1, TargetID: "preview_task27", TargetGeneration: 1, HostID: identity.HostID, InstallationGeneration: 7, Audience: "private", ConnectionMethod: "edge", Protocol: "http", Hostname: host, PathPrefix: "/", OriginScheme: "http", OriginAddress: ready.OriginAddress, TLSVerification: "not_applicable", PublicationID: "preview_task27", PublicationGeneration: 1}, DecisionID: "decision_task27", PolicyGeneration: 2, EdgeNodeID: "edge_task27", EdgeProcessEpoch: "epoch_task27_12345678", ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, AssignmentGeneration: 1, PrincipalID: "viewer_task27", GrantID: "grant_task27", GrantGeneration: 1, Action: "view", IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	if err := decision.Validate(decision.IssuedAt); err != nil {
		t.Fatalf("fixture decision invalid: %v", err)
	}
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "epoch_task27_12345678", MaximumRoutes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	transport, err := NewDataCarrierPreviewTransport(DataCarrierPreviewTransportConfig{Registry: registry, StreamOpenTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var dispatches atomic.Int32
	authority := &task27Authority{current: current}
	authority.activate = func(activationCtx context.Context) error {
		dispatches.Add(1)
		created := time.Now().UTC()
		request := task27Dispatch{Lazy: &task27LazyBinding{PolicyID: "policy_task27", PolicyGeneration: 2, InstallationGeneration: ready.InstallationGeneration, BootID: ready.BootID}, Schema: "paperboat.preview-tunnel/v1", Kind: "preview_dispatch", PreviewID: "preview_task27", OperationID: "operation_task27", AccountID: identity.AccountID, ActorID: "actor_task27", OwnerDeviceID: identity.HostID, OwnerSessionID: "lazy_" + ready.BootID, Target: task27Target{Scheme: "http", Address: ready.OriginAddress}, AccessMode: "private", Endpoint: "https://" + host, LeaseDeadline: created.Add(time.Hour), LeaseETag: fmt.Sprintf(`"ptv1:preview_lease:%s:1"`, base64.RawURLEncoding.EncodeToString([]byte("preview_task27"))), State: "allocating", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: created, LastRenewedAt: created, ExpectedGeneration: 1, IdempotencyKey: "task27_dispatch_key", RequestID: "request_task27", CorrelationID: "correlation_task27"}
		if err := request.setHash(); err != nil {
			return err
		}
		payload, _ := json.Marshal(request)
		req, _ := http.NewRequestWithContext(activationCtx, http.MethodPost, ready.DispatchURL+"/dispatch", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			body, _ := io.ReadAll(response.Body)
			return fmt.Errorf("dispatch status %d: %s", response.StatusCode, body)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			var state task27State
			resp, e := http.Get(ready.DispatchURL + "/status")
			if e == nil {
				e = json.NewDecoder(resp.Body).Decode(&state)
				resp.Body.Close()
			}
			if e == nil && state.State == "ready" {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("daemon readiness timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return registry.Attach(DataCarrierPreviewRoute{RouteID: "preview_task27", Hostname: host, Kind: dataCarrierPreviewPrivateRouteKind, Revision: 1, Server: server, PreviewID: "preview_task27", AccessMode: "private", EdgeNodeID: "edge_task27", EdgeProcessEpoch: "epoch_task27_12345678", ExpiresAt: time.Now().Add(time.Hour)})
	}
	gateway, err := NewGatewayWithTransports(Config{BrowserAccess: &BrowserAccess{Authority: authority, LazyAuthority: authority, LoginOrigin: "https://login.example.test"}, PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: NewCompositeRouteMatcher(NewPreviewCarrierRouteMatcher(registry)), RequestID: func() string { return "request_task27" }}, "127.0.0.1:1", transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(gateway)
	defer web.Close()
	client := &http.Client{Timeout: 12 * time.Second}
	requestEdge := func(authorized bool) (int, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, web.URL+"/service", nil)
		req.Host = host
		if authorized {
			req.Header.Set("Cookie", "__Host-pb-edge=fixture-session")
			req.Header.Set("Origin", "https://"+host)
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	status, body := requestEdge(false)
	if status < 400 || dispatches.Load() != 0 || machineCalls.Load() != 0 {
		t.Fatalf("unauthorized status=%d body=%q dispatches=%d machine=%d", status, body, dispatches.Load(), machineCalls.Load())
	}
	status, body = requestEdge(true)
	if status != 200 || body != "task27-origin-v1" || dispatches.Load() != 1 {
		var daemonState task27State
		if probe, probeErr := http.Get(ready.DispatchURL + "/status"); probeErr == nil {
			_ = json.NewDecoder(probe.Body).Decode(&daemonState)
			probe.Body.Close()
		}
		openMu.Lock()
		lastOpen := observedOpen
		openMu.Unlock()
		t.Fatalf("v1 status=%d body=%q dispatches=%d machine_calls=%d daemon=%#v open=%#v identity=%#v output=%s", status, body, dispatches.Load(), machineCalls.Load(), daemonState, lastOpen, identity, output.String())
	}
	replace, err := http.Post(ready.DispatchURL+"/replace", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	replace.Body.Close()
	if replace.StatusCode != http.StatusNoContent {
		t.Fatalf("replace=%d", replace.StatusCode)
	}
	status, body = requestEdge(true)
	if status != 200 || body != "task27-origin-v2" || dispatches.Load() != 1 {
		t.Fatalf("v2 status=%d body=%q dispatches=%d", status, body, dispatches.Load())
	}
	var state task27State
	resp, err := http.Get(ready.DispatchURL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	if json.NewDecoder(resp.Body).Decode(&state) != nil {
		t.Fatal("invalid daemon status")
	}
	resp.Body.Close()
	if state.OriginHits != 2 || state.Stopped {
		t.Fatalf("daemon state=%#v", state)
	}
}
