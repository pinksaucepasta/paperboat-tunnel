package edgehttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

type task30CarrierNode struct{ Address, NodeID, Epoch, Domain string }
type task30EdgeFixture struct {
	LifetimeSeconds                                                             int
	DockerSimulation                                                            bool
	Node                                                                        task30CarrierNode
	IP, HTTPPort, TCPPort, CA, Cert, Key, CarrierPath, AuthorityPath, ReadyPath string
}

func task30Write(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func task30Read(t *testing.T, ctx context.Context, path string, value any) {
	t.Helper()
	for {
		b, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(b, value) == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Each helper is a separate OS process with its own carrier, routing and public listeners.
func TestTask30EdgeProcess(t *testing.T) {
	path := os.Getenv("PAPERBOAT_TASK30_EDGE")
	if path == "" {
		t.Skip("coordinator helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	var f task30EdgeFixture
	task30Read(t, ctx, path, &f)
	lifetime := 30 * time.Second
	if f.DockerSimulation {
		lifetime = 120 * time.Second
		if f.LifetimeSeconds >= 120 && f.LifetimeSeconds <= 900 {
			lifetime = time.Duration(f.LifetimeSeconds) * time.Second
		}
	}
	timer := time.AfterFunc(lifetime, cancel)
	defer timer.Stop()
	certificate, err := tls.X509KeyPair([]byte(f.Cert), []byte(f.Key))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(f.CA)) {
		t.Fatal("invalid CA")
	}
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	listenAddress := "127.0.0.1:0"
	if f.DockerSimulation {
		listenAddress = "0.0.0.0:27443"
	}
	endpoint := datacarrier.EndpointConfig{Address: listenAddress, TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, PeerBinding: func(tls.ConnectionState) (datacarrier.Identity, error) { return identity, nil }}
	config := datacarrier.ServiceConfig{TCP: &endpoint, Carrier: datacarrier.DefaultConfig()}
	config.Carrier.Authorize = datacarrier.AuthorizerFunc(func(_ context.Context, _ datacarrier.Identity, o datacarrier.StreamOpen) error { return o.Validate() })
	service, err := datacarrier.NewHTTPService(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if !f.DockerSimulation {
		f.Node.Address = service.TCPAddr().String()
	}
	task30Write(t, f.CarrierPath, f.Node)
	var authority task24Authority
	task30Read(t, ctx, f.AuthorityPath, &authority)
	server, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	gateway, registry := task24RouteGateway(t, ctx, server, authority.HTTP, f.DockerSimulation)
	webListener, err := net.Listen("tcp", net.JoinHostPort(f.IP, f.HTTPPort))
	if err != nil {
		t.Fatal(err)
	}
	handler := http.Handler(gateway)
	if f.DockerSimulation {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Task30-Edge", f.Node.NodeID)
			gateway.ServeHTTP(w, r)
		})
	}
	web := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	defer web.Close()
	go web.Serve(tls.NewListener(webListener, web.TLSConfig))
	tcpListener, err := net.Listen("tcp", net.JoinHostPort(f.IP, f.TCPPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				initial := authority.TCP
				if f.DockerSimulation {
					initial.IssuedAt = time.Now().UTC()
					initial.ExpiresAt = initial.IssuedAt.Add(10 * time.Second)
				}
				_ = registry.ForwardPublicTCP(ctx, conn, initial, func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
					d := authority.TCP
					if f.DockerSimulation {
						d.IssuedAt = time.Now().UTC()
						d.ExpiresAt = d.IssuedAt.Add(10 * time.Second)
					}
					return d, nil
				})
			}()
		}
	}()
	task30Write(t, f.ReadyPath, true)
	<-ctx.Done()
}

// This fixture selects concrete cached addresses; it does not claim public DNS recovery.
func TestTask30TwoEdgeProcessRecovery(t *testing.T) {
	daemonBinary := os.Getenv("PAPERBOAT_TASK30_DAEMON_TEST_BINARY")
	if daemonBinary == "" {
		t.Skip("requires explicitly built daemon test binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	directory := t.TempDir()
	_, serverTLS, ca, clientCert, clientKey := task24Certificates(t)
	cert := serverTLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	freePort := func() string {
		l, err := net.Listen("tcp", "127.0.0.2:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	}
	httpPort, tcpPort := freePort(), freePort()
	var children []*exec.Cmd
	outputs := map[*exec.Cmd]*bytes.Buffer{}
	start := func(binary, run, env string) *exec.Cmd {
		c := exec.CommandContext(ctx, binary, "-test.run=^"+run+"$", "-test.count=1")
		c.Env = append(os.Environ(), env)
		output := &bytes.Buffer{}
		c.Stdout = output
		c.Stderr = output
		outputs[c] = output
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		children = append(children, c)
		return c
	}
	defer func() {
		for _, c := range children {
			_ = c.Process.Kill()
			_ = c.Wait()
			if t.Failed() {
				t.Logf("child output: %s", outputs[c].String())
			}
		}
	}()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]task30CarrierNode, 2)
	fixtures := make([]task30EdgeFixture, 2)
	for i := range 2 {
		prefix := filepath.Join(directory, fmt.Sprint(i))
		f := task30EdgeFixture{Node: task30CarrierNode{NodeID: fmt.Sprintf("edge_0%d", i+1), Epoch: fmt.Sprintf("epoch_000%d", i+1), Domain: fmt.Sprintf("domain_%d", i)}, IP: fmt.Sprintf("127.0.0.%d", i+2), HTTPPort: httpPort, TCPPort: tcpPort, CA: string(ca), Cert: string(certPEM), Key: string(keyPEM), CarrierPath: prefix + "-carrier", AuthorityPath: prefix + "-authority", ReadyPath: prefix + "-ready"}
		task30Write(t, prefix+"-fixture", f)
		start(self, "TestTask30EdgeProcess", "PAPERBOAT_TASK30_EDGE="+prefix+"-fixture")
		task30Read(t, ctx, f.CarrierPath, &nodes[i])
		fixtures[i] = f
	}
	descriptor := task24Descriptor{Protocol: "http2", CACert: string(ca), ClientCert: string(clientCert), ClientKey: string(clientKey), OriginsPath: filepath.Join(directory, "origins"), AuthorityPath: filepath.Join(directory, "daemon-authority"), ReadyPath: filepath.Join(directory, "daemon-ready"), StopPath: filepath.Join(directory, "stop"), Nodes: nodes}
	descriptorPath := filepath.Join(directory, "daemon-descriptor")
	task30Write(t, descriptorPath, descriptor)
	start(daemonBinary, "TestTask24CrossRepositoryDaemon", "PAPERBOAT_TASK24_DESCRIPTOR="+descriptorPath)
	var origins task24Origins
	task30Read(t, ctx, descriptor.OriginsPath, &origins)
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	now := time.Now().UTC()
	port, _ := strconv.Atoi(tcpPort)
	decision := func(node task30CarrierNode, protocol, origin string) connectorprotocol.IngressDecision {
		id := "route_" + protocol
		host := "app.customer.test"
		listener := ""
		publicPort := uint16(0)
		path := "/"
		if protocol == "tcp" {
			host = "tcp.customer.test"
			listener = "listener_task30"
			publicPort = uint16(port)
			path = ""
		}
		return connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_task24", AccountID: identity.AccountID, TunnelID: identity.TunnelID, Lifecycle: connectorprotocol.TunnelDurable, ResourceGeneration: 1, RouteID: id, RouteGeneration: 1, TargetID: "target_" + id, TargetGeneration: 1, HostID: identity.HostID, InstallationGeneration: 1, Audience: "public", ConnectionMethod: "edge", Protocol: protocol, Hostname: host, PathPrefix: path, OriginScheme: protocol, OriginAddress: origin, TLSVerification: "not_applicable", PublicationID: "publication_" + id, PublicationGeneration: 1, ListenerID: listener, PublicPort: publicPort}, DecisionID: "decision_" + id, PolicyGeneration: 1, EdgeNodeID: node.NodeID, EdgeProcessEpoch: node.Epoch, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, AssignmentGeneration: 1, Action: "view", IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	}
	var authorities task24Authority
	for i, node := range nodes {
		a := task24Authority{HTTP: decision(node, "http", origins.HTTP), TCP: decision(node, "tcp", origins.TCP)}
		authorities.Nodes = append(authorities.Nodes, a)
		task30Write(t, fixtures[i].AuthorityPath, a)
	}
	task30Write(t, descriptor.AuthorityPath, authorities)
	for _, f := range fixtures {
		var ready bool
		task30Read(t, ctx, f.ReadyPath, &ready)
	}
	for {
		if _, err := os.Stat(descriptor.ReadyPath); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	requestHTTP := func(i int) {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(fixtures[i].IP, httpPort))
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.customer.test/stream", strings.NewReader("task24-upload"))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != 200 || !bytes.Equal(body, []byte("task24-origin-ok")) {
			t.Fatalf("edge%d HTTP status=%d body=%q", i, response.StatusCode, body)
		}
	}
	requestTCP := func(i int) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(fixtures[i].IP, tcpPort), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(conn, "tcp-upload")
		conn.(*net.TCPConn).CloseWrite()
		body, err := io.ReadAll(conn)
		if err != nil || string(body) != "tcp-delayed-reply" {
			t.Fatalf("edge%d TCP body=%q err=%v", i, body, err)
		}
	}
	requestHTTP(0)
	requestHTTP(1)
	requestTCP(0)
	failedAt := time.Now()
	if err := children[0].Process.Kill(); err != nil {
		t.Fatal(err)
	}
	requestHTTP(1)
	requestTCP(1)
	if elapsed := time.Since(failedAt); elapsed > 20*time.Second {
		t.Fatalf("standby recovery took %v", elapsed)
	}
	t.Logf("two edge processes served the same HTTP hostname/certificate and TCP port; fresh survivor requests recovered in %s", time.Since(failedAt))
	if err := os.WriteFile(descriptor.StopPath, []byte("stop"), 0600); err != nil {
		t.Fatal(err)
	}
}
