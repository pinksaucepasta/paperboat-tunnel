package edgehttp

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

type task24Descriptor struct {
	Protocol, Address, CACert, ClientCert, ClientKey, ReadyPath, StopPath, OriginsPath, AuthorityPath string
	Nodes                                                                                             []task30CarrierNode
}
type task24Origins struct{ HTTP, TCP string }
type task24Authority struct {
	HTTP, TCP connectorprotocol.IngressDecision
	Nodes     []task24Authority
}
type task24Usage struct{}

func (task24Usage) Record(string, string, uint64, uint64, uint64) error { return nil }

func TestTask24CrossRepositoryHTTPInterop(t *testing.T) {
	if os.Getenv("PAPERBOAT_TASK24_INTEROP") == "" {
		t.Skip("set PAPERBOAT_TASK24_INTEROP=1 for cross-repository process proof")
	}
	for _, protocol := range []string{"http3", "http2"} {
		t.Run(protocol, func(t *testing.T) { runTask24Interop(t, protocol) })
	}
}

func runTask24Interop(t *testing.T, protocol string) {
	clientTLS, serverTLS, caPEM, clientCertPEM, clientKeyPEM := task24Certificates(t)
	_ = clientTLS
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := datacarrier.EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(state tls.ConnectionState) (datacarrier.Identity, error) { return identity, nil }}
	config := datacarrier.ServiceConfig{Carrier: datacarrier.DefaultConfig()}
	config.Carrier.Authorize = datacarrier.AuthorizerFunc(func(_ context.Context, _ datacarrier.Identity, open datacarrier.StreamOpen) error {
		return open.Validate()
	})
	if protocol == "http3" {
		config.QUIC = &endpoint
	} else {
		config.TCP = &endpoint
	}
	service, err := datacarrier.NewHTTPService(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	address := service.TCPAddr()
	if protocol == "http3" {
		address = service.QUICAddr()
	}
	directory := t.TempDir()
	descriptorPath := filepath.Join(directory, "descriptor.json")
	readyPath := filepath.Join(directory, "ready")
	stopPath := filepath.Join(directory, "stop")
	originsPath := filepath.Join(directory, "origins.json")
	authorityPath := filepath.Join(directory, "authority.json")
	// This mode-0600 fixture is the independently supplied current edge
	// decision for transport integration. It does not stand in for deployed
	// control-plane issuance or durable SQL authority.
	descriptor := task24Descriptor{Protocol: protocol, Address: address.String(), CACert: string(caPEM), ClientCert: string(clientCertPEM), ClientKey: string(clientKeyPEM), ReadyPath: readyPath, StopPath: stopPath, OriginsPath: originsPath, AuthorityPath: authorityPath}
	encoded, _ := json.Marshal(descriptor)
	if err := os.WriteFile(descriptorPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs("../../../paperboat")
	if err != nil {
		t.Fatal(err)
	}
	var command *exec.Cmd
	if binary := os.Getenv("PAPERBOAT_TASK24_DAEMON_TEST_BINARY"); binary != "" {
		command = exec.CommandContext(ctx, binary, "-test.run=^TestTask24CrossRepositoryDaemon$", "-test.count=1")
	} else {
		command = exec.CommandContext(ctx, "go", "test", "./internal/hostruntime/tunnelmanager", "-run", "^TestTask24CrossRepositoryDaemon$", "-count=1")
		command.Dir = repo
	}
	command.Env = append(os.Environ(), "PAPERBOAT_TASK24_DESCRIPTOR="+descriptorPath)
	childDone := make(chan error, 1)
	go func() { childDone <- command.Run() }()
	var origins task24Origins
	for {
		contents, readErr := os.ReadFile(originsPath)
		if readErr == nil {
			if json.Unmarshal(contents, &origins) != nil {
				t.Fatal("invalid origins fixture")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case err := <-childDone:
			t.Fatalf("daemon exited before origins: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	publicTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer publicTCP.Close()
	publicPort := uint16(publicTCP.Addr().(*net.TCPAddr).Port)
	now := time.Now().UTC()
	decision := func(routeID, protocolName, hostname, originAddress, listenerID string, port uint16) connectorprotocol.IngressDecision {
		return connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_task24", AccountID: identity.AccountID, TunnelID: identity.TunnelID, Lifecycle: connectorprotocol.TunnelDurable, ResourceGeneration: 1, RouteID: routeID, RouteGeneration: 1, TargetID: "target_" + routeID, TargetGeneration: 1, HostID: identity.HostID, InstallationGeneration: 1, Audience: "public", ConnectionMethod: "edge", Protocol: protocolName, Hostname: hostname, PathPrefix: map[bool]string{true: "/"}[protocolName == "http"], OriginScheme: protocolName, OriginAddress: originAddress, TLSVerification: "not_applicable", PublicationID: "publication_" + routeID, PublicationGeneration: 1, ListenerID: listenerID, PublicPort: port}, DecisionID: "decision_" + routeID, PolicyGeneration: 1, EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, AssignmentGeneration: 1, Action: "view", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(9 * time.Second)}
	}
	httpDecision := decision("route_http", "http", "app.customer.test", origins.HTTP, "", 0)
	tcpDecision := decision("route_tcp", "tcp", "tcp.customer.test", origins.TCP, "listener_task24", publicPort)
	authorityJSON, _ := json.Marshal(task24Authority{HTTP: httpDecision, TCP: tcpDecision})
	if err := os.WriteFile(authorityPath, authorityJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case err := <-childDone:
			t.Fatalf("daemon exited before ready: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	gateway, registry := task24RouteGateway(t, ctx, server, httpDecision)
	bodyReader, bodyWriter := io.Pipe()
	go func() {
		_, _ = bodyWriter.Write([]byte("task24-"))
		time.Sleep(20 * time.Millisecond)
		_, _ = bodyWriter.Write([]byte("upload"))
		_ = bodyWriter.Close()
	}()
	request := httptest.NewRequest(http.MethodPost, "https://app.customer.test/stream", bodyReader)
	request.Host = "app.customer.test"
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "task24-origin-ok" {
		t.Fatalf("gateway response = %d %q", response.Code, response.Body.String())
	}
	webServer := httptest.NewServer(gateway)
	defer webServer.Close()
	connection, err := net.Dial("tcp", strings.TrimPrefix(webServer.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	_, _ = io.WriteString(connection, "GET /socket HTTP/1.1\r\nHost: app.customer.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n")
	wsResponse, err := http.ReadResponse(reader, nil)
	if err != nil || wsResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket response=%v err=%v", wsResponse, err)
	}
	_, _ = connection.Write([]byte("late"))
	payload := make([]byte, len("earlyecho:late"))
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "earlyecho:late" {
		t.Fatalf("websocket payload=%q err=%v", payload, err)
	}
	_ = connection.Close()
	publicEndpoint := net.JoinHostPort("localhost", strconv.Itoa(publicTCP.Addr().(*net.TCPAddr).Port))
	wrongClient, err := net.Dial("tcp", publicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	wrongAccepted, err := publicTCP.Accept()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.ActiveStreams() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	before := server.ActiveStreams()
	wrongDecision := tcpDecision
	wrongDecision.Binding.TargetID = "target_wrong"
	if err := registry.ForwardPublicTCP(ctx, wrongAccepted, wrongDecision, func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
		return tcpDecision, nil
	}); err == nil {
		t.Fatal("wrong target reached carrier")
	}
	_ = wrongAccepted.Close()
	_ = wrongClient.Close()
	time.Sleep(50 * time.Millisecond)
	if server.ActiveStreams() != before {
		t.Fatal("wrong target opened a carrier stream")
	}
	badClient, err := net.Dial("tcp", publicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	badAccepted, err := publicTCP.Accept()
	if err != nil {
		t.Fatal(err)
	}
	badDone := make(chan error, 1)
	go func() {
		badDone <- registry.ForwardPublicTCP(ctx, badAccepted, tcpDecision, func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
			return tcpDecision, nil
		})
	}()
	_, _ = badClient.Write([]byte("wrong-application-credential"))
	_ = badClient.(*net.TCPConn).CloseWrite()
	badReply, err := io.ReadAll(badClient)
	if err != nil || string(badReply) != "application-auth-rejected" {
		t.Fatalf("application auth reply=%q err=%v", badReply, err)
	}
	if err := <-badDone; err != nil {
		t.Fatal(err)
	}
	_ = badClient.Close()
	tcpClient, err := net.Dial("tcp", publicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := publicTCP.Accept()
	if err != nil {
		t.Fatal(err)
	}
	tcpDone := make(chan error, 1)
	go func() {
		tcpDone <- registry.ForwardPublicTCP(ctx, accepted, tcpDecision, func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
			return tcpDecision, nil
		})
	}()
	_, _ = tcpClient.Write([]byte("tcp-upload"))
	_ = tcpClient.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(tcpClient)
	if err != nil || string(reply) != "tcp-delayed-reply" {
		t.Fatalf("tcp reply=%q err=%v", reply, err)
	}
	if err := <-tcpDone; err != nil {
		t.Fatal(err)
	}
	_ = tcpClient.Close()
	if err := os.WriteFile(stopPath, []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-childDone; err != nil {
		t.Fatal(err)
	}
}

func task24Certificates(t *testing.T, extraNames ...string) (*tls.Config, *tls.Config, []byte, []byte, []byte) {
	return task24CertificatesWithKey(t, func() crypto.Signer {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}, extraNames...)
}

func task24CertificatesWithKey(t *testing.T, generate func() crypto.Signer, extraNames ...string) (*tls.Config, *tls.Config, []byte, []byte, []byte) {
	t.Helper()
	now := time.Now()
	caKey := generate()
	caPub := caKey.Public()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "task24 CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, name string, server bool) (tls.Certificate, []byte, []byte) {
		key := generate()
		pub := key.Public()
		usage := x509.ExtKeyUsageClientAuth
		if server {
			usage = x509.ExtKeyUsageServerAuth
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: append([]string{"localhost", "app.customer.test"}, extraNames...), IPAddresses: nil, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, _ := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certificate, _ := tls.X509KeyPair(certPEM, keyPEM)
		return certificate, certPEM, keyPEM
	}
	serverCert, _, _ := issue(2, "localhost", true)
	clientCert, clientPEM, clientKeyPEM := issue(3, "client", false)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "localhost"}, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, caPEM, clientPEM, clientKeyPEM
}
