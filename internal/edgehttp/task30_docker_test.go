package edgehttp

// This opt-in integration runs only on the approved remote Docker host. Docker
// DNS and fixture authority isolate the simulated outage from deployed services.
import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"golang.org/x/net/dns/dnsmessage"
)

type task30ClientFixture struct {
	CA, ResultPath, Prefix                          string
	HTTPHostname, TCPHostname, HTTPPort, DNSAddress string
	DNSOnly                                         bool
	Hold                                            bool
	HeldPath                                        string
	ExpectedIPs                                     []string
	DirectIPs                                       []string
}
type task30ClientResult struct {
	Edge, TCPAddress, Certificate string
	Addresses                     []string
	TTL                           uint32
	IDs                           []string
}

func TestTask30DockerClient(t *testing.T) {
	path := os.Getenv("PAPERBOAT_TASK30_CLIENT")
	if path == "" {
		t.Skip("Docker coordinator helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var f task30ClientFixture
	task30Read(t, ctx, path, &f)
	if f.HTTPHostname == "" {
		f.HTTPHostname = "app.customer.test"
	}
	if f.TCPHostname == "" {
		f.TCPHostname = "tcp.customer.test"
	}
	if f.HTTPPort == "" {
		f.HTTPPort = "443"
	}
	if f.DNSAddress == "" {
		f.DNSAddress = "127.0.0.11:53"
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(f.CA)) {
		t.Fatal("invalid CA")
	}
	result := task30ClientResult{}
	// Resolve through the container's ordinary resolver, without --add-host or a
	// custom DialContext. Independently inspect the DNS response's real TTL.
	addresses, err := net.DefaultResolver.LookupHost(ctx, f.HTTPHostname)
	if err != nil {
		dnsErr, ok := err.(*net.DNSError)
		if !f.DNSOnly || len(f.ExpectedIPs) != 0 || !ok || !dnsErr.IsNotFound {
			t.Fatal(err)
		}
		addresses = nil
	}
	sort.Strings(addresses)
	sort.Strings(f.ExpectedIPs)
	if strings.Join(addresses, ",") != strings.Join(f.ExpectedIPs, ",") {
		t.Fatalf("DNS addresses %v want %v", addresses, f.ExpectedIPs)
	}
	result.Addresses = addresses
	dns, err := net.DialTimeout("udp", f.DNSAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	_ = dns.SetDeadline(time.Now().Add(time.Second))
	question := dnsmessage.Message{Header: dnsmessage.Header{ID: 30, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(f.HTTPHostname + "."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}}}
	if f.HTTPHostname == "app.customer.test" {
		question.Questions[0].Type = dnsmessage.TypeA
	}
	wire, _ := question.Pack()
	if _, err = dns.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := dns.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if len(answer.Answers) == 0 {
		if !f.DNSOnly || len(f.ExpectedIPs) != 0 {
			t.Fatal("DNS returned no answers")
		}
	} else {
		result.TTL = answer.Answers[0].Header.TTL
	}
	if f.DNSOnly {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://" + net.JoinHostPort(f.HTTPHostname, f.HTTPPort) + "/stream")
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			t.Fatal("unavailable hostname still served HTTP")
		}
		task30Write(t, f.ResultPath, result)
		return
	}
	if f.Hold {
		id := f.Prefix + "-interrupted-http"
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			address, _, _ := net.SplitHostPort(info.Conn.RemoteAddr().String())
			task30Write(t, f.HeldPath, task30ClientResult{TCPAddress: address, IDs: []string{id}})
		}}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, "https://"+net.JoinHostPort(f.HTTPHostname, f.HTTPPort)+"/stream", strings.NewReader("task24-upload"))
		req.Header.Set("X-Task30-ID", id)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			t.Fatal("interrupted POST unexpectedly succeeded")
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("interrupted POST waited for timeout")
		}
		task30Write(t, f.ResultPath, task30ClientResult{IDs: []string{id}})
		return
	}

	request := func(client *http.Client, id string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(f.HTTPHostname, f.HTTPPort)+"/stream", strings.NewReader("task24-upload"))
		req.Header.Set("X-Task30-ID", id)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != 200 || string(body) != "task24-origin-ok" {
			t.Fatalf("HTTP status=%d error=%v", response.StatusCode, err)
		}
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(response.TLS.PeerCertificates[0].Raw))
		if result.Certificate != "" && result.Certificate != fingerprint {
			t.Fatal("certificate changed between endpoints")
		}
		result.Certificate = fingerprint
		result.Edge = response.Header.Get("X-Task30-Edge")
		if result.Edge == "" {
			t.Fatal("missing observed edge")
		}
		result.IDs = append(result.IDs, id)
	}
	// Direct baseline probes only establish independent endpoint readiness. The
	// failover request below never chooses an address or substitutes a hostname.
	for i, ip := range f.DirectIPs {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, f.HTTPPort))
		}}
		request(&http.Client{Transport: transport, Timeout: 3 * time.Second}, fmt.Sprintf("%s-direct-%d", f.Prefix, i))
		transport.CloseIdleConnections()
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	request(&http.Client{Transport: transport, Timeout: 5 * time.Second}, f.Prefix+"-normal-http")
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(f.TCPHostname, "25001"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	id := f.Prefix + "-normal-tcp"
	if _, err = io.WriteString(conn, "tcp-upload:"+id); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "tcp-delayed-reply" {
		t.Fatalf("TCP reply error=%v", err)
	}
	result.TCPAddress, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	result.IDs = append(result.IDs, id)
	task30Write(t, f.ResultPath, result)
}

type task30LiveFixture struct {
	HTTPHostname, TCPHostname, DNSAddress, Publisher string
	PublicIPs                                        []string
	BrowserOnly                                      bool
}

type task30BrowserResult struct {
	OK            bool   `json:"ok"`
	Edge          string `json:"edge"`
	RemoteAddress string `json:"remote_address"`
	Certificate   string `json:"certificate"`
	Body          string `json:"body"`
}

func TestTask30DockerEdgeRecovery(t *testing.T) {
	directory := os.Getenv("PAPERBOAT_TASK30_DOCKER_DIRECTORY")
	if directory == "" {
		t.Skip("requires approved isolated remote Docker run")
	}
	var live *task30LiveFixture
	if path := os.Getenv("PAPERBOAT_TASK30_LIVE_FIXTURE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &live); err != nil {
			t.Fatal(err)
		}
		if len(live.PublicIPs) != 2 {
			t.Fatal("two public test addresses required")
		}
	}
	httpHost, tcpHost, httpPort := "app.customer.test", "tcp.customer.test", "443"
	if live != nil {
		httpHost, tcpHost, httpPort = live.HTTPHostname, live.TCPHostname, "28443"
	}
	daemonBinary := filepath.Join(directory, "daemon.test")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 850*time.Second)
	defer cancel()
	name := "paperboat-task30-" + fmt.Sprint(os.Getpid())
	var containers []string
	docker := func(args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", args...)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Docker %s failed: %v %s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, container := range containers {
			if out, err := exec.CommandContext(cleanup, "docker", "rm", "-f", container).CombinedOutput(); err != nil {
				t.Errorf("cleanup %s: %v %s", container, err, out)
			}
		}
		if out, err := exec.CommandContext(cleanup, "docker", "network", "rm", name).CombinedOutput(); err != nil {
			t.Errorf("network cleanup: %v %s", err, out)
		}
	}()
	networkArgs := []string{"network", "create", "--label", "paperboat.task=30"}
	if live == nil {
		networkArgs = append(networkArgs, "--internal")
	}
	networkArgs = append(networkArgs, name)
	docker(networkArgs...)
	certificates := task24Certificates
	if live != nil && live.BrowserOnly {
		// Chromium does not support Ed25519 X.509 signatures. Keep the Go-only
		// fixture unchanged and use ordinary browser-supported ECDSA certificates.
		certificates = func(t *testing.T, names ...string) (*tls.Config, *tls.Config, []byte, []byte, []byte) {
			return task24CertificatesWithKey(t, func() crypto.Signer {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}, names...)
		}
	}
	_, serverTLS, ca, clientCert, clientKey := certificates(t, httpHost)
	certificate := serverTLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	run := func(container, binary, test, env string, aliases ...string) {
		t.Helper()
		containers = append(containers, container)
		args := []string{"run", "-d", "--name", container, "--network", name, "--label", "paperboat.task=30", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=192m", "--pids-limit=64", "--mount", "type=bind,src=" + directory + ",dst=" + directory, "--env", env, "--env", "GODEBUG=netdns=go"}
		for _, alias := range aliases {
			args = append(args, "--network-alias", alias)
		}
		if live != nil && test == "TestTask30EdgeProcess" {
			index := 0
			if aliases[0] == "edge1" {
				index = 1
			}
			address := live.PublicIPs[index]
			args = append(args, "-p", net.JoinHostPort(address, "28443")+":443", "-p", net.JoinHostPort(address, "25001")+":25001")
		}
		if live != nil && test == "TestTask30DockerClient" {
			for i := range args {
				if i > 0 && args[i-1] == "--network" {
					args[i] = "host"
				}
			}
			dnsHost, _, _ := net.SplitHostPort(live.DNSAddress)
			args = append(args, "--dns", dnsHost)
		}
		args = append(args, "--entrypoint", binary, "postgres:17-alpine", "-test.run=^"+test+"$", "-test.count=1", "-test.v")
		docker(args...)
	}
	nodes := make([]task30CarrierNode, 2)
	fixtures := make([]task30EdgeFixture, 2)
	ips := make([]string, 2)
	for i := range 2 {
		prefix := filepath.Join(directory, fmt.Sprintf("edge%d", i))
		node := task30CarrierNode{Address: fmt.Sprintf("edge%d:27443", i), NodeID: fmt.Sprintf("edge_0%d", i+1), Epoch: fmt.Sprintf("epoch_000%d", i+1), Domain: fmt.Sprintf("simulated_container_%d", i)}
		f := task30EdgeFixture{DockerSimulation: true, LifetimeSeconds: 840, Node: node, IP: "0.0.0.0", HTTPPort: "443", TCPPort: "25001", CA: string(ca), Cert: string(certPEM), Key: string(keyPEM), CarrierPath: prefix + "-carrier", AuthorityPath: prefix + "-authority", ReadyPath: prefix + "-ready"}
		task30Write(t, prefix+"-fixture", f)
		container := fmt.Sprintf("%s-edge%d", name, i)
		run(container, self, "TestTask30EdgeProcess", "PAPERBOAT_TASK30_EDGE="+prefix+"-fixture", fmt.Sprintf("edge%d", i), "app.customer.test", "tcp.customer.test")
		task30Read(t, ctx, f.CarrierPath, &nodes[i])
		fixtures[i] = f
		ips[i] = docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container)
	}
	descriptor := task24Descriptor{Protocol: "http2", CACert: string(ca), ClientCert: string(clientCert), ClientKey: string(clientKey), OriginsPath: filepath.Join(directory, "origins"), AuthorityPath: filepath.Join(directory, "daemon-authority"), ReadyPath: filepath.Join(directory, "daemon-ready"), StopPath: filepath.Join(directory, "stop"), Nodes: nodes}
	// The daemon's optional fixture extensions are encoded without coupling the
	// edge's existing Task24 descriptor type to simulation-only observations.
	raw, _ := json.Marshal(descriptor)
	var descriptorMap map[string]any
	_ = json.Unmarshal(raw, &descriptorMap)
	descriptorMap["DockerSimulation"] = true
	descriptorMap["HTTPHostname"] = httpHost
	if live != nil {
		descriptorMap["FixtureTimeoutSeconds"] = 840
	}
	descriptorMap["ObservationsPath"] = filepath.Join(directory, "observations")
	descriptorPath := filepath.Join(directory, "daemon-descriptor")
	task30Write(t, descriptorPath, descriptorMap)
	run(name+"-daemon", daemonBinary, "TestTask24CrossRepositoryDaemon", "PAPERBOAT_TASK24_DESCRIPTOR="+descriptorPath)
	var origins task24Origins
	task30Read(t, ctx, descriptor.OriginsPath, &origins)
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	decision := func(node task30CarrierNode, protocol, origin string) connectorprotocol.IngressDecision {
		id := "route_" + protocol
		host, path, listener, port := httpHost, "/", "", uint16(0)
		if protocol == "tcp" {
			host, path, listener, port = tcpHost, "", "listener_task30", 25001
		}
		now := time.Now().UTC()
		return connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_task24", AccountID: identity.AccountID, TunnelID: identity.TunnelID, Lifecycle: connectorprotocol.TunnelDurable, ResourceGeneration: 1, RouteID: id, RouteGeneration: 1, TargetID: "target_" + id, TargetGeneration: 1, HostID: identity.HostID, InstallationGeneration: 1, Audience: "public", ConnectionMethod: "edge", Protocol: protocol, Hostname: host, PathPrefix: path, OriginScheme: protocol, OriginAddress: origin, TLSVerification: "not_applicable", PublicationID: "publication_" + id, PublicationGeneration: 1, ListenerID: listener, PublicPort: port}, DecisionID: "decision_" + id, PolicyGeneration: 1, EdgeNodeID: node.NodeID, EdgeProcessEpoch: node.Epoch, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, AssignmentGeneration: 1, Action: "view", IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
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
		if _, err = os.Stat(descriptor.ReadyPath); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	client := func(phase string, expected, direct []string) task30ClientResult {
		t.Helper()
		path := filepath.Join(directory, phase+"-client")
		f := task30ClientFixture{CA: string(ca), Prefix: phase, ExpectedIPs: expected, DirectIPs: direct, ResultPath: path + "-result", HTTPHostname: httpHost, TCPHostname: tcpHost, HTTPPort: httpPort}
		if live != nil {
			f.DNSAddress = live.DNSAddress
			f.DNSOnly = phase == "unavailable"
		}
		task30Write(t, path, f)
		container := name + "-" + phase
		run(container, self, "TestTask30DockerClient", "PAPERBOAT_TASK30_CLIENT="+path)
		if exit := docker("wait", container); exit != "0" {
			t.Fatalf("client %s exited %s: %s", phase, exit, docker("logs", container))
		}
		var result task30ClientResult
		task30Read(t, ctx, f.ResultPath, &result)
		return result
	}
	publish := func(addresses []string) {
		t.Helper()
		if live == nil {
			return
		}
		requestPath := filepath.Join(directory, "publication-request")
		task30Write(t, requestPath, map[string]any{"Addresses": addresses, "Hosts": []string{httpHost, tcpHost}})
		command := exec.CommandContext(ctx, "python3", live.Publisher, requestPath)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("live publication failed: %v %s", err, out)
		}
		t.Logf("live publication: %s", out)
	}
	preflightIDs := []string{}
	if live != nil {
		timer := time.NewTimer(11 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		ips = append([]string(nil), live.PublicIPs...)
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca)
		for _, ip := range ips {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort(ip, httpPort), &tls.Config{RootCAs: roots, ServerName: httpHost})
			if err != nil {
				t.Fatalf("public TLS endpoint not ready before DNS publication: %v", err)
			}
			conn.Close()
			tcp, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "25001"), 3*time.Second)
			if err != nil {
				t.Fatalf("public TCP endpoint not ready before DNS publication: %v", err)
			}
			id := "prepublication-tcp-" + ip
			_ = tcp.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(tcp, "tcp-upload:"+id)
			tcp.(*net.TCPConn).CloseWrite()
			body, err := io.ReadAll(tcp)
			tcp.Close()
			if err != nil || string(body) != "tcp-delayed-reply" {
				t.Fatalf("TCP origin not ready after fixture authority renewal: %v", err)
			}
			preflightIDs = append(preflightIDs, id)
		}
		t.Log("both published IPv6 TLS/TCP endpoints independently reachable after authority renewal and before DNS publication")
		publish(ips)
	}
	if live != nil && live.BrowserOnly {
		const browserContainer = "paperboat-task30-browser"
		caPath := filepath.Join(directory, "task30-browser-ca.pem")
		policyPath := filepath.Join(directory, "task30-browser-policy.json")
		if err := os.WriteFile(caPath, ca, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policyPath, []byte(`{"DnsOverHttpsMode":"off"}`), 0600); err != nil {
			t.Fatal(err)
		}
		docker("exec", browserContainer, "mkdir", "-p", "/root/.pki/nssdb", "/etc/chromium/policies/managed")
		if out, err := exec.CommandContext(ctx, "docker", "exec", browserContainer, "certutil", "-N", "--empty-password", "-d", "sql:/root/.pki/nssdb").CombinedOutput(); err != nil {
			t.Fatalf("initialize browser trust store: %v %s", err, out)
		}
		docker("cp", caPath, browserContainer+":/tmp/task30-ca.pem")
		docker("cp", policyPath, browserContainer+":/etc/chromium/policies/managed/task30.json")
		docker("exec", browserContainer, "certutil", "-A", "-d", "sql:/root/.pki/nssdb", "-n", "paperboat-task30-ca", "-t", "C,,", "-i", "/tmp/task30-ca.pem")
		chromium := docker("exec", browserContainer, "sh", "-c", "command -v chromium-browser || command -v chromium")
		docker("exec", "-d", browserContainer, chromium, "--headless", "--no-sandbox", "--disable-background-networking", "--disable-default-apps", "--disable-sync", "--no-first-run", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=29222", "--user-data-dir=/tmp/task30-chromium", "about:blank")
		browserStartupDeadline := time.Now().Add(20 * time.Second)
		for {
			probe := exec.CommandContext(ctx, "docker", "exec", browserContainer, "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:29222/json/version")
			if probe.Run() == nil {
				break
			}
			if time.Now().After(browserStartupDeadline) {
				t.Fatal("headless Chromium debugging endpoint did not start")
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		browserURL := "https://" + net.JoinHostPort(httpHost, httpPort) + "/browser"
		attemptedIDs, successfulIDs := []string{}, []string{}
		navigate := func(id string) (task30BrowserResult, bool) {
			attemptedIDs = append(attemptedIDs, id)
			commandCtx, commandCancel := context.WithTimeout(ctx, 25*time.Second)
			defer commandCancel()
			out, commandErr := exec.CommandContext(commandCtx, "docker", "exec", browserContainer, "python3", "/task30_browser.py", browserURL, id).CombinedOutput()
			var result task30BrowserResult
			if commandErr != nil || json.Unmarshal(bytes.TrimSpace(out), &result) != nil || !result.OK {
				t.Logf("browser navigation %s failed: %v %s", id, commandErr, out)
				return result, false
			}
			successfulIDs = append(successfulIDs, id)
			return result, true
		}
		beforeBrowser, ok := navigate("browser-before")
		if !ok || beforeBrowser.Certificate == "" || beforeBrowser.Edge != nodes[0].NodeID && beforeBrowser.Edge != nodes[1].NodeID {
			t.Fatal("initial headless Chromium navigation failed")
		}
		cacheEvidence := client("browser-cache", ips, nil)
		expectedCacheAddresses := append([]string(nil), ips...)
		sort.Strings(expectedCacheAddresses)
		if cacheEvidence.TTL == 0 || cacheEvidence.TTL > 60 || strings.Join(cacheEvidence.Addresses, ",") != strings.Join(expectedCacheAddresses, ",") {
			t.Fatal("browser failover cache precondition was not established")
		}
		failed := 0
		if beforeBrowser.Edge == nodes[1].NodeID {
			failed = 1
		}
		survivor := 1 - failed
		if strings.Trim(beforeBrowser.RemoteAddress, "[]") != strings.Trim(ips[failed], "[]") {
			t.Fatal("headless Chromium edge header and remote address disagree")
		}
		docker("kill", fmt.Sprintf("%s-edge%d", name, failed))
		failedAt := time.Now()
		var afterBrowser task30BrowserResult
		ok = false
		for attempt := 0; time.Since(failedAt) <= 180*time.Second; attempt++ {
			candidate, success := navigate(fmt.Sprintf("browser-after-%d", attempt))
			if success && candidate.Edge == nodes[survivor].NodeID {
				afterBrowser, ok = candidate, true
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Second):
			}
		}
		recoveryElapsed := time.Since(failedAt)
		if !ok || recoveryElapsed > 180*time.Second || strings.Trim(afterBrowser.RemoteAddress, "[]") != strings.Trim(ips[survivor], "[]") || beforeBrowser.Certificate != afterBrowser.Certificate {
			t.Fatal("headless Chromium did not recover to the surviving edge with the same certificate")
		}
		publish([]string{ips[survivor]})
		_ = os.Remove(fixtures[failed].ReadyPath)
		docker("start", fmt.Sprintf("%s-edge%d", name, failed))
		var ready bool
		task30Read(t, ctx, fixtures[failed].ReadyPath, &ready)
		publish(ips)
		restoredBrowser, ok := navigate("browser-restored")
		if !ok || restoredBrowser.Certificate != beforeBrowser.Certificate {
			t.Fatal("headless Chromium restore navigation failed")
		}
		observations, err := os.ReadFile(filepath.Join(directory, "observations"))
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, line := range bytes.Split(bytes.TrimSpace(observations), []byte("\n")) {
			var id string
			if json.Unmarshal(line, &id) != nil {
				t.Fatal("invalid origin observation")
			}
			counts[id]++
		}
		expectedIDs := append(append(append([]string{}, preflightIDs...), cacheEvidence.IDs...), successfulIDs...)
		for _, id := range expectedIDs {
			if counts[id] != 1 {
				t.Fatalf("browser origin delivery %s count=%d", id, counts[id])
			}
		}
		for _, id := range attemptedIDs {
			if counts[id] > 1 {
				t.Fatalf("browser origin replay %s count=%d", id, counts[id])
			}
			delete(counts, id)
		}
		for _, id := range append(preflightIDs, cacheEvidence.IDs...) {
			delete(counts, id)
		}
		if len(counts) != 0 {
			t.Fatal("unexpected browser origin delivery")
		}
		publish([]string{})
		if err := os.WriteFile(descriptor.StopPath, []byte("stop"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("headless Chromium hostname recovery reached %s in %s with unchanged certificate", nodes[survivor].NodeID, recoveryElapsed)
		return
	}
	before := client("before", ips, ips)
	failed := 0
	if before.Edge == nodes[1].NodeID {
		failed = 1
	}
	survivor := 1 - failed
	var interrupted task30ClientResult
	heldContainer := ""
	{
		path := filepath.Join(directory, "interrupted-client")
		f := task30ClientFixture{CA: string(ca), Prefix: "held", ExpectedIPs: ips, ResultPath: path + "-result", HTTPHostname: httpHost, TCPHostname: tcpHost, HTTPPort: httpPort, Hold: true, HeldPath: path + "-held"}
		if live != nil {
			f.DNSAddress = live.DNSAddress
		}
		task30Write(t, path, f)
		heldContainer = name + "-interrupted"
		run(heldContainer, self, "TestTask30DockerClient", "PAPERBOAT_TASK30_CLIENT="+path)
		task30Read(t, ctx, f.HeldPath, &interrupted)
		failed = 0
		if interrupted.TCPAddress == ips[1] {
			failed = 1
		}
		survivor = 1 - failed
		// Wait for the origin to observe this POST before killing its actual edge.
		deadline := time.Now().Add(3 * time.Second)
		for {
			data, _ := os.ReadFile(filepath.Join(directory, "observations"))
			if bytes.Contains(data, []byte(interrupted.IDs[0])) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("held POST did not reach origin")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	failedAt := time.Now()
	docker("kill", fmt.Sprintf("%s-edge%d", name, failed))
	if heldContainer != "" {
		if exit := docker("wait", heldContainer); exit != "0" {
			t.Fatalf("interrupted client failed: %s", docker("logs", heldContainer))
		}
	}
	var after task30ClientResult
	var cached task30ClientResult
	if live != nil {
		// The cache still has both actual provider answers. The client must recover
		// without being told which address survived or replacing its URL.
		cached = client("cached-after-loss", ips, nil)
		if cached.Edge != nodes[survivor].NodeID || cached.TCPAddress != ips[survivor] {
			t.Fatal("cached client failed to reach survivor")
		}
		t.Logf("cached answer recovery in %s; remaining DNS TTL=%ds", time.Since(failedAt), cached.TTL)
		publish([]string{ips[survivor]})
		wait := time.Duration(before.TTL)*time.Second - time.Since(failedAt) + time.Second
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
		}
	}
	after = client("after", []string{ips[survivor]}, nil)
	elapsed := time.Since(failedAt)
	if after.Edge != nodes[survivor].NodeID || after.TCPAddress != ips[survivor] || before.Certificate != after.Certificate {
		t.Fatal("stable endpoint/certificate did not reach surviving edge")
	}
	limit := 20 * time.Second
	if live != nil {
		limit = 180 * time.Second
	}
	if elapsed > limit {
		t.Fatalf("simulated edge recovery exceeded target: %v", elapsed)
	}
	var restored task30ClientResult
	if live != nil {
		// Restoring the same task-owned container preserves its exact fixture epoch;
		// restart readiness is acknowledged again before any republication.
		_ = os.Remove(fixtures[failed].ReadyPath)
		docker("start", fmt.Sprintf("%s-edge%d", name, failed))
		var ready bool
		task30Read(t, ctx, fixtures[failed].ReadyPath, &ready)
		publish(ips)
		// Wait out the survivor-only cache, then verify both endpoints and normal use.
		timer := time.NewTimer(time.Duration(after.TTL+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		restored = client("restored", ips, ips)
	}
	if live != nil {
		for i := range 2 {
			docker("kill", fmt.Sprintf("%s-edge%d", name, i))
		}
		publish([]string{})
		timer := time.NewTimer(time.Duration(restored.TTL+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		client("unavailable", nil, nil)
		t.Log("both edges unavailable: owned DNS withdrawn and hostname requests fail closed")
	}
	observations, err := os.ReadFile(filepath.Join(directory, "observations"))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(observations), []byte("\n")) {
		var id string
		if err = json.Unmarshal(line, &id); err != nil {
			t.Fatal(err)
		}
		counts[id]++
	}
	allIDs := append(append(append(append(before.IDs, cached.IDs...), after.IDs...), restored.IDs...), interrupted.IDs...)
	allIDs = append(allIDs, preflightIDs...)
	for _, id := range allIDs {
		if counts[id] != 1 {
			t.Fatalf("origin delivery %s count=%d", id, counts[id])
		}
		delete(counts, id)
	}
	if len(counts) != 0 {
		t.Fatal("unexpected origin delivery")
	}
	t.Logf("simulated Docker edge loss: unchanged HTTPS hostname/certificate and TCP hostname:25001 recovered in %s; DNS before=%v after=%v TTL=%ds; unique origin deliveries exactly once", elapsed, before.Addresses, after.Addresses, before.TTL)
	if live != nil {
		publish([]string{})
	}
	if err = os.WriteFile(descriptor.StopPath, []byte("stop"), 0600); err != nil {
		t.Fatal(err)
	}
}
