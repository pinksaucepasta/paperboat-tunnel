package datacarrier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	quic "github.com/quic-go/quic-go"
)

func TestEndpointRejectsWeakClientAuthentication(t *testing.T) {
	_, serverTLS, _ := testEndpointCertificates(t)
	peer := func(tls.ConnectionState) (Identity, error) { return testCarrierIdentity(), nil }
	for _, auth := range []tls.ClientAuthType{tls.NoClientCert, tls.VerifyClientCertIfGiven, tls.RequireAnyClientCert} {
		t.Run(auth.String(), func(t *testing.T) {
			config := EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS.Clone(), PeerBinding: peer}
			config.TLS.ClientAuth = auth
			listener, err := ListenTCPMux(context.Background(), config, testCarrierConfig(2))
			if listener != nil {
				_ = listener.Close()
			}
			if !errors.Is(err, ErrCarrierTLS) {
				t.Fatalf("auth %v error = %v, want TLS authentication error", auth, err)
			}
		})
	}
}

func TestEndpointClientAuthVerifierRules(t *testing.T) {
	_, serverTLS, _ := testEndpointCertificates(t)
	for _, tc := range []struct {
		auth tls.ClientAuthType
		want bool
	}{
		{auth: tls.VerifyClientCertIfGiven, want: true},
		{auth: tls.RequireAnyClientCert, want: false},
	} {
		config := serverTLS.Clone()
		config.ClientAuth = tc.auth
		config.VerifyConnection = func(tls.ConnectionState) error { return nil }
		err := validateEndpointTLS(config, true)
		if (err != nil) != tc.want {
			t.Fatalf("client auth %v error = %v, rejected = %v, want rejected %v", tc.auth, err, err != nil, tc.want)
		}
	}
}

func TestTCPMuxListenerUsesBoundedConcurrentHandshakes(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := testCarrierConfig(4)
	config.ConnectionWriteLimit = 40 * time.Millisecond
	identity := testCarrierIdentity()
	listener, err := ListenTCPMux(ctx, EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (Identity, error) { return identity, nil }}, config)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()
	unauthenticated, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("open unauthenticated socket: %v", err)
	}
	defer unauthenticated.Close()

	acceptContext, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()
	accepted := make(chan *Server, 1)
	acceptErr := make(chan error, 1)
	go func() {
		server, err := listener.Accept(acceptContext)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- server
	}()
	tlsConnection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial authenticated socket: %v", err)
	}
	defer tlsConnection.Close()
	select {
	case server := <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatalf("accept authenticated socket: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for authenticated socket")
	}
}

func TestTCPMuxListenerRejectsPeerIdentityMismatch(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := testCarrierConfig(2)
	identity := testCarrierIdentity()
	wrongIdentity := identity
	wrongIdentity.HostID = "host-other"
	listener, err := ListenTCPMux(ctx, EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (Identity, error) { return wrongIdentity, nil }}, config)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()
	connection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial TCP: %v", err)
	}
	_ = connection.Close()
	acceptContext, acceptCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer acceptCancel()
	if _, err := listener.Accept(acceptContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mismatched peer accept error = %v, want deadline", err)
	}
}

func TestTCPMuxListenerAcceptsMultiplePeerIdentities(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := testCarrierConfig(4)
	config.Identity = Identity{}
	first := testCarrierIdentity()
	second := first
	second.HostID = "host-b"
	second.TunnelID = "tunnel-b"
	second.ConnectorID = "connector-b"
	second.SessionID = "session-b"
	second.ProcessGeneration = 8
	second.Generation = 12
	identities := []Identity{first, second}
	var peerCalls atomic.Int32
	listener, err := ListenTCPMux(ctx, EndpointConfig{
		Address: "127.0.0.1:0",
		TLS:     serverTLS,
		PeerBinding: func(state tls.ConnectionState) (Identity, error) {
			if len(state.PeerCertificates) == 0 {
				return Identity{}, errors.New("peer certificate was not verified")
			}
			index := int(peerCalls.Add(1)) - 1
			if index < 0 || index >= len(identities) {
				return Identity{}, errors.New("unexpected peer")
			}
			return identities[index], nil
		},
	}, config)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()

	dial := func(identity Identity) (*Client, *tls.Conn) {
		t.Helper()
		connection, err := (&tls.Dialer{Config: clientTLS.Clone()}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial TCP: %v", err)
		}
		clientConfig := config
		clientConfig.Identity = identity
		client, err := NewClient(ctx, connection, clientConfig)
		if err != nil {
			_ = connection.Close()
			t.Fatalf("new client: %v", err)
		}
		return client, connection.(*tls.Conn)
	}
	client1, connection1 := dial(first)
	defer client1.Close()
	defer connection1.Close()
	server1, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept first identity: %v", err)
	}
	defer server1.Close()
	client2, connection2 := dial(second)
	defer client2.Close()
	defer connection2.Close()
	server2, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept second identity: %v", err)
	}
	defer server2.Close()
	if peerCalls.Load() != 2 {
		t.Fatalf("peer binding calls = %d, want 2", peerCalls.Load())
	}

	open1 := streamOpenForIdentity(first, "route-a", "multi-first")
	stream1, err := server1.OpenStream(ctx, open1)
	if err != nil {
		t.Fatalf("open first identity stream: %v", err)
	}
	connector1, metadata1, err := client1.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept first identity stream: %v", err)
	}
	if metadata1 != open1 {
		t.Fatalf("first metadata = %+v, want %+v", metadata1, open1)
	}
	_ = stream1.Close()
	_ = connector1.Close()

	if _, err := server1.OpenStream(ctx, streamOpenForIdentity(second, "route-a", "cross-identity")); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("cross-identity open error = %v, want identity mismatch", err)
	}

	open2 := streamOpenForIdentity(second, "route-a", "multi-second")
	stream2, err := server2.OpenStream(ctx, open2)
	if err != nil {
		t.Fatalf("open second identity stream: %v", err)
	}
	connector2, metadata2, err := client2.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept second identity stream: %v", err)
	}
	if metadata2 != open2 {
		t.Fatalf("second metadata = %+v, want %+v", metadata2, open2)
	}
	_ = stream2.Close()
	_ = connector2.Close()

	if err := server1.Close(); err != nil {
		t.Fatalf("close first identity: %v", err)
	}
	open2.RequestID = "multi-second-after-first-close"
	stream2, err = server2.OpenStream(ctx, open2)
	if err != nil {
		t.Fatalf("second identity after first close: %v", err)
	}
	connector2, _, err = client2.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept second identity after first close: %v", err)
	}
	_ = stream2.Close()
	_ = connector2.Close()
}

func TestTCPMuxListenerEdgeOpenConnectorAcceptAndALPN(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := testCarrierConfig(4)
	identity := testCarrierIdentity()
	listener, err := ListenTCPMux(ctx, EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(state tls.ConnectionState) (Identity, error) {
		if len(state.PeerCertificates) == 0 {
			return Identity{}, errors.New("peer certificate was not verified")
		}
		return identity, nil
	}}, config)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()
	serverResult := make(chan struct {
		server *Server
		err    error
	}, 1)
	go func() {
		server, err := listener.Accept(ctx)
		serverResult <- struct {
			server *Server
			err    error
		}{server: server, err: err}
	}()
	tlsConnection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial TCP: %v", err)
	}
	tlsState := tlsConnection.(*tls.Conn).ConnectionState()
	if tlsState.NegotiatedProtocol != DataCarrierALPN {
		t.Fatalf("TCP negotiated ALPN = %q, want %q", tlsState.NegotiatedProtocol, DataCarrierALPN)
	}
	client, err := NewClient(ctx, tlsConnection, config)
	if err != nil {
		_ = tlsConnection.Close()
		t.Fatalf("new TCP client: %v", err)
	}
	defer client.Close()
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("accept TCP carrier: %v", result.err)
	}
	server := result.server
	defer server.Close()
	open := testStreamOpen("route-a", "endpoint-tcp")
	edgeStream, err := server.OpenStream(ctx, open)
	if err != nil {
		t.Fatalf("edge open TCP stream: %v", err)
	}
	connectorStream, metadata, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("connector accept TCP stream: %v", err)
	}
	const body = "listener-tcp-body"
	_, _ = io.WriteString(edgeStream, body)
	_ = edgeStream.Close()
	got, err := io.ReadAll(connectorStream)
	if err != nil {
		t.Fatalf("read TCP stream: %v", err)
	}
	_ = connectorStream.Close()
	if metadata != open || string(got) != body {
		t.Fatalf("TCP metadata/body = %+v/%q, want %+v/%q", metadata, got, open, body)
	}
}

func TestTCPMuxListenerRejectsMissingOrWrongALPN(t *testing.T) {
	_, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity := testCarrierIdentity()
	config := testCarrierConfig(2)
	listener, err := ListenTCPMux(ctx, EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (Identity, error) { return identity, nil }}, config)
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()
	for _, tc := range []struct {
		name   string
		protos []string
	}{
		{name: "missing", protos: nil},
		{name: "wrong", protos: []string{"wrong.protocol"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection, err := (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: tc.protos}}).DialContext(ctx, "tcp", listener.Addr().String())
			if err == nil {
				state := connection.(*tls.Conn).ConnectionState()
				if state.NegotiatedProtocol == DataCarrierALPN {
					_ = connection.Close()
					t.Fatal("invalid ALPN unexpectedly negotiated carrier protocol")
				}
				_ = connection.Close()
			}
		})
	}
}

func TestQUICListenerEdgeOpenConnectorAcceptAndALPN(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := testCarrierConfig(4)
	identity := testCarrierIdentity()
	listener, err := ListenQUIC(ctx, EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(state tls.ConnectionState) (Identity, error) {
		if len(state.PeerCertificates) == 0 {
			return Identity{}, errors.New("peer certificate was not verified")
		}
		return identity, nil
	}}, config)
	if err != nil {
		t.Fatalf("listen QUIC: %v", err)
	}
	defer listener.Close()
	serverResult := make(chan struct {
		server *Server
		err    error
	}, 1)
	go func() {
		server, err := listener.Accept(ctx)
		serverResult <- struct {
			server *Server
			err    error
		}{server: server, err: err}
	}()
	connection, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS.Clone(), endpointQUICConfig(config))
	if err != nil {
		t.Fatalf("dial QUIC: %v", err)
	}
	state := connection.ConnectionState().TLS
	if state.NegotiatedProtocol != DataCarrierALPN {
		t.Fatalf("QUIC negotiated ALPN = %q, want %q", state.NegotiatedProtocol, DataCarrierALPN)
	}
	client, err := NewClientWithSession(ctx, newQUICSession(connection), config)
	if err != nil {
		_ = connection.CloseWithError(0, "test failed")
		t.Fatalf("new QUIC client: %v", err)
	}
	defer client.Close()
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("accept QUIC carrier: %v", result.err)
	}
	server := result.server
	defer server.Close()
	open := testStreamOpen("route-a", "endpoint-quic")
	edgeStream, err := server.OpenStream(ctx, open)
	if err != nil {
		t.Fatalf("edge open QUIC stream: %v", err)
	}
	connectorStream, metadata, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("connector accept QUIC stream: %v", err)
	}
	const body = "listener-quic-body"
	_, _ = io.WriteString(edgeStream, body)
	_ = edgeStream.Close()
	got, err := io.ReadAll(connectorStream)
	if err != nil {
		t.Fatalf("read QUIC stream: %v", err)
	}
	_ = connectorStream.Close()
	if metadata != open || string(got) != body {
		t.Fatalf("QUIC metadata/body = %+v/%q, want %+v/%q", metadata, got, open, body)
	}
}

func testEndpointCertificates(t *testing.T) (clientTLS, serverTLS *tls.Config, pool *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{SerialNumber: newSerial(t), Subject: pkix.Name{CommonName: "paperboat test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCertificate)
	makeCertificate := func(serial int64, commonName string, usages []x509.ExtKeyUsage) tls.Certificate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", commonName, err)
		}
		template := &x509.Certificate{SerialNumber: bigSerial(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: usages, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, public, caPrivate)
		if err != nil {
			t.Fatalf("create %s certificate: %v", commonName, err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatalf("marshal %s key: %v", commonName, err)
		}
		certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
		if err != nil {
			t.Fatalf("load %s certificate: %v", commonName, err)
		}
		certificate.Certificate = append(certificate.Certificate, caDER)
		return certificate
	}
	serverCertificate := makeCertificate(2, "carrier-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertificate := makeCertificate(3, "carrier-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	serverTLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, NextProtos: []string{DataCarrierALPN}}
	clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCertificate}, RootCAs: pool, ServerName: "localhost", NextProtos: []string{DataCarrierALPN}}
	return clientTLS, serverTLS, pool
}

func streamOpenForIdentity(identity Identity, routeID, requestID string) StreamOpen {
	return StreamOpen{
		Protocol:          connectorprotocol.ProtocolName,
		Version:           connectorprotocol.ProtocolVersion,
		AccountID:         identity.AccountID,
		TunnelID:          identity.TunnelID,
		ConnectorID:       identity.ConnectorID,
		SessionID:         identity.SessionID,
		ProcessGeneration: identity.ProcessGeneration,
		Generation:        identity.Generation,
		RouteID:           routeID,
		RequestID:         requestID,
		Kind:              "http",
	}
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	return bigSerial(time.Now().UnixNano())
}

func bigSerial(value int64) *big.Int {
	return new(big.Int).SetInt64(value)
}
