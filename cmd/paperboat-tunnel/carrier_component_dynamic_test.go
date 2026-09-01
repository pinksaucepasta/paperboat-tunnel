package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

// TestCarrierPromotesAnAlreadyLivePreviewSessionToDurableRouting verifies the
// ordering that occurs in production when a connector has already established
// a preview/accessor carrier before the route worker publishes its durable
// assignment. The carrier must be promoted in place: reconnecting would lose
// the authenticated session and leaves the server's staged assignment stuck.
func TestCarrierPromotesAnAlreadyLivePreviewSessionToDurableRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity := datacarrier.Identity{
		AccountID: "account_dynamic", HostID: "host_dynamic", TunnelID: "tunnel_dynamic",
		ConnectorID: "connector_dynamic", SessionID: "session_dynamic",
		ProcessGeneration: 12, Generation: 4,
	}
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machinePublicEncoded := base64.RawURLEncoding.EncodeToString(machinePublic)
	machineThumbprint, err := connectorprotocol.IdentityThumbprint(machinePublic)
	if err != nil {
		t.Fatal(err)
	}
	const (
		edgeNodeID     = "edge_dynamic"
		edgeProcess    = "_edge_dynamic_1"
		routeID        = "route_dynamic"
		assignmentID   = "assignment_dynamic"
		configHash     = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		previewRouteID = "preview_dynamic"
	)
	now := time.Now().UTC()
	durableAdmission := datacarrier.DurableAdmission{
		Identity: identity, EdgeNodeID: edgeNodeID, EdgeProcessEpoch: edgeProcess,
		AssignmentID: assignmentID, RouteID: routeID, AssignmentGeneration: 7,
		RouteGeneration: 4, ConfigContentHash: configHash,
		MachineIdentityPublicKey: machinePublicEncoded, MachineIdentityThumbprint: machineThumbprint,
		State: "staged", ExpiresAt: now.Add(5 * time.Minute),
	}

	durableExpected, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: edgeNodeID, ProcessEpoch: edgeProcess})
	if err != nil {
		t.Fatal(err)
	}
	defer durableExpected.Close()
	accessorExpected, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: edgeNodeID, ProcessEpoch: edgeProcess})
	if err != nil {
		t.Fatal(err)
	}
	defer accessorExpected.Close()
	if err := accessorExpected.Replace([]datacarrier.DurableAdmission{durableAdmission}, now); err != nil {
		t.Fatalf("publish initial accessor admission: %v", err)
	}
	previewExpected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: edgeNodeID, ProcessEpoch: edgeProcess})
	if err != nil {
		t.Fatal(err)
	}
	defer previewExpected.Close()
	previewKeyDigest := sha256.Sum256(machinePublic)
	previewThumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(previewKeyDigest[:])
	previewAdmission := dynamicPreviewAdmission(identity, machinePublicEncoded, previewThumbprint, edgeNodeID, edgeProcess, previewRouteID, now.Add(5*time.Minute))
	if err := previewExpected.Replace([]datacarrier.ExpectedAdmission{previewAdmission}, now); err != nil {
		t.Fatalf("publish initial preview admission: %v", err)
	}

	routes, err := edgehttp.NewDataCarrierRouteRegistry(edgehttp.DataCarrierRouteRegistryConfig{MaximumRoutes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()

	previewStarted := make(chan struct{})
	previewHandle := func(handlerContext context.Context, server *datacarrier.Server) error {
		close(previewStarted)
		select {
		case <-server.Done():
			return nil
		case <-handlerContext.Done():
			return handlerContext.Err()
		}
	}
	serverCertificate := dynamicCarrierCertificate(t, "edge-carrier", nil, nil)
	tcpAddress, quicAddress := dynamicCarrierListenAddresses(t)
	assembly, closeService, err := newCarrierComponentWithTelemetry(
		config.Deployment{
			CarrierTCPListenAddress: tcpAddress, CarrierQUICListenAddress: quicAddress,
			ControlInterval: 5 * time.Millisecond, NodeCapacity: 8,
		}, serverCertificate, previewExpected, durableExpected, accessorExpected,
		previewHandle, routes, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeService()
	if err := assembly.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		if err := assembly.Shutdown(shutdownContext); err != nil {
			t.Errorf("shutdown carrier assembly: %v", err)
		}
	}()

	carrierCertificate, err := dynamicCarrierCertificateWithURI(t, "connector-carrier", machinePublic, machinePrivate, identity, edgeProcess)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := datacarrier.DefaultConfig()
	clientConfig.Identity = identity
	clientConfig.Authorize = datacarrier.AuthorizerFunc(func(context.Context, datacarrier.Identity, datacarrier.StreamOpen) error { return nil })
	connection, err := (&tls.Dialer{Config: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{carrierCertificate},
		InsecureSkipVerify: true, // The test server certificate is intentionally self-signed.
		NextProtos:         []string{datacarrier.DataCarrierALPN},
	}}).DialContext(ctx, "tcp", tcpAddress)
	if err != nil {
		t.Fatalf("dial carrier: %v", err)
	}
	client, err := datacarrier.NewClient(ctx, connection, clientConfig)
	if err != nil {
		_ = connection.Close()
		t.Fatalf("create carrier client: %v", err)
	}
	defer client.Close()

	// The preview handler is the barrier proving that the authenticated carrier
	// is already live while durableExpected is still empty. No timing sleep is
	// needed before publishing the durable assignment.
	select {
	case <-previewStarted:
	case <-ctx.Done():
		t.Fatal("carrier was not accepted through the initial preview/accessor admission")
	}
	if got := routes.Len(); got != 0 {
		t.Fatalf("durable route registry attached before durable publication: %d", got)
	}

	if err := durableExpected.Replace([]datacarrier.DurableAdmission{durableAdmission}, time.Now().UTC()); err != nil {
		t.Fatalf("publish durable admission: %v", err)
	}
	waitDynamicCondition(t, ctx, func() bool { return routes.Len() == 1 })

	rule := route.RouteRule{
		ID: routeID, Revision: 4, RouteID: routeID, RouteGeneration: durableAdmission.RouteGeneration,
		AssignmentID: assignmentID, AssignmentGeneration: durableAdmission.AssignmentGeneration,
		AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID,
		ConnectorID: identity.ConnectorID, ConnectorSessionID: identity.SessionID,
		ConnectorProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation,
		ConfigContentHash: configHash, Node: edgeNodeID, EdgeProcessEpoch: edgeProcess,
		Kind: route.TunnelHTTPSWSS, MatchType: route.MatchExact, Hostname: "dynamic.example.test",
		Target: routeID, Protocol: "https", AccessMode: "public",
	}
	probeDone := make(chan error, 1)
	go func() {
		stream, open, acceptErr := client.AcceptStream(ctx)
		if acceptErr != nil {
			probeDone <- acceptErr
			return
		}
		if open.RouteID != routeID || !strings.HasPrefix(open.RequestID, "edge-probe-") {
			_ = stream.Close()
			probeDone <- fmt.Errorf("probe stream metadata = %+v", open)
			return
		}
		request, readErr := http.ReadRequest(bufio.NewReader(stream))
		if readErr == nil {
			readErr = request.Body.Close()
		}
		if readErr == nil {
			_, readErr = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}
		_ = stream.Close()
		probeDone <- readErr
	}()
	probeContext, probeCancel := context.WithTimeout(ctx, 2*time.Second)
	defer probeCancel()
	if err := routes.ProbeRoutes(probeContext, []route.RouteRule{rule}); err != nil {
		t.Fatalf("probe after in-place durable promotion: %v", err)
	}
	select {
	case err := <-probeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("connector did not receive the promoted durable probe")
	}
}

func dynamicPreviewAdmission(identity datacarrier.Identity, machinePublicKey, machineThumbprint, edgeNodeID, edgeProcess, routeID string, expiresAt time.Time) datacarrier.ExpectedAdmission {
	return datacarrier.ExpectedAdmission{
		Schema: datacarrier.PreviewCarrierSchema, Kind: datacarrier.PreviewCarrierKind,
		EdgeNodeID: edgeNodeID, PreviewID: "preview_dynamic", OperationID: "operation_dynamic",
		OwnerDeviceID: identity.HostID, OwnerSessionID: "owner_dynamic", Identity: identity,
		LeaseGeneration: 1, ConfigGeneration: identity.Generation,
		ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RouteID:           routeID, EdgeProcessEpoch: edgeProcess,
		EdgeCarrierServerSPKISHA256:          "sha256:" + strings.Repeat("0", 64),
		EdgeCarrierServerCertificateChainPEM: "test-certificate-chain", AccessMode: datacarrier.PreviewCarrierAccessPublic,
		RouteKind: datacarrier.PreviewCarrierRoute, Hostname: "preview.dynamic.example.test",
		RouteRevision: 1, AttachmentGeneration: 1, Endpoint: "https://preview.dynamic.example.test",
		ExpiresAt: expiresAt, MachineIdentityPublicKey: machinePublicKey,
		MachineIdentityThumbprint: machineThumbprint, Admitted: true,
	}
}

func dynamicCarrierCertificate(t *testing.T, commonName string, public ed25519.PublicKey, private ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	if public == nil || private == nil {
		var err error
		public, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	return dynamicCarrierCertificateWithTemplate(t, commonName, public, private, nil)
}

func dynamicCarrierCertificateWithURI(t *testing.T, commonName string, public ed25519.PublicKey, private ed25519.PrivateKey, identity datacarrier.Identity, edgeProcess string) (tls.Certificate, error) {
	uri, err := connectorprotocol.CarrierIdentityURN(connectorprotocol.CarrierIdentityBinding{
		AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID,
		ConnectorID: identity.ConnectorID, SessionID: identity.SessionID,
		ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation,
		EdgeProcessEpoch: edgeProcess,
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	return dynamicCarrierCertificateWithTemplate(t, commonName, public, private, uri), nil
}

func dynamicCarrierCertificateWithTemplate(t *testing.T, commonName string, public ed25519.PublicKey, private ed25519.PrivateKey, uri *url.URL) tls.Certificate {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if uri != nil {
		template.URIs = []*url.URL{uri}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

func dynamicCarrierListenAddresses(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddress := tcp.Addr().String()
	_ = tcp.Close()
	quic, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quicAddress := quic.LocalAddr().String()
	_ = quic.Close()
	return tcpAddress, quicAddress
}

func waitDynamicCondition(t *testing.T, ctx context.Context, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("condition did not become true: %v", ctx.Err())
		}
	}
}
