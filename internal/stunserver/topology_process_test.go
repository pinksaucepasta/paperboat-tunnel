package stunserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalinghttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalingprotocol"
	"github.com/pion/stun/v3"
)

const (
	topologyControllingCredential = "controlling.payload.signature"
	topologyControlledCredential  = "controlled.payload.signature"
)

func TestTopologyProcess(t *testing.T) {
	switch os.Getenv("PAPERBOAT_TOPOLOGY_ROLE") {
	case "":
		t.Skip("topology process mode is not configured")
	case "server":
		runTopologyServer(t)
	case "edge":
		runTopologyEdge(t)
	case "client":
		runTopologyClient(t)
	default:
		t.Fatal("invalid topology process role")
	}
}

func runTopologyEdge(t *testing.T) {
	stunService, err := New(Config{Address: "0.0.0.0:3478"})
	if err != nil {
		t.Fatal(err)
	}
	if err := stunService.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := stunService.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	signalingService, err := peersignaling.New(peersignaling.Config{
		Authenticator: topologySignalingAuthenticator{}, Validators: peersignalingprotocol.Factory{},
		MaximumSessions: 4, MaximumConsumed: 8, QueueDepth: 64, MaximumMessage: peersignalingprotocol.MaximumMessage,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer signalingService.Close()
	certificate := topologySignalingCertificate(t)
	listener, err := net.Listen("tcp4", "0.0.0.0:8443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: peersignalinghttp.Handler{Path: "/v1/peer-signaling", Service: signalingService, ObserveError: func(err error) {
			fmt.Printf("PAPERBOAT_TOPOLOGY_SIGNALING_ERROR %v\n", err)
		}},
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}},
		ReadHeaderTimeout: 2 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	fmt.Println("PAPERBOAT_TOPOLOGY_EDGE_READY")
	t.Fatal(<-serverErrors)
}

type topologySignalingAuthenticator struct{}

func (topologySignalingAuthenticator) Authenticate(_ context.Context, credential string) (peersignaling.Admission, error) {
	role := peersignaling.RoleControlling
	credentialID, endpointID, peerEndpointID := "topology-controlling", "cli-topology", "machine-topology"
	if credential == topologyControlledCredential {
		role = peersignaling.RoleControlled
		credentialID, endpointID, peerEndpointID = "topology-controlled", "machine-topology", "cli-topology"
	} else if credential != topologyControllingCredential {
		return peersignaling.Admission{}, peersignaling.ErrInvalid
	}
	return peersignaling.Admission{
		CredentialID: credentialID, EnvironmentID: "environment-topology", NodeID: "edge-topology",
		IntentID: "intent-topology", EndpointID: endpointID, PeerEndpointID: peerEndpointID,
		AttemptGeneration: 1, NetworkGeneration: 1, Role: role, ExpiresAt: time.Now().Add(2 * time.Minute),
		Revoked: make(chan struct{}), Release: func() {},
	}, nil
}

func topologySignalingCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	seed := [ed25519.SeedSize]byte{1, 9, 8, 4, 2, 7, 6, 5, 3, 8, 1, 4, 9, 2, 6, 7, 5, 3, 8, 1, 4, 9, 2, 6, 7, 5, 3, 8, 1, 4, 9, 2}
	private := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signaling.paperboat.test"},
		NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0),
		DNSNames: []string{"signaling.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}
}

func runTopologyServer(t *testing.T) {
	server, err := New(Config{Address: "0.0.0.0:3478"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	fmt.Println("PAPERBOAT_TOPOLOGY_STUN_READY")
	select {}
}

func runTopologyClient(t *testing.T) {
	target, err := net.ResolveUDPAddr("udp4", os.Getenv("PAPERBOAT_TOPOLOGY_STUN_TARGET"))
	if err != nil || target.Port == 0 {
		t.Fatalf("resolve STUN target: %v", err)
	}
	connection, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := topologyBindingExchange(connection); err == nil {
			fmt.Println("PAPERBOAT_TOPOLOGY_STUN_OK")
			return
		} else if !time.Now().Before(deadline) {
			t.Fatal(err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		<-timer.C
	}
}

func topologyBindingExchange(connection *net.UDPConn) error {
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		return err
	}
	if _, err := connection.Write(request.Raw); err != nil {
		return err
	}
	if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		return err
	}
	buffer := make([]byte, 1200)
	read, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	response := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
	if err := response.Decode(); err != nil {
		return err
	}
	if response.Type != stun.BindingSuccess || response.TransactionID != request.TransactionID {
		return fmt.Errorf("unexpected STUN response")
	}
	var reflected stun.XORMappedAddress
	if err := reflected.GetFrom(response); err != nil {
		return err
	}
	local := connection.LocalAddr().(*net.UDPAddr)
	if !reflected.IP.Equal(local.IP) || reflected.Port != local.Port {
		return fmt.Errorf("reflected address %s does not match local address %s", reflected.String(), local.String())
	}
	return nil
}
