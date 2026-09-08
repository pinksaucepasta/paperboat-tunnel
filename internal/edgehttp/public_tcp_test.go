package edgehttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func publicTCPDecision(now time.Time, port uint16) connectorprotocol.IngressDecision {
	return connectorprotocol.IngressDecision{Binding: connectorprotocol.IngressBinding{EnvironmentID: "environment_tcp", AccountID: "account_replica", TunnelID: "tunnel_replica", Lifecycle: connectorprotocol.TunnelDurable, ResourceGeneration: 1, RouteID: "route_tcp", RouteGeneration: 1, TargetID: "target_tcp", TargetGeneration: 1, HostID: "host_pinned", InstallationGeneration: 1, Audience: "public", ConnectionMethod: "edge", Protocol: "tcp", Hostname: "tcp.customer.test", OriginScheme: "tcp", OriginAddress: "127.0.0.1:9000", TLSVerification: "not_applicable", PublicationID: "publication_tcp", PublicationGeneration: 1, ListenerID: "listener_tcp", PublicPort: port}, DecisionID: "decision_tcp", PolicyGeneration: 1, EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", ConnectorID: "connector_pinned", SessionID: "session_pinned", ProcessGeneration: 3, ConfigGeneration: 3, AssignmentGeneration: 1, Action: "view", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(9 * time.Second)}
}

func TestForwardPublicTCPValidatesAuthorityAndPreservesHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	carrier, connector := testEdgePreviewCarrierPair(t, identity)
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Attach(carrier); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	decision := publicTCPDecision(now, port)
	current := func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
		return decision, nil
	}
	forwardDone := make(chan error, 1)
	go func() { forwardDone <- registry.ForwardPublicTCP(context.Background(), accepted, decision, current) }()
	stream, open, err := connector.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if open.Kind != "tcp_public" || open.RouteID != decision.Binding.RouteID {
		t.Fatalf("open=%+v", open)
	}
	if got, err := connectorprotocol.ReadIngressDecision(stream, time.Now().UTC()); err != nil || got.Binding != decision.Binding {
		t.Fatalf("decision=%+v err=%v", got, err)
	}
	uploadBytes := bytes.Repeat([]byte{0, 255, 13, 10, 1, 128, 70, 73, 78}, 8192)
	replyBytes := []byte{255, 0, 10, 13, 128, 254}
	if _, err := client.Write(uploadBytes); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	upload, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(upload, uploadBytes) {
		t.Fatalf("upload=%q err=%v", upload, err)
	}
	if _, err := stream.Write(replyBytes); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(reply, replyBytes) {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	select {
	case err := <-forwardDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("forward did not release")
	}
}

func TestForwardPublicTCPRejectsInvalidTargetBeforeOpeningCarrier(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	carrier, connector := testEdgePreviewCarrierPair(t, identity)
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Attach(carrier); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := publicTCPDecision(now, uint16(listener.Addr().(*net.TCPAddr).Port))
	current := func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
		return valid, nil
	}
	for name, mutate := range map[string]func(*connectorprotocol.IngressDecision){
		"wrong port":   func(d *connectorprotocol.IngressDecision) { d.Binding.PublicPort++ },
		"wrong target": func(d *connectorprotocol.IngressDecision) { d.Binding.TargetID = "target_other" },
		"expired": func(d *connectorprotocol.IngressDecision) {
			d.IssuedAt = now.Add(-11 * time.Second)
			d.ExpiresAt = now.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := registry.ForwardPublicTCP(context.Background(), accepted, candidate, current); err == nil {
				t.Fatal("invalid decision accepted")
			}
		})
	}
	acceptCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := connector.AcceptStream(acceptCtx); err == nil {
		t.Fatal("invalid decision reached daemon carrier")
	}
}
