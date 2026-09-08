package edgehttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestDurableCarrierWebSocketUpgradeTraversesGatewayDuplex(t *testing.T) {
	identity := replicaIdentity("host_pinned", "connector_pinned", "session_pinned", 3)
	carrier, connector := testEdgePreviewCarrierPair(t, identity)
	rule := replicaRule()
	rule.Generation = 1
	rule.Target = rule.RouteID
	rule.Protocol = "websocket"
	rule.Hostname = "socket.customer.test"
	rule.MatchType = route.MatchExact
	rule.PathPrefix = "/"
	rule.AccessMode = "public"
	rule.ObservedState = "ready"
	rule.Node = "edge_01"
	rule.EdgeProcessEpoch = "epoch_0001"
	rule.EdgeFailureDomain = "region_01"
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.AttachReplica(carrier, "key", "thumb", replicaState(rule, 3, rule.AssignmentID, "region_01", time.Millisecond, 2)); err != nil {
		t.Fatal(err)
	}
	transport, err := NewDataCarrierRouteTransport(DataCarrierRouteTransportConfig{Registry: registry, StreamOpenTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	routes := route.NewRegistry("preview.example.test", "runtime.example.test")
	if err := routes.ApplyGeneration(context.Background(), 1, []route.RouteRule{rule}, func(context.Context, []route.RouteRule) error { return nil }, 0); err != nil {
		t.Fatal(err)
	}
	policy, err := NewGatewayWithTransports(Config{PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: routes}, "127.0.0.1:1", nil, transport)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(policy)
	defer server.Close()

	connectorDone := make(chan error, 1)
	go func() {
		stream, open, acceptErr := connector.AcceptStream(context.Background())
		if acceptErr != nil {
			connectorDone <- acceptErr
			return
		}
		defer stream.Close()
		request, readErr := http.ReadRequest(bufio.NewReader(stream))
		if readErr != nil {
			connectorDone <- readErr
			return
		}
		if open.Kind != "websocket" || !isWebSocketUpgrade(request.Header) {
			connectorDone <- ErrDataCarrierRouteInvalid
			return
		}
		if _, readErr = io.WriteString(stream, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nearly"); readErr != nil {
			connectorDone <- readErr
			return
		}
		late := make([]byte, len("late"))
		if _, readErr = io.ReadFull(stream, late); readErr == nil {
			_, readErr = stream.Write(append([]byte("echo:"), late...))
		}
		connectorDone <- readErr
	}()

	address := strings.TrimPrefix(server.URL, "http://")
	client, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(client, "GET /socket HTTP/1.1\r\nHost: socket.customer.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if _, err := client.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len("earlyecho:late"))
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "earlyecho:late" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	_ = client.Close()
	select {
	case err := <-connectorDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connector upgrade did not clean up")
	}
}
