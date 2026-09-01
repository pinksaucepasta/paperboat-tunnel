package edgehttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type privateAccessGrantAuthorizerFunc func(context.Context, string, connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error)

func (f privateAccessGrantAuthorizerFunc) AuthorizePrivateAccessGrant(ctx context.Context, grant string, request connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error) {
	return f(ctx, grant, request)
}

type privateTCPRouteSnapshot struct{ rules []route.RouteRule }

func (s privateTCPRouteSnapshot) CanonicalSnapshot() (uint64, []route.RouteRule, bool) {
	return 1, append([]route.RouteRule(nil), s.rules...), true
}

func TestPrivateTCPFullAuthenticatedEdgePath(t *testing.T) {
	now := time.Now().UTC()
	durableIdentity := datacarrier.Identity{AccountID: "account_1", HostID: "owner_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 2, Generation: 3}
	accessorIdentity := durableIdentity
	accessorIdentity.HostID = "accessor_1"
	request := edgePrivateAccessRequest(now)
	request.AccountID, request.DeviceID = accessorIdentity.AccountID, accessorIdentity.HostID
	request.ResourceKind, request.ResourceID = "tunnel", durableIdentity.TunnelID
	request.Audience, request.Protocol = "paperboat-tunnel-tcp", "tcp"
	request.Method, request.Host, request.Path = "", "", ""
	request.ConnectorID, request.CarrierSessionID = durableIdentity.ConnectorID, durableIdentity.SessionID
	request.ProcessGeneration, request.ConfigGeneration = durableIdentity.ProcessGeneration, durableIdentity.Generation
	rule := route.RouteRule{ID: request.RouteID, RouteID: request.RouteID, RouteGeneration: request.RouteGeneration, AssignmentID: "assignment_private_tcp", AssignmentGeneration: request.AssignmentGeneration, ResourceKind: "tunnel", SessionGeneration: request.SessionGeneration, AccountID: request.AccountID, HostID: durableIdentity.HostID, TunnelID: request.ResourceID, ConnectorID: request.ConnectorID, ConnectorSessionID: request.CarrierSessionID, ConnectorProcessGeneration: request.ProcessGeneration, ConfigGeneration: request.ConfigGeneration, ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Node: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch, Kind: route.TunnelPrivateTCP, Protocol: "private_tcp", AccessMode: "private"}

	t.Run("allow duplex", func(t *testing.T) {
		accessorServer, accessorClient := testEdgePreviewCarrierPair(t, accessorIdentity)
		durableServer, durableClient := testEdgePreviewCarrierPair(t, durableIdentity)
		registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 4})
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		state := replicaState(rule, durableIdentity.Generation, rule.AssignmentID, "zone_1", time.Millisecond, 4)
		if err := registry.AttachReplica(durableServer, "owner-key", "owner-thumb", state); err != nil {
			t.Fatal(err)
		}
		routeTarget := PrivateAccessRouteTarget{HTTP: PrivateAccessTargetFunc(func(context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
			t.Fatal("TCP reached Caddy target")
			return nil, nil
		}), Routes: privateTCPRouteSnapshot{rules: []route.RouteRule{rule}}, Carriers: registry}
		bridge, err := NewPrivateAccessStreamBridge(PrivateAccessStreamBridgeConfig{Authorizer: privateAccessGrantAuthorizerFunc(func(context.Context, string, connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error) {
			return control.PrivateAccessGrantDecision{Allowed: true, ExpiresAt: now.Add(30 * time.Second)}, nil
		}), Target: routeTarget, Clock: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = bridge.Serve(ctx, accessorServer) }()
		originEdge, origin := net.Pipe()
		defer origin.Close()
		connectorDone := make(chan error, 1)
		connectorReady := make(chan error, 1)
		go func() {
			stream, open, err := durableClient.AcceptStream(ctx)
			if err != nil {
				connectorReady <- err
				connectorDone <- err
				return
			}
			if open.Kind != "tcp_private" || open.RouteID != rule.RouteID {
				err = errors.New("wrong durable stream")
				connectorReady <- err
				connectorDone <- err
				return
			}
			connectorReady <- nil
			payload := make([]byte, len("client-to-origin"))
			if _, err = io.ReadFull(stream, payload); err == nil {
				_, err = originEdge.Write(payload)
			}
			if err == nil {
				payload = make([]byte, len("origin-to-client"))
				_, err = io.ReadFull(originEdge, payload)
				if err == nil {
					_, err = stream.Write(payload)
				}
			}
			connectorDone <- err
		}()
		stream, err := accessorClient.OpenStream(ctx, connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: request.AccountID, TunnelID: accessorIdentity.TunnelID, ConnectorID: accessorIdentity.ConnectorID, SessionID: request.CarrierSessionID, ProcessGeneration: request.ProcessGeneration, Generation: request.ConfigGeneration, RouteID: request.RouteID, RequestID: request.RequestID, Kind: connectorprotocol.PrivateAccessTCP})
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		if err := connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: "grant", Request: request}); err != nil {
			t.Fatal(err)
		}
		result, err := connectorprotocol.ReadPrivateAccessResult(stream, now)
		if err != nil || result.Status != http.StatusOK {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if err := <-connectorReady; err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = io.WriteString(stream, "client-to-origin") }()
		got := make([]byte, len("client-to-origin"))
		if _, err := io.ReadFull(origin, got); err != nil || string(got) != "client-to-origin" {
			t.Fatalf("origin got=%q err=%v", got, err)
		}
		go func() { _, _ = io.WriteString(origin, "origin-to-client") }()
		got = make([]byte, len("origin-to-client"))
		if _, err := io.ReadFull(stream, got); err != nil || string(got) != "origin-to-client" {
			t.Fatalf("client got=%q err=%v", got, err)
		}
		cancel()
		_ = originEdge.Close()
		select {
		case <-connectorDone:
		case <-time.After(time.Second):
			t.Fatal("durable bridge did not stop")
		}
	})

	for _, tc := range []struct {
		name        string
		mutate      func(*connectorprotocol.PrivateAccessRequest)
		allowed     bool
		withCarrier bool
		want        int
	}{{"wrong account", func(r *connectorprotocol.PrivateAccessRequest) { r.AccountID = "account_other" }, false, true, http.StatusForbidden}, {"stale assignment", func(r *connectorprotocol.PrivateAccessRequest) { r.AssignmentGeneration++ }, true, true, http.StatusServiceUnavailable}, {"removed carrier", func(*connectorprotocol.PrivateAccessRequest) {}, true, false, http.StatusServiceUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			accessorServer, accessorClient := testEdgePreviewCarrierPair(t, accessorIdentity)
			registry, _ := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2})
			defer registry.Close()
			var opened atomic.Int32
			var negativeDurableServer *datacarrier.Server
			if tc.withCarrier {
				durableServer, durableClient := testEdgePreviewCarrierPair(t, durableIdentity)
				negativeDurableServer = durableServer
				state := replicaState(rule, durableIdentity.Generation, rule.AssignmentID, "zone_1", time.Millisecond, 2)
				if err := registry.AttachReplica(durableServer, "owner-key", "owner-thumb", state); err != nil {
					t.Fatal(err)
				}
				acceptCtx, stopAccept := context.WithCancel(context.Background())
				defer stopAccept()
				go func() {
					stream, _, err := durableClient.AcceptStream(acceptCtx)
					if err == nil {
						opened.Add(1)
						_ = stream.Close()
					}
				}()
			}
			targetRules := privateTCPRouteSnapshot{rules: []route.RouteRule{rule}}
			bridge, _ := NewPrivateAccessStreamBridge(PrivateAccessStreamBridgeConfig{Authorizer: privateAccessGrantAuthorizerFunc(func(context.Context, string, connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error) {
				if !tc.allowed {
					return control.PrivateAccessGrantDecision{Allowed: false}, nil
				}
				return control.PrivateAccessGrantDecision{Allowed: true, ExpiresAt: now.Add(30 * time.Second)}, nil
			}), Target: PrivateAccessTargetFunc(func(ctx context.Context, got connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
				return (PrivateAccessRouteTarget{Routes: targetRules, Carriers: registry}).OpenPrivateAccessTarget(ctx, got)
			}), Clock: func() time.Time { return now }})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = bridge.Serve(ctx, accessorServer) }()
			gotRequest := request
			tc.mutate(&gotRequest)
			metadata := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: gotRequest.AccountID, TunnelID: accessorIdentity.TunnelID, ConnectorID: accessorIdentity.ConnectorID, SessionID: gotRequest.CarrierSessionID, ProcessGeneration: gotRequest.ProcessGeneration, Generation: gotRequest.ConfigGeneration, RouteID: gotRequest.RouteID, RequestID: gotRequest.RequestID, Kind: connectorprotocol.PrivateAccessTCP}
			// Wrong account is rejected by policy while retaining the authenticated
			// carrier metadata, so metadata itself cannot become authority.
			if tc.name == "wrong account" {
				metadata.AccountID = accessorIdentity.AccountID
				gotRequest.AccountID = accessorIdentity.AccountID
			}
			stream, err := accessorClient.OpenStream(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if err := connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: "grant", Request: gotRequest}); err != nil {
				t.Fatal(err)
			}
			result, err := connectorprotocol.ReadPrivateAccessResult(stream, now)
			if err != nil || result.Status != tc.want {
				t.Fatalf("result=%+v err=%v want=%d", result, err, tc.want)
			}
			if opened.Load() != 0 || negativeDurableServer != nil && negativeDurableServer.ActiveStreams() != 0 {
				t.Fatalf("origin target opened=%d", opened.Load())
			}
		})
	}
}

func edgePrivateAccessRequest(now time.Time) connectorprotocol.PrivateAccessRequest {
	return connectorprotocol.PrivateAccessRequest{
		AccountID: "account_1", ResourceKind: "preview", ResourceID: "preview_1", RouteID: "route_1",
		Audience: "paperboat-preview-http", DeviceID: "machine_1", SessionID: "installation_1", InstallationGeneration: 1,
		ExpiresAt: now.Add(time.Minute), Nonce: "nonce_1", OperationID: "operation_1", CarrierSessionID: "session_1",
		RouteGeneration: 1, ProcessGeneration: 2, ConfigGeneration: 3, SessionGeneration: 4, AssignmentGeneration: 5,
		EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_1", Protocol: "http", Method: http.MethodConnect,
		Host: "private.preview.example.test", Path: "/", IdempotencyKey: "access_1", RequestID: "request_1", CorrelationID: "correlation_1",
	}
}

func TestPrivateAccessStreamBridgeAuthorizesBeforeOpaqueDuplex(t *testing.T) {
	now := time.Now().UTC()
	identity := testEdgePreviewIdentity(2, 3)
	server, client := testEdgePreviewCarrierPair(t, identity)
	request := edgePrivateAccessRequest(now)
	request.AccountID = identity.AccountID
	request.DeviceID = identity.HostID
	request.CarrierSessionID = identity.SessionID
	request.ProcessGeneration = identity.ProcessGeneration
	request.ConfigGeneration = identity.Generation
	targetEdge, targetOrigin := net.Pipe()
	defer targetOrigin.Close()
	authorizer := privateAccessGrantAuthorizerFunc(func(_ context.Context, grant string, got connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error) {
		if grant != "signed-grant" || got != request {
			t.Fatalf("grant=%q request=%+v", grant, got)
		}
		return control.PrivateAccessGrantDecision{Allowed: true, ExpiresAt: now.Add(30 * time.Second)}, nil
	})
	bridge, err := NewPrivateAccessStreamBridge(PrivateAccessStreamBridgeConfig{Authorizer: authorizer, Target: PrivateAccessTargetFunc(func(context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
		return targetEdge, nil
	}), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- bridge.Serve(runCtx, server) }()
	metadata := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: request.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: request.CarrierSessionID, ProcessGeneration: request.ProcessGeneration, Generation: request.ConfigGeneration, RouteID: request.RouteID, RequestID: request.RequestID, Kind: connectorprotocol.PrivateAccessHTTP}
	stream, err := client.OpenStream(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: "signed-grant", Request: request}); err != nil {
		t.Fatal(err)
	}
	result, err := connectorprotocol.ReadPrivateAccessResult(stream, now)
	if err != nil || result.Status != http.StatusOK {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	writeDone := make(chan error, 1)
	go func() { _, err := io.WriteString(stream, "browser-tls"); writeDone <- err }()
	got := make([]byte, len("browser-tls"))
	if _, err := io.ReadFull(targetOrigin, got); err != nil || string(got) != "browser-tls" {
		t.Fatalf("target bytes=%q err=%v", got, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = server.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop")
	}
}

func TestPrivateAccessStreamBridgeMapsAuthorizationFailures(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{{control.ErrPrivateAccessGrantUnauthorized, http.StatusUnauthorized}, {control.ErrPrivateAccessGrantForbidden, http.StatusForbidden}, {control.ErrPrivateAccessGrantUnavailable, http.StatusServiceUnavailable}} {
		if got := privateAccessErrorStatus(test.err); got != test.status {
			t.Fatalf("error %v status=%d want=%d", test.err, got, test.status)
		}
	}
	if !errors.Is(ErrPrivateAccessStreamInvalid, ErrPrivateAccessStreamInvalid) {
		t.Fatal("sentinel mismatch")
	}
}

func TestPrivateTCPRuleRequiresExactDurableGenerationTuple(t *testing.T) {
	request := edgePrivateAccessRequest(time.Now().UTC())
	request.ResourceKind = "tunnel"
	request.ResourceID = "tunnel_1"
	request.Audience = "paperboat-tunnel-tcp"
	request.Protocol = "tcp"
	request.Method, request.Host, request.Path = "", "", ""
	rule := route.RouteRule{RouteID: request.RouteID, RouteGeneration: request.RouteGeneration, AssignmentGeneration: request.AssignmentGeneration, ResourceKind: "tunnel", SessionGeneration: request.SessionGeneration, AccountID: request.AccountID, TunnelID: request.ResourceID, ConnectorID: request.ConnectorID, ConnectorSessionID: request.CarrierSessionID, ConnectorProcessGeneration: request.ProcessGeneration, ConfigGeneration: request.ConfigGeneration, Node: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch, Kind: route.TunnelPrivateTCP, Protocol: "private_tcp", AccessMode: "private"}
	if got, err := privateTCPRule([]route.RouteRule{rule}, request); err != nil || got.RouteID != rule.RouteID {
		t.Fatalf("exact route got=%+v err=%v", got, err)
	}
	stale := request
	stale.AssignmentGeneration++
	if _, err := privateTCPRule([]route.RouteRule{rule}, stale); !errors.Is(err, ErrPrivateAccessStreamInvalid) {
		t.Fatalf("stale assignment error=%v", err)
	}
	if _, err := privateTCPRule([]route.RouteRule{rule, rule}, request); !errors.Is(err, ErrPrivateAccessStreamInvalid) {
		t.Fatalf("duplicate route error=%v", err)
	}
}
