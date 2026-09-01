package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func testPrivateAccessGrantRequest(now time.Time) connectorprotocol.PrivateAccessRequest {
	return connectorprotocol.PrivateAccessRequest{
		AccountID: "account_1", ResourceKind: "tunnel", ResourceID: "tunnel_1", RouteID: "route_1",
		Audience: "paperboat-tunnel-http", DeviceID: "machine_1", SessionID: "installation_1", InstallationGeneration: 1,
		ExpiresAt: now.Add(time.Minute), Nonce: "nonce_1", ConnectorID: "connector_1", CarrierSessionID: "session_1",
		RouteGeneration: 2, ProcessGeneration: 3, ConfigGeneration: 4, SessionGeneration: 5, AssignmentGeneration: 6,
		EdgeNodeID: "edge_1", EdgeProcessEpoch: "edge_epoch_1", Protocol: "http", Method: http.MethodConnect,
		Host: "private.preview.example.test", Path: "/", IdempotencyKey: "access_1", RequestID: "request_1", CorrelationID: "correlation_1",
	}
}

func TestPrivateAccessGrantClientUsesOnlyEdgeAuthAndSignedGrant(t *testing.T) {
	now := time.Now().UTC()
	input := testPrivateAccessGrantRequest(now)
	client := controlClient(t, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != PrivateAccessGrantAuthorizePath {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testControlCredential || request.Header.Get("X-Paperboat-Edge-Node-ID") != "edge_1" || request.Header.Get("X-Paperboat-Edge-Process-Epoch") != "edge_epoch_1" || request.Header.Get("X-Paperboat-Private-Access-Grant") != "signed-grant" {
			t.Fatalf("edge headers = %v", request.Header)
		}
		for _, forbidden := range []string{"Cookie", "X-Paperboat-Access-Cookie", "X-Paperboat-Access-Authorization", "X-Paperboat-Machine-Identity", "X-Paperboat-Machine-Proof"} {
			if request.Header.Get(forbidden) != "" {
				t.Fatalf("browser or machine proof header %s reached edge authorization", forbidden)
			}
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var got connectorprotocol.PrivateAccessRequest
		if err := json.Unmarshal(body, &got); err != nil || got != input || strings.Contains(string(body), "cookie") || strings.Contains(string(body), "proof") || strings.Contains(string(body), "bearer") {
			t.Fatalf("body = %s err=%v", body, err)
		}
		decision := PrivateAccessGrantDecision{
			Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_authorization", DecisionID: "decision_1", Allowed: true, Reason: "allowed",
			ExpiresAt: now.Add(30 * time.Second), RequestID: input.RequestID, CorrelationID: input.CorrelationID,
			ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, RouteID: input.RouteID, OperationID: input.OperationID,
			ConnectorID: input.ConnectorID, CarrierSessionID: input.CarrierSessionID, RouteGeneration: input.RouteGeneration,
			SessionGeneration: input.SessionGeneration, ProcessGeneration: input.ProcessGeneration, ConfigGeneration: input.ConfigGeneration,
			AssignmentGeneration: input.AssignmentGeneration, Protocol: input.Protocol,
		}
		payload, _ := json.Marshal(decision)
		return response(http.StatusOK, string(payload)), nil
	})
	authorizer, err := NewPrivateAccessGrantClient(client, "edge_1", "edge_epoch_1")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := authorizer.AuthorizePrivateAccessGrant(context.Background(), "signed-grant", input)
	if err != nil || !decision.Allowed || decision.RouteID != input.RouteID {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestPrivateAccessGrantClientMapsAuthorizationStatus(t *testing.T) {
	now := time.Now().UTC()
	input := testPrivateAccessGrantRequest(now)
	for _, test := range []struct {
		status int
		want   error
	}{{http.StatusUnauthorized, ErrPrivateAccessGrantUnauthorized}, {http.StatusForbidden, ErrPrivateAccessGrantForbidden}, {http.StatusServiceUnavailable, ErrPrivateAccessGrantUnavailable}} {
		client := controlClient(t, func(*http.Request) (*http.Response, error) {
			return response(test.status, `{"schema":"paperboat.preview-tunnel/v1","kind":"private_access_authorization","allowed":false,"reason":"denied","expires_at":"`+now.Add(time.Second).Format(time.RFC3339Nano)+`","request_id":"request_1","correlation_id":"correlation_1"}`), nil
		})
		authorizer, err := NewPrivateAccessGrantClient(client, "edge_1", "edge_epoch_1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authorizer.AuthorizePrivateAccessGrant(context.Background(), "signed-grant", input); !errors.Is(err, test.want) {
			t.Fatalf("status=%d err=%v want=%v", test.status, err, test.want)
		}
	}
}

func TestAccessorAdmissionCarriesAuthoritativeAssignment(t *testing.T) {
	a := PrivateAccessCarrierAdmission{AccountID: "account_1", DeviceID: "machine_1", TunnelID: "tunnel_1", CarrierConnectorID: "connector_1", CarrierSessionID: "session_1", ProcessGeneration: 2, ConfigGeneration: 3, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_1", AssignmentID: "assignment_1", RouteID: "route_1", AssignmentGeneration: 9, RouteGeneration: 7, ConfigContentHash: "sha256:" + strings.Repeat("a", 64), AccessorPublicKey: "key", AccessorThumbprint: "thumb", ExpiresAt: time.Now().Add(time.Minute)}
	got := a.Durable()
	if got.AssignmentID != a.AssignmentID || got.ConfigContentHash != a.ConfigContentHash || got.AssignmentID == got.RouteID {
		t.Fatalf("durable admission fabricated assignment binding: %#v", got)
	}
}

func TestAccessorAdmissionRejectsMalformedWireFields(t *testing.T) {
	now := time.Now().UTC()
	trust, err := NewProcessCarrierServerTrust("edge_1", "epoch_1", "edge.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	valid := func() PrivateAccessCarrierAdmission {
		return PrivateAccessCarrierAdmission{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_admission", AccountID: "account_1", DeviceID: "machine_1", InstallationGeneration: 1, AccessorPublicKey: "ugS1P3D8QWeKLIzyLOMZD8l_wp1lo6uY6NdicTbDz58", AccessorThumbprint: "ACVmA_IRxdrb0sXXfLqW6uB5U1oI6rRLPxHcQ0jimlg", ResourceKind: "tunnel", ResourceID: "tunnel_1", TunnelName: "payments", RouteName: "postgres", ConnectorID: "connector_1", CarrierSessionID: "session_1", RouteID: "route_1", RouteGeneration: 1, SessionGeneration: 1, ProcessGeneration: 1, ConfigGeneration: 1, AssignmentGeneration: 1, AssignmentID: "assignment_1", ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_1", EdgeCarrierServerSPKISHA256: trust.SPKISHA256, EdgeCarrierServerCertificateChainPEM: trust.CertificateChainPEM, Protocol: "http", Hostname: "web.example.test", MatchType: "exact", EdgeEndpoints: []string{"tls://edge.example.test:25001", "quic://edge.example.test:25002"}, ExpiresAt: now.Add(time.Minute), TunnelID: "tunnel_1", CarrierConnectorID: "connector_1"}
	}
	for name, mutate := range map[string]func(*PrivateAccessCarrierAdmission){
		"uppercase hash": func(a *PrivateAccessCarrierAdmission) { a.ConfigContentHash = "sha256:" + strings.Repeat("A", 64) },
		"nonhex hash":    func(a *PrivateAccessCarrierAdmission) { a.ConfigContentHash = "sha256:" + strings.Repeat("z", 64) },
		"missing port":   func(a *PrivateAccessCarrierAdmission) { a.EdgeEndpoints[0] = "tls://edge.example.test" },
		"zero port":      func(a *PrivateAccessCarrierAdmission) { a.EdgeEndpoints[0] = "tls://edge.example.test:0" },
		"unknown match":  func(a *PrivateAccessCarrierAdmission) { a.MatchType = "recursive" },
		"missing tunnel name": func(a *PrivateAccessCarrierAdmission) {
			a.TunnelName = ""
		},
		"invalid route name": func(a *PrivateAccessCarrierAdmission) {
			a.RouteName = "route name"
		},
		"recursive wildcard": func(a *PrivateAccessCarrierAdmission) {
			a.MatchType = "one_label_wildcard"
			a.Hostname = "**.example.test"
			a.WildcardSuffix = "example.test"
		},
		"invalid suffix": func(a *PrivateAccessCarrierAdmission) {
			a.MatchType = "one_label_wildcard"
			a.Hostname = "*.example.test"
			a.WildcardSuffix = "*.example.test"
		},
		"protocol resource mismatch": func(a *PrivateAccessCarrierAdmission) {
			a.ResourceKind = "preview"
			a.OperationID = "operation_1"
			a.ConnectorID = ""
			a.TunnelName = ""
			a.RouteName = ""
			a.Protocol = "private_tcp"
			a.Hostname = ""
			a.MatchType = "catch_all"
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := valid()
			mutate(&a)
			if a.Validate("edge_1", "epoch_1", now) == nil {
				t.Fatal("malformed admission accepted")
			}
		})
	}
}
