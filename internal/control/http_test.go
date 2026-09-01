package control

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

const testControlCredential = "edge-control-test-012345678901234567890123456789"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func controlClient(t *testing.T, roundTrip roundTripFunc) *HTTPClient {
	t.Helper()
	client, err := NewHTTPClient(HTTPConfig{BaseURL: "https://control.test", Credential: testControlCredential, Timeout: time.Second, Client: &http.Client{Transport: roundTrip}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func usageKey() usage.Key {
	return usage.Key{Node: "edge", Epoch: "epoch", Environment: "env", Route: "route", Revision: 1, Direction: "egress"}
}

func TestHTTPClientTypedOperationsAndAuthentication(t *testing.T) {
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+testControlCredential {
			t.Errorf("unsafe auth request: %s %v", r.URL.String(), r.Header)
			return response(http.StatusUnauthorized, ""), nil
		}
		switch r.URL.Path {
		case "/v1/edge/assignments/current":
			data, _ := json.Marshal(map[string]any{"connector_generation": 3, "edge_pool": "default", "edge_node_id": "edge_1", "revoked": false})
			return response(http.StatusOK, string(data)), nil
		case "/v1/edge/usage-reports":
			var wire map[string]any
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || wire["edge_node_id"] != "edge" || wire["route_id"] != "route" || wire["counter_epoch"] != "epoch" {
				t.Errorf("usage wire = %#v", wire)
			}
			data, _ := json.Marshal(UsageResult{Delta: 10})
			return response(http.StatusOK, string(data)), nil
		case "/v1/nodes/register":
			var registration NodeRegistration
			if err := json.NewDecoder(r.Body).Decode(&registration); err != nil || registration.SignalingHost != "signal.example.test" || registration.STUNEndpoint.Host != "edge.example.test" || registration.STUNEndpoint.Port != 3478 || registration.CarrierEndpoint.Host != "edge.example.test" || registration.CarrierEndpoint.TCPPort != 27443 || registration.CarrierEndpoint.QUICPort != 27444 || !ValidCarrierServerSPKISHA256(registration.CarrierServerSPKISHA256) || registration.CarrierServerCertificateChainPEM == "" {
				t.Errorf("registration wire = %+v, %v", registration, err)
			}
			return response(http.StatusNoContent, ""), nil
		case "/v1/nodes/heartbeat":
			return response(http.StatusNoContent, ""), nil
		case "/v1/edge/routes/desired-state":
			return response(http.StatusOK, `{"routes":[{"route_id":"route","route_revision":2,"environment_id":"env","connector_generation":3,"edge_node_id":"edge","kind":"runtime_https_wss","public_host":"app.example.test","target":{"host":"127.0.0.1","port":8080}}]}`), nil
		case "/v1/edge/routes/observations":
			return response(http.StatusNoContent, ""), nil
		case "/v1/trust/revocations":
			if r.Method != http.MethodGet {
				t.Errorf("revocation method = %s", r.Method)
			}
			return response(http.StatusOK, `{"jtis":["jti_revoked"],"environments":[],"helper_generations":[],"key_ids":[]}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})
	current, err := client.Current(context.Background(), "env", "machine", "runtime")
	if err != nil || current.Generation != 3 || current.EdgeNode != "edge_1" {
		t.Fatalf("current = %+v, %v", current, err)
	}
	result, err := client.ReportUsage(context.Background(), UsageReport{OperationID: "op", Key: usageKey(), Interval: [2]time.Time{time.Unix(1, 0), time.Unix(2, 0)}})
	if err != nil || result.Delta != 10 {
		t.Fatalf("usage = %+v, %v", result, err)
	}
	trust, err := NewProcessCarrierServerTrust("edge", "epoch", "edge.example.test", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RegisterNode(context.Background(), NodeRegistration{NodeID: "edge", ProcessEpoch: "epoch", Capacity: 1, SignalingHost: "signal.example.test", CarrierEndpoint: ConnectorEndpoint{Host: "edge.example.test", TCPPort: 27443, QUICPort: 27444}, CarrierServerSPKISHA256: trust.SPKISHA256, CarrierServerCertificateChainPEM: trust.CertificateChainPEM, STUNEndpoint: UDPEndpoint{Host: "edge.example.test", Port: 3478}}); err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(context.Background(), NodeObservation{NodeID: "edge"}); err != nil {
		t.Fatal(err)
	}
	routes, err := client.DesiredRoutes(context.Background(), "edge")
	if err != nil || len(routes) != 1 || routes[0].Revision != 2 {
		t.Fatalf("routes = %+v, %v", routes, err)
	}
	revocations, err := client.Revocations(context.Background())
	if err != nil || !strings.Contains(string(revocations), "jti_revoked") {
		t.Fatalf("revocations = %s, %v", revocations, err)
	}
	if err := client.ObserveRoutes(context.Background(), "edge", []RouteObservation{{RouteID: "route", RouteRevision: 2, EdgeNodeID: "edge", ConnectorGeneration: 3}}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientClassifiesStaleHeartbeat(t *testing.T) {
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/nodes/heartbeat" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		return response(http.StatusConflict, `{"code":"node_observation_stale"}`), nil
	})
	if err := client.Heartbeat(context.Background(), NodeObservation{NodeID: "edge"}); !errors.Is(err, ErrNodeObservationStale) {
		t.Fatalf("heartbeat error = %v", err)
	}
}

func TestHTTPClientRejectsPlaintextRedirectMalformedAndOversized(t *testing.T) {
	if _, err := NewHTTPClient(HTTPConfig{BaseURL: "http://control.test", Credential: testControlCredential, Timeout: time.Second}); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("plaintext = %v", err)
	}
	client := controlClient(t, func(*http.Request) (*http.Response, error) {
		result := response(http.StatusTemporaryRedirect, "")
		result.Header.Set("Location", "https://other.test/")
		return result, nil
	})
	if _, err := client.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("redirect = %v", err)
	}
	malformed := controlClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"connector_generation":3,"unknown":true}`), nil
	})
	if _, err := malformed.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("malformed = %v", err)
	}
	duplicate := controlClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"connector_generation":3,"connector_generation":4,"edge_pool":"default","edge_node_id":"edge"}`), nil
	})
	if _, err := duplicate.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("duplicate = %v", err)
	}
	oversized := controlClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.Repeat("x", maxControlDocument+1)), nil
	})
	if _, err := oversized.Current(context.Background(), "env", "machine", "runtime"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("oversized = %v", err)
	}
	if _, err := oversized.Revocations(context.Background()); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("oversized revocations = %v", err)
	}
}

func TestHTTPClientPreviewCarrierCompleteSnapshotAndNodeBinding(t *testing.T) {
	admission := testPreviewCarrierAdmissionForHTTP(t, "preview_1", "operation_1", "route_1", "one.preview.example.test", time.Now().UTC().Add(time.Hour))
	detachment := PreviewCarrierDetachment{
		Schema: admission.Schema, Kind: admission.Kind, Binding: admission.Binding,
		AttachmentGeneration: 2, Reason: "server_detach", ObservedAt: time.Now().UTC(),
	}
	var paths []string
	var methods []string
	var nodeHeaders []string
	var processEpochHeaders []string
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		methods = append(methods, r.Method)
		nodeHeaders = append(nodeHeaders, r.Header.Get("X-Paperboat-Edge-Node-ID"))
		processEpochHeaders = append(processEpochHeaders, r.Header.Get("X-Paperboat-Edge-Process-Epoch"))
		if r.Header.Get("Authorization") != "Bearer "+testControlCredential {
			t.Fatalf("preview request missing bearer")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case PreviewCarrierAdmissionsPath:
			if r.Method != http.MethodPost || string(body) != `{"edge_node_id":"edge_1","edge_process_epoch":"edge_epoch_1"}` {
				t.Fatalf("pull request = %s %s", r.Method, body)
			}
			payload, _ := json.Marshal(struct {
				Schema      string                     `json:"schema"`
				Kind        string                     `json:"kind"`
				Complete    bool                       `json:"complete"`
				Admissions  []PreviewCarrierAdmission  `json:"admissions"`
				Detachments []PreviewCarrierDetachment `json:"detachments"`
			}{Schema: "paperboat.preview-tunnel/v1", Kind: "preview_carrier_attachment", Complete: true, Admissions: []PreviewCarrierAdmission{admission}, Detachments: []PreviewCarrierDetachment{detachment}})
			return response(http.StatusOK, string(payload)), nil
		case PreviewCarrierAdmissionAcksPath:
			var request struct {
				NodeID       string                    `json:"edge_node_id"`
				ProcessEpoch string                    `json:"edge_process_epoch"`
				Admissions   []PreviewCarrierAdmission `json:"admissions"`
			}
			if err := json.Unmarshal(body, &request); err != nil || request.NodeID != "edge_1" || request.ProcessEpoch != "edge_epoch_1" || len(request.Admissions) != 1 || request.Admissions[0].Binding.OperationID != admission.Binding.OperationID {
				t.Fatalf("ack request = %s", body)
			}
			return response(http.StatusNoContent, ""), nil
		case PreviewCarrierObservationsPath:
			var request struct {
				NodeID       string                      `json:"edge_node_id"`
				ProcessEpoch string                      `json:"edge_process_epoch"`
				Observations []PreviewCarrierObservation `json:"observations"`
			}
			if err := json.Unmarshal(body, &request); err != nil || request.NodeID != "edge_1" || request.ProcessEpoch != "edge_epoch_1" || len(request.Observations) != 1 {
				t.Fatalf("observation request = %s", body)
			}
			return response(http.StatusNoContent, ""), nil
		case PreviewCarrierDetachmentsPath:
			var request struct {
				NodeID       string                     `json:"edge_node_id"`
				ProcessEpoch string                     `json:"edge_process_epoch"`
				Detachments  []PreviewCarrierDetachment `json:"detachments"`
			}
			if err := json.Unmarshal(body, &request); err != nil || request.NodeID != "edge_1" || request.ProcessEpoch != "edge_epoch_1" || len(request.Detachments) != 1 || request.Detachments[0].AttachmentGeneration != 2 {
				t.Fatalf("detachment request = %s", body)
			}
			return response(http.StatusNoContent, ""), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})
	snapshot, err := client.PreviewCarrierSnapshot(context.Background(), "edge_1", "edge_epoch_1")
	if err != nil || len(snapshot.Admissions) != 1 || len(snapshot.Detachments) != 1 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	if err := client.AcknowledgePreviewCarrierAdmissions(context.Background(), "edge_1", "edge_epoch_1", []PreviewCarrierAdmission{admission}); err != nil {
		t.Fatal(err)
	}
	observation := PreviewCarrierObservation{Schema: admission.Schema, Kind: admission.Kind, Binding: admission.Binding, AttachmentGeneration: admission.AttachmentGeneration, State: "edge_ready", ObservedAt: time.Now().UTC()}
	if err := client.ObservePreviewCarriers(context.Background(), "edge_1", "edge_epoch_1", []PreviewCarrierObservation{observation}); err != nil {
		t.Fatal(err)
	}
	if err := client.DetachPreviewCarriers(context.Background(), "edge_1", "edge_epoch_1", []PreviewCarrierDetachment{detachment}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 || paths[0] != PreviewCarrierAdmissionsPath || paths[1] != PreviewCarrierAdmissionAcksPath || paths[2] != PreviewCarrierObservationsPath || paths[3] != PreviewCarrierDetachmentsPath {
		t.Fatalf("preview paths = %#v", paths)
	}
	for index := range methods {
		if methods[index] != http.MethodPost || nodeHeaders[index] != "edge_1" || processEpochHeaders[index] != "edge_epoch_1" {
			t.Fatalf("preview request %d method/node/epoch = %s/%s/%s", index, methods[index], nodeHeaders[index], processEpochHeaders[index])
		}
	}
}

func TestHTTPClientPreviewCarrierRejectsIncompleteSnapshot(t *testing.T) {
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != PreviewCarrierAdmissionsPath || r.Header.Get("X-Paperboat-Edge-Node-ID") != "edge_1" || r.Header.Get("X-Paperboat-Edge-Process-Epoch") != "edge_epoch_1" {
			t.Fatalf("pull path/node/epoch = %s/%s/%s", r.URL.Path, r.Header.Get("X-Paperboat-Edge-Node-ID"), r.Header.Get("X-Paperboat-Edge-Process-Epoch"))
		}
		return response(http.StatusOK, `{"complete":false,"admissions":[],"detachments":[]}`), nil
	})
	if _, err := client.PreviewCarrierSnapshot(context.Background(), "edge_1", "edge_epoch_1"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("incomplete snapshot error = %v", err)
	}
}

func TestHTTPClientPrivateAccessAdmissionsBindsProcessEpochHeader(t *testing.T) {
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != PrivateAccessCarrierAdmissionsPath || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testControlCredential || r.Header.Get("X-Paperboat-Edge-Node-ID") != "edge_1" || r.Header.Get("X-Paperboat-Edge-Process-Epoch") != "edge_epoch_1" {
			t.Fatalf("private admission headers = %s auth=%q node=%q epoch=%q", r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Paperboat-Edge-Node-ID"), r.Header.Get("X-Paperboat-Edge-Process-Epoch"))
		}
		return response(http.StatusUnauthorized, `{"code":"edge_identity_invalid"}`), nil
	})
	if _, err := client.PrivateAccessCarrierAdmissions(context.Background(), "edge_1", "edge_epoch_1"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf("private admissions error = %v", err)
	}
}

func TestPreviewCarrierAdmissionRejectsUnknownState(t *testing.T) {
	admission := testPreviewCarrierAdmissionForHTTP(t, "preview_state", "operation_state", "route_state", "state.preview.example.test", time.Now().UTC().Add(time.Hour))
	admission.State = "server_owned_unknown"
	if err := admission.Validate("edge_1", time.Now().UTC(), "edge_epoch_1"); !errors.Is(err, ErrPreviewCarrierInvalid) {
		t.Fatalf("unknown admission state error = %v, want ErrPreviewCarrierInvalid", err)
	}
}

func TestPreviewCarrierAdmissionValidatesCustomAliasGenerations(t *testing.T) {
	now := time.Now().UTC()
	one := 1
	admission := testPreviewCarrierAdmissionForHTTP(t, "preview_alias", "operation_alias", "route_alias", "managed.preview.example.test", now.Add(time.Hour))
	admission.Aliases = []PreviewCarrierAlias{{
		DomainID: "domain_alias", Hostname: "*.customer.example", MatchType: "one_label_wildcard", WildcardLabels: &one,
		PreviewGeneration: admission.Binding.LeaseGeneration, DomainGeneration: 2, CertificateGeneration: 3,
	}}
	if err := admission.Validate("edge_1", now, "edge_epoch_1"); err != nil {
		t.Fatalf("valid alias: %v", err)
	}
	for name, mutate := range map[string]func(*PreviewCarrierAdmission){
		"wrong preview generation":       func(value *PreviewCarrierAdmission) { value.Aliases[0].PreviewGeneration++ },
		"recursive wildcard":             func(value *PreviewCarrierAdmission) { value.Aliases[0].Hostname = "**.customer.example" },
		"missing certificate generation": func(value *PreviewCarrierAdmission) { value.Aliases[0].CertificateGeneration = 0 },
		"duplicate hostname": func(value *PreviewCarrierAdmission) {
			value.Aliases = append(value.Aliases, PreviewCarrierAlias{DomainID: "domain_other", Hostname: value.Aliases[0].Hostname, MatchType: value.Aliases[0].MatchType, PreviewGeneration: value.Binding.LeaseGeneration, DomainGeneration: 1, CertificateGeneration: 1})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := admission
			candidate.Aliases = append([]PreviewCarrierAlias(nil), admission.Aliases...)
			mutate(&candidate)
			if err := candidate.Validate("edge_1", now, "edge_epoch_1"); !errors.Is(err, ErrPreviewCarrierInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func testPreviewCarrierAdmissionForHTTP(t *testing.T, previewID, operationID, routeID, hostname string, expiresAt time.Time) PreviewCarrierAdmission {
	t.Helper()
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	digest := sha256.Sum256(publicKey)
	trust, err := NewProcessCarrierServerTrust("edge_1", "edge_epoch_1", "edge.example.test", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return PreviewCarrierAdmission{
		Schema: "paperboat.preview-tunnel/v1", Kind: "preview_carrier_attachment",
		Binding:              PreviewCarrierBinding{AccountID: "account_1", PreviewID: previewID, OperationID: operationID, OwnerDeviceID: "host_1", OwnerSessionID: "owner_session_1", HostID: "host_1", LeaseGeneration: 1, TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 1, ConfigGeneration: 1, RouteID: routeID, RouteGeneration: 1, EdgeNodeID: "edge_1", EdgeProcessEpoch: "edge_epoch_1", EdgeCarrierServerSPKISHA256: trust.SPKISHA256, EdgeCarrierServerCertificateChainPEM: trust.CertificateChainPEM, MachineIdentityPublicKey: base64.RawURLEncoding.EncodeToString(publicKey), MachineIdentityThumbprint: "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])},
		AttachmentGeneration: 1, ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", EdgeEndpoints: []string{"tls://edge.example.test:27443", "quic://edge.example.test:27444"}, Endpoint: "https://" + hostname, ExpiresAt: expiresAt, AccessMode: "public", RouteKind: "preview_public_https_wss", RouteRevision: 1,
	}
}
