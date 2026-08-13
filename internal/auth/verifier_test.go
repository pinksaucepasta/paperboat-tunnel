package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelayhttp"
)

func tokenFor(t testing.TB, private ed25519.PrivateKey, keyID string, mutate func(map[string]any)) string {
	t.Helper()
	now := time.Unix(1000, 0)
	header := map[string]any{"alg": "EdDSA", "kid": keyID, "typ": "paperboat-credential+jwt"}
	claims := map[string]any{"iss": "https://api.paperboat.test", "aud": "paperboat-edge", "sub": "machine", "jti": "jti_admit_01", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "scope": []string{"connector:admit"}, "credential_class": "connector_admission", "environment_id": "env", "machine_id": "machine", "installation_generation": 1, "connector_id": "runtime", "connector_generation": 3, "edge_pool": "default", "edge_node_id": "edge", "route_binding": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "file_transfer_policy": map[string]any{"revision": "file-transfer-v1", "max_file_bytes": 50 << 20, "max_batch_files": 10, "max_batch_bytes": 500 << 20, "max_concurrent_transfers": 2, "retention_seconds": 604800, "delivery_timeout_seconds": 600, "max_pending_spool_bytes": 1 << 30}}
	if mutate != nil {
		mutate(claims)
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signing)))
}

func TestVerifierAcceptsExactConnectorCredential(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }, ClockSkew: time.Minute}
	claims, err := verifier.Verify(context.Background(), tokenFor(t, private, "key-1", nil))
	if err != nil || claims.JTI != "jti_admit_01" || claims.ConnectorGeneration != 3 || claims.EdgeNodeID != "edge" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
}

func TestVerifierRejectsDuplicateSignedHeaderAndClaims(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }, ClockSkew: time.Minute}
	canonical := tokenFor(t, private, "key-1", nil)
	parts := strings.Split(canonical, ".")

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	duplicateHeader := strings.Replace(string(header), `"kid":"key-1"`, `"kid":"key-1","kid":"key-1"`, 1)
	if duplicateHeader == string(header) {
		t.Fatal("header fixture did not mutate")
	}
	if _, err := verifier.Verify(context.Background(), resignToken(duplicateHeader, string(mustDecodeSegment(t, parts[1])), private)); err == nil {
		t.Fatal("duplicate signed header accepted")
	}

	payload := string(mustDecodeSegment(t, parts[1]))
	duplicateClaims := strings.Replace(payload, `"jti":"jti_admit_01"`, `"jti":"jti_admit_01","jti":"jti_admit_01"`, 1)
	if duplicateClaims == payload {
		t.Fatal("claims fixture did not mutate")
	}
	if _, err := verifier.Verify(context.Background(), resignToken(string(header), duplicateClaims, private)); err == nil {
		t.Fatal("duplicate signed claims accepted")
	}

	if _, err := verifier.Verify(context.Background(), parts[0]+"=."+parts[1]+"."+parts[2]); err == nil {
		t.Fatal("non-canonical base64url header accepted")
	}
}

func resignToken(header, payload string, private ed25519.PrivateKey) string {
	headerPart := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadPart := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signing := headerPart + "." + payloadPart
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signing)))
}

func mustDecodeSegment(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestVerifierAuthenticatesPeerSignalingAndWatchesRevocation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := NewSnapshot()
	snapshot.keys["key-1"] = public
	snapshot.revocationUpdatedAt = time.Unix(1000, 0)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: snapshot, Revocations: snapshot, Now: func() time.Time { return time.Unix(1000, 0) }}
	token := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["sub"] = "endpoint_left"
		claims["jti"] = "jti_peer_left"
		claims["credential_class"] = "peer_signaling"
		claims["scope"] = []string{"peer:signal"}
		claims["intent_id"] = "intent_1"
		claims["endpoint_id"] = "endpoint_left"
		claims["peer_endpoint_id"] = "endpoint_right"
		claims["attempt_generation"] = 2
		claims["network_generation"] = 4
		claims["peer_role"] = "controlling"
		delete(claims, "machine_id")
		delete(claims, "installation_generation")
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "file_transfer_policy")
	})
	peer, err := verifier.Authenticate(context.Background(), token)
	if err != nil || peer.CredentialID != "jti_peer_left" || peer.EndpointID != "endpoint_left" || peer.PeerEndpointID != "endpoint_right" || peer.AttemptGeneration != 2 || peer.NetworkGeneration != 4 || peer.Role != "controlling" {
		t.Fatalf("peer=%+v error=%v", peer, err)
	}
	if len(snapshot.watchers) != 1 {
		t.Fatalf("watchers=%d", len(snapshot.watchers))
	}
	document := []byte(`{"jtis":["jti_peer_left"],"environments":[],"connector_generations":[],"key_ids":[]}`)
	if err := snapshot.ReplaceRevocations(document); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.Revoked:
	case <-time.After(time.Second):
		t.Fatal("peer revocation was not delivered")
	}
	peer.Release()
	if len(snapshot.watchers) != 0 {
		t.Fatalf("released watchers=%d", len(snapshot.watchers))
	}
	if _, err := verifier.Authenticate(context.Background(), token); err == nil {
		t.Fatal("revoked peer credential was accepted again")
	}
}

func TestVerifierAuthenticatesExactRelayAttachment(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", NodeID: "edge", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	route := base64.RawURLEncoding.EncodeToString([]byte("route-allocate01"))
	token := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["sub"] = "intent_1"
		claims["jti"] = "jti_peer_relay_1"
		claims["credential_class"] = "peer_relay"
		claims["scope"] = []string{"peer:relay"}
		claims["intent_id"] = "intent_1"
		claims["attempt_generation"] = 2
		claims["network_generation"] = 4
		claims["route_allocation"] = route
		claims["route_generation"] = 3
		claims["initiator_endpoint_id"] = "endpoint_left"
		claims["responder_endpoint_id"] = "endpoint_right"
		claims["relay_byte_limit"] = 1 << 20
		claims["relay_carriers"] = []string{"relay_quic", "relay_wss"}
		delete(claims, "machine_id")
		delete(claims, "installation_generation")
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "file_transfer_policy")
	})
	var handle [16]byte
	copy(handle[:], []byte("stream-handle-01"))
	got, err := verifier.AuthenticateRelay(context.Background(), token, peerrelayhttp.Attachment{StreamHandle: handle, EndpointID: "endpoint_left", Role: peerrelay.RoleInitiator, Carrier: peerrelay.CarrierWSS})
	if err != nil || got.Binding.RouteAllocation == [16]byte{} || got.Binding.StreamHandle != handle || got.Binding.IntentID != "intent_1" || got.Binding.RouteRevision != 3 || got.Binding.MaximumBytes != 1<<20 {
		t.Fatalf("admission=%+v err=%v", got, err)
	}
	if _, err := verifier.AuthenticateRelay(context.Background(), token, peerrelayhttp.Attachment{StreamHandle: handle, EndpointID: "endpoint_right", Role: peerrelay.RoleInitiator, Carrier: peerrelay.CarrierWSS}); err == nil {
		t.Fatal("relay role substitution accepted")
	}
	quic, err := verifier.AuthenticateRelay(context.Background(), token, peerrelayhttp.Attachment{StreamHandle: [16]byte{2}, EndpointID: "endpoint_left", Role: peerrelay.RoleInitiator, Carrier: peerrelay.CarrierQUIC})
	if err != nil || quic.Carrier != peerrelay.CarrierQUIC {
		t.Fatalf("relay QUIC admission=%+v error=%v", quic, err)
	}
}

func TestVerifierAuthenticatesPMTUOnlyCredential(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", NodeID: "edge", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	token := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["sub"] = "intent_1"
		claims["jti"] = "jti_peer_relay_1"
		claims["credential_class"] = "peer_pmtu"
		claims["scope"] = []string{"peer:pmtu"}
		claims["intent_id"] = "intent_1"
		claims["edge_node_id"] = "edge"
		claims["route_allocation"] = base64.RawURLEncoding.EncodeToString([]byte("route-allocate01"))
		claims["route_generation"] = 3
		claims["initiator_endpoint_id"] = "endpoint_left"
		claims["responder_endpoint_id"] = "endpoint_right"
		claims["attempt_generation"] = 2
		claims["network_generation"] = 4
		delete(claims, "machine_id")
		delete(claims, "installation_generation")
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "file_transfer_policy")
	})
	if err := verifier.AuthenticatePMTU(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierRejectsInvalidRelayCarrierSets(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", NodeID: "edge", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	var handle [16]byte
	copy(handle[:], []byte("stream-handle-01"))
	attachment := peerrelayhttp.Attachment{StreamHandle: handle, EndpointID: "endpoint_left", Role: peerrelay.RoleInitiator, Carrier: peerrelay.CarrierQUIC}
	for name, carriers := range map[string]any{
		"missing":   nil,
		"reversed":  []string{"relay_wss", "relay_quic"},
		"unknown":   []string{"relay_quic", "relay_http2"},
		"duplicate": []string{"relay_quic", "relay_quic"},
	} {
		t.Run(name, func(t *testing.T) {
			token := tokenFor(t, private, "key-1", func(claims map[string]any) {
				claims["sub"] = "intent_1"
				claims["credential_class"] = "peer_relay"
				claims["scope"] = []string{"peer:relay"}
				claims["intent_id"] = "intent_1"
				claims["attempt_generation"] = 2
				claims["network_generation"] = 4
				claims["route_allocation"] = base64.RawURLEncoding.EncodeToString([]byte("route-allocate01"))
				claims["route_generation"] = 3
				claims["initiator_endpoint_id"] = "endpoint_left"
				claims["responder_endpoint_id"] = "endpoint_right"
				claims["relay_byte_limit"] = 1 << 20
				if carriers == nil {
					delete(claims, "relay_carriers")
				} else {
					claims["relay_carriers"] = carriers
				}
			})
			if _, err := verifier.AuthenticateRelay(context.Background(), token, attachment); err == nil {
				t.Fatal("invalid relay carrier set accepted")
			}
		})
	}
}

func TestVerifierRejectsInvalidPeerSignalingBindings(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	base := func(claims map[string]any) {
		claims["sub"], claims["credential_class"], claims["scope"] = "left", "peer_signaling", []string{"peer:signal"}
		claims["intent_id"], claims["endpoint_id"], claims["peer_endpoint_id"] = "intent", "left", "right"
		claims["attempt_generation"], claims["network_generation"], claims["peer_role"] = 1, 1, "controlling"
	}
	for _, invalid := range []func(map[string]any){
		func(claims map[string]any) { claims["sub"] = "other" },
		func(claims map[string]any) { claims["peer_endpoint_id"] = "left" },
		func(claims map[string]any) { claims["attempt_generation"] = 0 },
		func(claims map[string]any) { claims["peer_role"] = "initiator" },
		func(claims map[string]any) { claims["scope"] = []string{"peer:signal", "connector:admit"} },
	} {
		token := tokenFor(t, private, "key-1", func(claims map[string]any) { base(claims); invalid(claims) })
		if _, err := verifier.Authenticate(context.Background(), token); err == nil {
			t.Fatal("invalid peer credential accepted")
		}
	}
}

func TestVerifierAcceptsExactHelperAccessCredential(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	token := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["aud"] = "paperboat-machine"
		claims["credential_class"] = "terminal_operation"
		claims["scope"] = []string{"terminal:operate"}
		claims["machine_id"] = "machine_1"
		claims["source_machine_id"] = "machine_source"
		claims["user_id"] = "usr_1"
		claims["cli_client_session_id"] = "acs_1"
		claims["session_id"] = "pts_1"
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "edge_node_id")
		delete(claims, "file_transfer_policy")
	})
	claims, err := verifier.VerifyHelperAccess(context.Background(), token)
	if err != nil || claims.JTI != "jti_admit_01" || claims.EnvironmentID != "env" || claims.MachineID != "machine_1" || claims.CredentialClass != "terminal_operation" {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	if _, err := verifier.VerifyHelperAccess(context.Background(), tokenFor(t, private, "key-1", nil)); err == nil {
		t.Fatal("connector credential accepted as helper access")
	}
	fileToken := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["aud"] = "paperboat-machine"
		claims["credential_class"] = "file_transfer"
		claims["scope"] = []string{"file:transfer"}
		claims["machine_id"] = "machine_1"
		claims["source_machine_id"] = "machine_source"
		claims["user_id"] = "usr_1"
		claims["cli_client_session_id"] = "acs_1"
		delete(claims, "session_id")
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "edge_node_id")
		delete(claims, "file_transfer_policy")
	})
	claims, err = verifier.VerifyHelperAccess(context.Background(), fileToken)
	if err != nil || claims.CredentialClass != "file_transfer" || len(claims.Scopes) != 1 || claims.Scopes[0] != "file:transfer" {
		t.Fatalf("file claims=%+v err=%v", claims, err)
	}
	missingTerminalSession := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["aud"] = "paperboat-machine"
		claims["credential_class"] = "terminal_operation"
		claims["scope"] = []string{"terminal:operate"}
		claims["machine_id"] = "machine_1"
		claims["user_id"] = "usr_1"
		claims["cli_client_session_id"] = "acs_1"
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "edge_node_id")
		delete(claims, "file_transfer_policy")
	})
	if _, err := verifier.VerifyHelperAccess(context.Background(), missingTerminalSession); err == nil {
		t.Fatal("terminal credential without session accepted")
	}
	wrongScope := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["aud"] = "paperboat-machine"
		claims["credential_class"] = "file_transfer"
		claims["scope"] = []string{"file:stage"}
		claims["machine_id"] = "machine_1"
		claims["user_id"] = "usr_1"
		claims["cli_client_session_id"] = "acs_1"
		claims["session_id"] = "pts_1"
		delete(claims, "connector_id")
		delete(claims, "connector_generation")
		delete(claims, "edge_pool")
		delete(claims, "edge_node_id")
		delete(claims, "file_transfer_policy")
	})
	if _, err := verifier.VerifyHelperAccess(context.Background(), wrongScope); err == nil {
		t.Fatal("retired file:stage scope accepted")
	}
}

func TestVerifierAcceptsBoundCodexCredentials(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }}
	for class, scopes := range map[string][]string{"codex_connect": {"codex:connect"}, "codex_manage": {"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}} {
		token := tokenFor(t, private, "key-1", func(claims map[string]any) {
			claims["aud"] = "paperboat-machine"
			claims["credential_class"] = class
			claims["scope"] = scopes
			claims["machine_id"] = "machine_1"
			claims["user_id"] = "usr_1"
			claims["cli_client_session_id"] = "cls_1"
			claims["session_id"] = "cdx_1"
			delete(claims, "file_transfer_policy")
		})
		if claims, err := verifier.VerifyHelperAccess(context.Background(), token); err != nil || claims.CredentialClass != class {
			t.Fatalf("%s claims=%+v err=%v", class, claims, err)
		}
	}
	missingSession := tokenFor(t, private, "key-1", func(claims map[string]any) {
		claims["aud"] = "paperboat-machine"
		claims["credential_class"] = "codex_connect"
		claims["scope"] = []string{"codex:connect"}
		claims["machine_id"] = "machine_1"
		claims["user_id"] = "usr_1"
		claims["cli_client_session_id"] = "cls_1"
		delete(claims, "session_id")
		delete(claims, "file_transfer_policy")
	})
	if _, err := verifier.VerifyHelperAccess(context.Background(), missingSession); err == nil {
		t.Fatal("Codex credential without session accepted")
	}
}

func TestVerifierRejectsMalformedWrongKeySignatureAndClaims(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }, ClockSkew: time.Minute}
	tokens := []string{"not-a-token", tokenFor(t, private, "unknown", nil), tokenFor(t, otherPrivate, "key-1", nil), tokenFor(t, private, "key-1", func(claims map[string]any) { claims["aud"] = "other" }), tokenFor(t, private, "key-1", func(claims map[string]any) { claims["exp"] = int64(999) }), tokenFor(t, private, "key-1", func(claims map[string]any) { claims["unknown"] = true })}
	for _, token := range tokens {
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}

func TestVerifierRejectsMissingOrInvalidFileTransferPolicy(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Now: func() time.Time { return time.Unix(1000, 0) }, ClockSkew: time.Minute}
	for _, mutate := range []func(map[string]any){
		func(claims map[string]any) { delete(claims, "file_transfer_policy") },
		func(claims map[string]any) { claims["file_transfer_policy"].(map[string]any)["max_file_bytes"] = 0 },
	} {
		if _, err := verifier.Verify(context.Background(), tokenFor(t, private, "key-1", mutate)); err == nil {
			t.Fatal("invalid file transfer policy accepted")
		}
	}
}

type revokedSource struct{}

func (revokedSource) Revoked(context.Context, admission.Claims) (bool, error) { return true, nil }

func TestVerifierPropagatesRevocationAndFailsClosedOnSourceError(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier := &Verifier{Issuer: "https://api.paperboat.test", Keys: StaticKeys{"key-1": public}, Revocations: revokedSource{}, Now: func() time.Time { return time.Unix(1000, 0) }}
	claims, err := verifier.Verify(context.Background(), tokenFor(t, private, "key-1", nil))
	if err != nil || !claims.Revoked {
		t.Fatalf("revocation = %+v, %v", claims, err)
	}
	verifier.Keys = failingKeys{}
	if _, err := verifier.Verify(context.Background(), tokenFor(t, private, "key-1", nil)); err == nil {
		t.Fatal("key source failure accepted")
	}
}

type failingKeys struct{}

func (failingKeys) Key(context.Context, string) (ed25519.PublicKey, error) {
	return nil, errors.New("unavailable")
}
