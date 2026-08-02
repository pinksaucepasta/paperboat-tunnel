package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

func tokenFor(t *testing.T, private ed25519.PrivateKey, keyID string, mutate func(map[string]any)) string {
	t.Helper()
	now := time.Unix(1000, 0)
	header := map[string]any{"alg": "EdDSA", "kid": keyID, "typ": "paperboat-credential+jwt"}
	claims := map[string]any{"iss": "https://api.paperboat.test", "aud": "paperboat-edge", "sub": "machine", "jti": "jti_admit_01", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "scope": []string{"connector:admit"}, "credential_class": "connector_admission", "environment_id": "env", "machine_id": "machine", "installation_generation": 1, "connector_id": "runtime", "connector_generation": 3, "edge_pool": "default", "edge_node_id": "edge", "file_transfer_policy": map[string]any{"revision": "file-transfer-v1", "max_file_bytes": 50 << 20, "max_batch_files": 10, "max_batch_bytes": 500 << 20, "max_concurrent_transfers": 2, "retention_seconds": 604800, "delivery_timeout_seconds": 600, "max_pending_spool_bytes": 1 << 30}}
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
