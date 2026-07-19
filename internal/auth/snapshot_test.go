package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

func makeJWKS(t *testing.T, entries map[string]ed25519.PublicKey) []byte {
	t.Helper()
	keys := make([]map[string]string, 0, len(entries))
	for id, key := range entries {
		keys = append(keys, map[string]string{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": id, "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	data, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSnapshotRotationAndRevocation(t *testing.T) {
	oldPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := NewSnapshot()
	if err := snapshot.ReplaceJWKS(makeJWKS(t, map[string]ed25519.PublicKey{"old": oldPublic, "new": newPublic})); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Key(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.ReplaceJWKS(makeJWKS(t, map[string]ed25519.PublicKey{"new": newPublic})); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Key(context.Background(), "old"); err == nil {
		t.Fatal("retired key retained")
	}
	revocations, _ := json.Marshal(RevocationDocument{JTIs: []string{"jti"}, Environments: []string{"other-env"}, Helpers: []RevokedHelperGeneration{{HelperID: "helper", Generation: 3}}, KeyIDs: []string{"retired"}})
	if err := snapshot.ReplaceRevocations(revocations); err != nil {
		t.Fatal(err)
	}
	for _, claims := range []admission.Claims{{JTI: "jti"}, {EnvironmentID: "other-env"}, {HelperID: "helper", ConnectorGeneration: 3}, {KeyID: "retired"}} {
		revoked, err := snapshot.Revoked(context.Background(), claims)
		if err != nil || !revoked {
			t.Fatalf("not revoked: %+v, %v", claims, err)
		}
	}
}

func TestSnapshotRejectsMalformedAndSupportsConcurrentReaders(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := NewSnapshot()
	for _, invalid := range [][]byte{nil, []byte(`{"keys":[]}`), []byte(`{"keys":[{"kty":"RSA"}]}`), []byte(`{"keys":[],"unknown":true}`)} {
		if err := snapshot.ReplaceJWKS(invalid); err == nil {
			t.Fatalf("invalid JWKS accepted: %s", invalid)
		}
	}
	data := makeJWKS(t, map[string]ed25519.PublicKey{"key": public})
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				_ = snapshot.ReplaceJWKS(data)
				_, _ = snapshot.Key(context.Background(), "key")
			}
		}()
	}
	group.Wait()
}
