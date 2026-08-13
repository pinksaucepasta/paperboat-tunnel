package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func FuzzReplaceJWKS(f *testing.F) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(makeJWKS(f, map[string]ed25519.PublicKey{"key": public}))
	f.Add([]byte(nil))
	f.Add([]byte(`{"keys":[],"keys":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		snapshot := NewSnapshot()
		if err := snapshot.ReplaceJWKS(data); err != nil {
			return
		}
		if len(snapshot.keys) == 0 || len(snapshot.keys) > 128 {
			t.Fatalf("accepted key count=%d", len(snapshot.keys))
		}
		for id, key := range snapshot.keys {
			if id == "" || len(id) > 128 || len(key) != ed25519.PublicKeySize {
				t.Fatalf("accepted invalid key id=%q length=%d", id, len(key))
			}
		}
	})
}

func FuzzVerifyCredential(f *testing.F) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	valid := tokenFor(f, private, "key-1", nil)
	f.Add(valid)
	f.Add("")
	f.Add(strings.Repeat("x", maxCredentialBytes+1))
	verifier := &Verifier{
		Issuer:    "https://api.paperboat.test",
		Keys:      StaticKeys{"key-1": public},
		Now:       func() time.Time { return time.Unix(1000, 0) },
		ClockSkew: time.Minute,
	}

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := verifier.Verify(context.Background(), token)
		if err != nil {
			return
		}
		if claims.KeyID != "key-1" || claims.Issuer != verifier.Issuer || claims.Audience != "paperboat-edge" || claims.JTI == "" || claims.CredentialClass != "connector_admission" || claims.EnvironmentID == "" || claims.MachineID == "" || claims.ConnectorGeneration == 0 || claims.ExpiresAt.IsZero() {
			t.Fatalf("accepted credential escaped binding: %+v", claims)
		}
	})
}

func FuzzReplaceRevocations(f *testing.F) {
	valid, err := json.Marshal(RevocationDocument{
		JTIs:         []string{"jti"},
		Environments: []string{"environment"},
		Connectors:   []RevokedConnectorGeneration{{MachineID: "machine", ConnectorID: "connector", Generation: 1}},
		KeyIDs:       []string{"key"},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte(`{"jtis":[],"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		snapshot := NewSnapshot()
		if err := snapshot.ReplaceRevocations(data); err != nil {
			return
		}
		count := len(snapshot.revokedJTI) + len(snapshot.revokedEnvironment) + len(snapshot.revokedConnectorGeneration) + len(snapshot.revokedKey)
		if count > 10000 {
			t.Fatalf("accepted revocation count=%d", count)
		}
		for value := range snapshot.revokedJTI {
			if value == "" {
				t.Fatal("accepted empty JTI")
			}
		}
		for value := range snapshot.revokedEnvironment {
			if value == "" {
				t.Fatal("accepted empty environment")
			}
		}
		for value := range snapshot.revokedKey {
			if value == "" {
				t.Fatal("accepted empty key ID")
			}
		}
		for value := range snapshot.revokedConnectorGeneration {
			if value.Machine == "" || value.Connector == "" || value.Generation == 0 {
				t.Fatal("accepted invalid connector revocation")
			}
		}
	})
}
