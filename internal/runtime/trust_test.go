package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTrustStrictDocuments(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	jwks := filepath.Join(directory, "jwks.json")
	revocations := filepath.Join(directory, "revocations.json")
	usageKey := filepath.Join(directory, "usage.json")
	writeTrust(t, jwks, fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"connector","x":"%s"}]}`, base64.RawURLEncoding.EncodeToString(public)), 0644)
	writeTrust(t, revocations, `{"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`, 0644)
	writeTrust(t, usageKey, fmt.Sprintf(`{"key_id":"usage","edge_node_id":"edge-test","private_key":"%s"}`, base64.RawURLEncoding.EncodeToString(private)), 0600)
	trust, err := LoadTrust(jwks, revocations, usageKey)
	if err != nil {
		t.Fatal(err)
	}
	if trust.UsageKeyID != "usage" || trust.UsageEdgeNodeID != "edge-test" || len(trust.UsagePrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("trust = %+v", trust)
	}
	if got, err := trust.Snapshot.Key(context.Background(), "connector"); err != nil || !got.Equal(public) {
		t.Fatalf("key = %x, %v", got, err)
	}
}

func TestLoadTrustRejectsPublicPrivateKey(t *testing.T) {
	directory := t.TempDir()
	jwks := filepath.Join(directory, "jwks.json")
	revocations := filepath.Join(directory, "revocations.json")
	usageKey := filepath.Join(directory, "usage.json")
	writeTrust(t, jwks, `{"keys":[]}`, 0644)
	writeTrust(t, revocations, `{}`, 0644)
	writeTrust(t, usageKey, `{}`, 0644)
	if _, err := LoadTrust(jwks, revocations, usageKey); err == nil {
		t.Fatal("unsafe usage key accepted")
	}
}

func TestLoadTrustRequiresUsageKeyNodeBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	jwks := filepath.Join(directory, "jwks.json")
	revocations := filepath.Join(directory, "revocations.json")
	usageKey := filepath.Join(directory, "usage.json")
	writeTrust(t, jwks, fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"connector","x":"%s"}]}`, base64.RawURLEncoding.EncodeToString(public)), 0644)
	writeTrust(t, revocations, `{"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`, 0644)
	writeTrust(t, usageKey, fmt.Sprintf(`{"key_id":"usage","private_key":"%s"}`, base64.RawURLEncoding.EncodeToString(private)), 0600)
	if _, err := LoadTrust(jwks, revocations, usageKey); err == nil {
		t.Fatal("usage signing key without edge-node binding accepted")
	}
}

func TestLoadTrustAcceptsHexSeed(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	jwks := filepath.Join(directory, "jwks.json")
	revocations := filepath.Join(directory, "revocations.json")
	usageKey := filepath.Join(directory, "usage.json")
	writeTrust(t, jwks, fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"connector","x":"%s"}]}`, base64.RawURLEncoding.EncodeToString(public)), 0644)
	writeTrust(t, revocations, `{"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`, 0644)
	writeTrust(t, usageKey, `{"key_id":"usage","edge_node_id":"edge-test","private_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`, 0600)
	trust, err := LoadTrust(jwks, revocations, usageKey)
	if err != nil || len(trust.UsagePrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("trust = %+v, %v", trust, err)
	}
}

func TestLoadTrustRejectsDuplicateAndNonCanonicalUsageKey(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	directory := t.TempDir()
	jwks := filepath.Join(directory, "jwks.json")
	revocations := filepath.Join(directory, "revocations.json")
	usageKey := filepath.Join(directory, "usage.json")
	writeTrust(t, jwks, fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"connector","x":"%s"}]}`, base64.RawURLEncoding.EncodeToString(public)), 0644)
	writeTrust(t, revocations, `{"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`, 0644)
	encoded := base64.RawURLEncoding.EncodeToString(private)
	writeTrust(t, usageKey, fmt.Sprintf(`{"key_id":"usage","key_id":"other","edge_node_id":"edge-test","private_key":"%s"}`, encoded), 0600)
	if _, err := LoadTrust(jwks, revocations, usageKey); err == nil {
		t.Fatal("duplicate usage key field accepted")
	}
	writeTrust(t, usageKey, fmt.Sprintf(`{"key_id":"usage","edge_node_id":"edge-test","private_key":"%s="}`, encoded), 0600)
	if _, err := LoadTrust(jwks, revocations, usageKey); err == nil {
		t.Fatal("non-canonical usage private key accepted")
	}
}

func writeTrust(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}
