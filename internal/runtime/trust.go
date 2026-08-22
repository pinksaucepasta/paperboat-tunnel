package runtime

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/auth"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const maxTrustDocument = 1 << 20

type Trust struct {
	Snapshot        *auth.Snapshot
	UsageKeyID      string
	UsageEdgeNodeID string
	UsagePrivateKey ed25519.PrivateKey
}

func LoadTrust(jwksPath, revocationsPath, usageKeyPath string) (Trust, error) {
	jwks, err := readTrustFile(jwksPath, false)
	if err != nil {
		return Trust{}, fmt.Errorf("read JWKS: %w", err)
	}
	revocations, err := readTrustFile(revocationsPath, false)
	if err != nil {
		return Trust{}, fmt.Errorf("read revocations: %w", err)
	}
	keyDocument, err := readTrustFile(usageKeyPath, true)
	if err != nil {
		return Trust{}, fmt.Errorf("read usage key: %w", err)
	}
	snapshot := auth.NewSnapshot()
	if err := snapshot.ReplaceJWKS(jwks); err != nil {
		return Trust{}, fmt.Errorf("decode JWKS: %w", err)
	}
	if err := snapshot.ReplaceRevocations(revocations); err != nil {
		return Trust{}, fmt.Errorf("decode revocations: %w", err)
	}
	var key struct {
		KeyID      string `json:"key_id"`
		EdgeNodeID string `json:"edge_node_id"`
		PrivateKey string `json:"private_key"`
	}
	if err := strictjson.Decode(keyDocument, &key, 64); err != nil || key.KeyID == "" || len(key.KeyID) > 128 || key.EdgeNodeID == "" || len(key.EdgeNodeID) > 128 {
		return Trust{}, fmt.Errorf("decode usage key document: %w", ErrProcessInvalid)
	}
	private, err := base64.RawURLEncoding.DecodeString(key.PrivateKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(private) != key.PrivateKey || len(private) != ed25519.PrivateKeySize && len(private) != ed25519.SeedSize {
		private, err = hex.DecodeString(key.PrivateKey)
		if err == nil && hex.EncodeToString(private) != key.PrivateKey {
			err = ErrProcessInvalid
		}
	}
	if err != nil || len(private) != ed25519.PrivateKeySize && len(private) != ed25519.SeedSize {
		return Trust{}, fmt.Errorf("decode usage private key: %w", ErrProcessInvalid)
	}
	if len(private) == ed25519.SeedSize {
		private = ed25519.NewKeyFromSeed(private)
	}
	return Trust{Snapshot: snapshot, UsageKeyID: key.KeyID, UsageEdgeNodeID: key.EdgeNodeID, UsagePrivateKey: ed25519.PrivateKey(append([]byte(nil), private...))}, nil
}

func readTrustFile(path string, ownerOnly bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTrustDocument || ownerOnly && info.Mode().Perm()&0077 != 0 {
		return nil, ErrProcessInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > maxTrustDocument {
		return nil, ErrProcessInvalid
	}
	return data, nil
}
