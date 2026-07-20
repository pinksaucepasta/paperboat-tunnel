package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

const maxSnapshotBytes = 1 << 20

var ErrSnapshotInvalid = errors.New("credential trust snapshot is invalid")

type Snapshot struct {
	mu                                         sync.RWMutex
	keys                                       map[string]ed25519.PublicKey
	revokedJTI, revokedEnvironment, revokedKey map[string]struct{}
	revokedHelperGeneration                    map[helperGeneration]struct{}
	revocationMaxAge                           time.Duration
	revocationUpdatedAt                        time.Time
	now                                        func() time.Time
}
type helperGeneration struct {
	Helper     string
	Generation uint64
}

func NewSnapshot() *Snapshot {
	return &Snapshot{keys: map[string]ed25519.PublicKey{}, revokedJTI: map[string]struct{}{}, revokedEnvironment: map[string]struct{}{}, revokedKey: map[string]struct{}{}, revokedHelperGeneration: map[helperGeneration]struct{}{}, now: time.Now}
}

func (s *Snapshot) ConfigureRevocationFreshness(maxAge time.Duration, now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revocationMaxAge = maxAge
	if now != nil {
		s.now = now
	}
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}
type jwk struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
}

func (s *Snapshot) ReplaceJWKS(data []byte) error {
	if len(data) == 0 || len(data) > maxSnapshotBytes {
		return ErrSnapshotInvalid
	}
	var document jwksDocument
	if strictSnapshotJSON(data, &document) != nil || len(document.Keys) == 0 || len(document.Keys) > 128 {
		return ErrSnapshotInvalid
	}
	next := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.KeyType != "OKP" || item.Curve != "Ed25519" || item.Use != "sig" || item.Algorithm != "EdDSA" || item.KeyID == "" || len(item.KeyID) > 128 {
			return ErrSnapshotInvalid
		}
		raw, err := base64.RawURLEncoding.DecodeString(item.X)
		if err != nil || len(raw) != ed25519.PublicKeySize || next[item.KeyID] != nil {
			return ErrSnapshotInvalid
		}
		next[item.KeyID] = append(ed25519.PublicKey(nil), raw...)
	}
	s.mu.Lock()
	s.keys = next
	s.mu.Unlock()
	return nil
}
func (s *Snapshot) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := s.keys[keyID]
	if key == nil {
		return nil, ErrSnapshotInvalid
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

type RevocationDocument struct {
	JTIs         []string                  `json:"jtis"`
	Environments []string                  `json:"environments"`
	Helpers      []RevokedHelperGeneration `json:"helper_generations"`
	KeyIDs       []string                  `json:"key_ids"`
}
type RevokedHelperGeneration struct {
	HelperID   string `json:"helper_id"`
	Generation uint64 `json:"connector_generation"`
}

func (s *Snapshot) ReplaceRevocations(data []byte) error {
	if len(data) == 0 || len(data) > maxSnapshotBytes {
		return ErrSnapshotInvalid
	}
	var document RevocationDocument
	if strictSnapshotJSON(data, &document) != nil || len(document.JTIs)+len(document.Environments)+len(document.Helpers)+len(document.KeyIDs) > 10000 {
		return ErrSnapshotInvalid
	}
	jtis, environments, helpers, keys := map[string]struct{}{}, map[string]struct{}{}, map[helperGeneration]struct{}{}, map[string]struct{}{}
	for _, value := range document.JTIs {
		if value == "" {
			return ErrSnapshotInvalid
		}
		jtis[value] = struct{}{}
	}
	for _, value := range document.Environments {
		if value == "" {
			return ErrSnapshotInvalid
		}
		environments[value] = struct{}{}
	}
	for _, value := range document.Helpers {
		if value.HelperID == "" || value.Generation == 0 {
			return ErrSnapshotInvalid
		}
		helpers[helperGeneration{value.HelperID, value.Generation}] = struct{}{}
	}
	for _, value := range document.KeyIDs {
		if value == "" {
			return ErrSnapshotInvalid
		}
		keys[value] = struct{}{}
	}
	s.mu.Lock()
	s.revokedJTI, s.revokedEnvironment, s.revokedHelperGeneration, s.revokedKey = jtis, environments, helpers, keys
	clock := s.now
	if clock == nil {
		clock = time.Now
	}
	s.revocationUpdatedAt = clock()
	s.mu.Unlock()
	return nil
}
func (s *Snapshot) Revoked(_ context.Context, claims admission.Claims) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revocationMaxAge > 0 && (s.revocationUpdatedAt.IsZero() || s.now().Sub(s.revocationUpdatedAt) > s.revocationMaxAge) {
		return false, ErrSnapshotInvalid
	}
	_, a := s.revokedJTI[claims.JTI]
	_, b := s.revokedEnvironment[claims.EnvironmentID]
	_, c := s.revokedHelperGeneration[helperGeneration{claims.HelperID, claims.ConnectorGeneration}]
	_, d := s.revokedKey[claims.KeyID]
	return a || b || c || d, nil
}
func strictSnapshotJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrSnapshotInvalid
	}
	return nil
}
