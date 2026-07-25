package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

const maxCredentialBytes = 8192

type KeySource interface {
	Key(context.Context, string) (ed25519.PublicKey, error)
}
type Revocations interface {
	Revoked(context.Context, admission.Claims) (bool, error)
}

type Verifier struct {
	Issuer      string
	Keys        KeySource
	Revocations Revocations
	Now         func() time.Time
	ClockSkew   time.Duration
}

type header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}
type claims struct {
	Issuer              string   `json:"iss"`
	Audience            string   `json:"aud"`
	Subject             string   `json:"sub"`
	JTI                 string   `json:"jti"`
	IssuedAt            int64    `json:"iat"`
	Expires             int64    `json:"exp"`
	Scope               []string `json:"scope"`
	CredentialClass     string   `json:"credential_class"`
	EnvironmentID       string   `json:"environment_id"`
	HelperID            string   `json:"helper_id"`
	ConnectorGeneration uint64   `json:"connector_generation"`
	EdgePool            string   `json:"edge_pool"`
	EdgeNodeID          string   `json:"edge_node_id"`
	UserID              string   `json:"user_id"`
	CLIClientSessionID  string   `json:"cli_client_session_id"`
	SessionID           string   `json:"session_id"`
}

// VerifyHelperAccess verifies the signed credential carried by public helper
// runtime and upload requests. The helper still enforces the complete operation
// policy; the edge verifies enough binding to terminate revoked streams.
func (v *Verifier) VerifyHelperAccess(ctx context.Context, token string) (admission.Claims, error) {
	if v == nil || v.Keys == nil || v.Issuer == "" || len(token) == 0 || len(token) > maxCredentialBytes || v.ClockSkew < 0 || v.ClockSkew > time.Minute {
		return admission.Claims{}, invalid()
	}
	parsedHeader, parsed, err := v.verifySigned(ctx, token)
	if err != nil {
		return admission.Claims{}, err
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	wantScope := ""
	switch parsed.CredentialClass {
	case "terminal_operation":
		wantScope = "terminal:operate"
	case "image_stage":
		wantScope = "file:stage"
	default:
		return admission.Claims{}, invalid()
	}
	if parsed.Issuer != v.Issuer || parsed.Audience != "paperboat-helper" || parsed.Subject == "" || parsed.JTI == "" || len(parsed.Scope) != 1 || parsed.Scope[0] != wantScope || parsed.EnvironmentID == "" || parsed.UserID == "" || parsed.CLIClientSessionID == "" || parsed.SessionID == "" || parsed.Expires <= parsed.IssuedAt || parsed.Expires-parsed.IssuedAt > 300 || time.Unix(parsed.IssuedAt, 0).After(now.Add(v.ClockSkew)) || !time.Unix(parsed.Expires, 0).After(now) {
		return admission.Claims{}, invalid()
	}
	result := admission.Claims{KeyID: parsedHeader.KeyID, Issuer: parsed.Issuer, Audience: parsed.Audience, JTI: parsed.JTI, CredentialClass: parsed.CredentialClass, Scopes: append([]string(nil), parsed.Scope...), EnvironmentID: parsed.EnvironmentID, HelperID: parsed.HelperID, ConnectorGeneration: parsed.ConnectorGeneration, ExpiresAt: time.Unix(parsed.Expires, 0).UTC()}
	if v.Revocations != nil {
		revoked, err := v.Revocations.Revoked(ctx, result)
		if err != nil {
			return admission.Claims{}, edgeerrors.New(edgeerrors.CodeCredentialInvalid, "credential revocation state is unavailable", "retry after revocation synchronization")
		}
		result.Revoked = revoked
	}
	return result, nil
}

func (v *Verifier) verifySigned(ctx context.Context, token string) (header, claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return header{}, claims{}, invalid()
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return header{}, claims{}, invalid()
	}
	var parsedHeader header
	if strictJSON(headerBytes, &parsedHeader) != nil || parsedHeader.Algorithm != "EdDSA" || parsedHeader.Type != "paperboat-credential+jwt" || parsedHeader.KeyID == "" || len(parsedHeader.KeyID) > 128 {
		return header{}, claims{}, invalid()
	}
	key, err := v.Keys.Key(ctx, parsedHeader.KeyID)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return header{}, claims{}, edgeerrors.New(edgeerrors.CodeCredentialInvalid, "credential signing key is unavailable", "retry after key synchronization")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return header{}, claims{}, invalid()
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return header{}, claims{}, invalid()
	}
	var parsed claims
	if strictJSON(payload, &parsed) != nil {
		return header{}, claims{}, invalid()
	}
	return parsedHeader, parsed, nil
}

func (v *Verifier) Verify(ctx context.Context, token string) (admission.Claims, error) {
	if v == nil || v.Keys == nil || v.Issuer == "" || len(token) == 0 || len(token) > maxCredentialBytes || v.ClockSkew < 0 || v.ClockSkew > time.Minute {
		return admission.Claims{}, invalid()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return admission.Claims{}, invalid()
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return admission.Claims{}, invalid()
	}
	var parsedHeader header
	if strictJSON(headerBytes, &parsedHeader) != nil || parsedHeader.Algorithm != "EdDSA" || parsedHeader.Type != "paperboat-credential+jwt" || parsedHeader.KeyID == "" || len(parsedHeader.KeyID) > 128 {
		return admission.Claims{}, invalid()
	}
	key, err := v.Keys.Key(ctx, parsedHeader.KeyID)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return admission.Claims{}, edgeerrors.New(edgeerrors.CodeCredentialInvalid, "credential signing key is unavailable", "retry after key synchronization")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return admission.Claims{}, invalid()
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return admission.Claims{}, invalid()
	}
	var parsed claims
	if strictJSON(payload, &parsed) != nil {
		return admission.Claims{}, invalid()
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if parsed.Issuer != v.Issuer || parsed.Audience != "paperboat-edge" || parsed.Subject == "" || parsed.JTI == "" || parsed.CredentialClass != "connector_admission" || len(parsed.Scope) != 1 || parsed.Scope[0] != "connector:admit" || parsed.EnvironmentID == "" || parsed.HelperID == "" || parsed.ConnectorGeneration == 0 || parsed.EdgePool == "" || parsed.EdgeNodeID == "" || parsed.Expires <= parsed.IssuedAt || parsed.Expires-parsed.IssuedAt > 300 || time.Unix(parsed.IssuedAt, 0).After(now.Add(v.ClockSkew)) || !time.Unix(parsed.Expires, 0).After(now) {
		return admission.Claims{}, invalid()
	}
	result := admission.Claims{KeyID: parsedHeader.KeyID, Issuer: parsed.Issuer, Audience: parsed.Audience, JTI: parsed.JTI, CredentialClass: parsed.CredentialClass, Scopes: append([]string(nil), parsed.Scope...), EnvironmentID: parsed.EnvironmentID, HelperID: parsed.HelperID, ConnectorGeneration: parsed.ConnectorGeneration, EdgePool: parsed.EdgePool, EdgeNodeID: parsed.EdgeNodeID, ExpiresAt: time.Unix(parsed.Expires, 0).UTC()}
	if v.Revocations != nil {
		revoked, err := v.Revocations.Revoked(ctx, result)
		if err != nil {
			return admission.Claims{}, edgeerrors.New(edgeerrors.CodeCredentialInvalid, "credential revocation state is unavailable", "retry after revocation synchronization")
		}
		if revoked {
			result.Revoked = true
		}
	}
	return result, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func invalid() error {
	return edgeerrors.New(edgeerrors.CodeCredentialInvalid, "credential is invalid", "request a fresh admission")
}

type StaticKeys map[string]ed25519.PublicKey

func (keys StaticKeys) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	key, ok := keys[keyID]
	if !ok {
		return nil, errors.New("unknown key")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}
