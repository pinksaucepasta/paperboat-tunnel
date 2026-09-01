package control

// Certificate distribution is an internal, authenticated control-plane
// exchange.  It is intentionally not part of the public API or route feed:
// certificate private keys are accepted only over the already authenticated
// edge-control TLS client and are handed directly to the in-memory tlscert
// registry.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

var (
	ErrCertificateDistributionInvalid = errors.New("invalid certificate distribution message")
	ErrCertificateDistributionAuth    = errors.New("certificate distribution message is not authenticated")
)

const (
	certificateDistributionMaximumMessages = 128
	certificateDistributionMaximumPages    = 4096
	certificateDistributionMaximumTotal    = 4096
	certificateDistributionMaximumBytes    = 16 << 20
	certificateDistributionMaximumLifetime = 10 * time.Minute
)

// CertificateDistributionClient pulls pending actions from the server and
// acknowledges each action after the local registry has completed it.  The
// client is safe to use from one worker and does not retain certificate bytes
// after a method returns.
type CertificateDistributionClient struct {
	client     *HTTPClient
	credential []byte
}

// HMACDistributionAuthenticator verifies the same canonical message proof
// as CertificateDistributionClient. Keeping verification at the receiver
// boundary means callers cannot accidentally install an unverified envelope
// merely because it arrived over a control HTTP client.
type HMACDistributionAuthenticator struct {
	credential []byte
}

func NewHMACDistributionAuthenticator(credential string) (HMACDistributionAuthenticator, error) {
	if len(credential) < 32 || strings.TrimSpace(credential) != credential || strings.ContainsAny(credential, "\r\n\x00") {
		return HMACDistributionAuthenticator{}, ErrCertificateDistributionInvalid
	}
	return HMACDistributionAuthenticator{credential: append([]byte(nil), credential...)}, nil
}

func (a HMACDistributionAuthenticator) Verify(_ context.Context, action string, envelope tlscert.DistributionEnvelope) error {
	if len(a.credential) == 0 || envelope.Action != action || envelope.CertificateID == "" || len(envelope.Proof) == 0 {
		return ErrCertificateDistributionAuth
	}
	wire := certificateDistributionWire{
		Version: 1, Action: envelope.Action, CertificateID: envelope.CertificateID,
		AccountID: envelope.Binding.AccountID, TunnelID: envelope.Binding.TunnelID,
		DomainID: envelope.Binding.DomainID, TargetKind: string(envelope.Binding.TargetKind), RouteID: envelope.Binding.RouteID,
		PreviewID: envelope.Binding.PreviewID, PreviewGeneration: envelope.Binding.PreviewGeneration, PreviewState: envelope.Binding.PreviewState, PreviewExpiresAt: envelope.Binding.PreviewExpiresAt,
		Hostname: envelope.Binding.Hostname, OnDemandLeaf: envelope.Binding.OnDemandLeaf,
		DomainGeneration: envelope.Binding.DomainGeneration, CertificateGeneration: envelope.Binding.CertificateGeneration,
		EdgeNodeID: envelope.Binding.EdgeNodeID, EdgeProcessEpoch: envelope.Binding.EdgeProcessEpoch,
		AssignmentGeneration: envelope.Binding.AssignmentGeneration,
		Fingerprint:          base64.RawURLEncoding.EncodeToString(envelope.Fingerprint[:]), Issuer: envelope.Bundle.Issuer,
		NotBefore: envelope.Bundle.NotBefore, CertificateExpiresAt: envelope.Bundle.NotAfter,
		ExpiresAt: envelope.ExpiresAt, IssuedAt: envelope.IssuedAt, Proof: string(envelope.Proof),
	}
	if envelope.Action == "stage" {
		wire.CertificatePEM = append([]byte(nil), envelope.Bundle.CertificatePEM...)
		wire.PrivateKeyPEM = append([]byte(nil), envelope.Bundle.PrivateKeyPEM...)
	}
	defer wipeCertificateDistributionWire(&wire)
	return verifyDistributionProof(wire, a.credential)
}

func NewCertificateDistributionClient(client *HTTPClient) (*CertificateDistributionClient, error) {
	if client == nil || len(client.credential) < 32 {
		return nil, ErrCertificateDistributionInvalid
	}
	return &CertificateDistributionClient{client: client, credential: append([]byte(nil), client.credential...)}, nil
}

// Close drops the private verifier copy held by the distribution client. The
// underlying HTTP client remains owned by the control plane and is not
// closed here.
func (c *CertificateDistributionClient) Close() error {
	if c == nil {
		return nil
	}
	clear(c.credential)
	c.credential = nil
	return nil
}

type certificateDistributionWire struct {
	Version               int       `json:"version"`
	Action                string    `json:"action"`
	CertificateID         string    `json:"certificate_id"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	DomainID              string    `json:"domain_id"`
	TargetKind            string    `json:"target_kind"`
	RouteID               string    `json:"route_id"`
	PreviewID             string    `json:"preview_id"`
	PreviewGeneration     uint64    `json:"preview_generation"`
	PreviewState          string    `json:"preview_state"`
	PreviewExpiresAt      time.Time `json:"preview_expires_at"`
	Hostname              string    `json:"hostname"`
	OnDemandLeaf          bool      `json:"on_demand_leaf"`
	DomainGeneration      uint64    `json:"domain_generation"`
	CertificateGeneration uint64    `json:"certificate_generation"`
	EdgeNodeID            string    `json:"edge_node_id"`
	EdgeProcessEpoch      string    `json:"edge_process_epoch"`
	AssignmentGeneration  uint64    `json:"assignment_generation"`
	Fingerprint           string    `json:"fingerprint"`
	Issuer                string    `json:"issuer"`
	NotBefore             time.Time `json:"not_before"`
	ExpiresAt             time.Time `json:"expires_at"`
	CertificateExpiresAt  time.Time `json:"certificate_expires_at"`
	CertificatePEM        []byte    `json:"certificate_pem"`
	PrivateKeyPEM         []byte    `json:"private_key_pem"`
	IssuedAt              time.Time `json:"issued_at"`
	Proof                 string    `json:"proof"`
}

type certificateDistributionAckWire struct {
	Version               int       `json:"version"`
	Action                string    `json:"action"`
	CertificateID         string    `json:"certificate_id"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	DomainID              string    `json:"domain_id"`
	TargetKind            string    `json:"target_kind"`
	RouteID               string    `json:"route_id"`
	PreviewID             string    `json:"preview_id"`
	PreviewGeneration     uint64    `json:"preview_generation"`
	PreviewState          string    `json:"preview_state"`
	PreviewExpiresAt      time.Time `json:"preview_expires_at"`
	Hostname              string    `json:"hostname"`
	DomainGeneration      uint64    `json:"domain_generation"`
	CertificateGeneration uint64    `json:"certificate_generation"`
	EdgeNodeID            string    `json:"edge_node_id"`
	EdgeProcessEpoch      string    `json:"edge_process_epoch"`
	AssignmentGeneration  uint64    `json:"assignment_generation"`
	Fingerprint           string    `json:"fingerprint"`
	Status                string    `json:"status"`
	Code                  string    `json:"code,omitempty"`
}

// Pull obtains a bounded, complete set of pending actions for exactly one
// edge process. The server may page a large set with a stable key cursor; an
// empty complete set is meaningful and does not erase local registry state.
func (c *CertificateDistributionClient) Pull(ctx context.Context, nodeID, processEpoch string) ([]tlscert.DistributionEnvelope, error) {
	if c == nil || c.client == nil || connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return nil, ErrCertificateDistributionInvalid
	}
	result := make([]tlscert.DistributionEnvelope, 0, certificateDistributionMaximumMessages)
	cursor := ""
	now := time.Now().UTC()
	for page := 0; page < certificateDistributionMaximumPages; page++ {
		var response struct {
			Version    int                           `json:"version"`
			Complete   bool                          `json:"complete"`
			NextCursor string                        `json:"next_cursor"`
			Messages   []certificateDistributionWire `json:"messages"`
		}
		if err := c.client.postNodeWithMaximumAndIdentity(ctx, CertificateDistributionPullPath, nodeID, processEpoch, struct {
			EdgeNodeID       string `json:"edge_node_id"`
			EdgeProcessEpoch string `json:"edge_process_epoch"`
			Limit            int    `json:"limit"`
			Cursor           string `json:"cursor,omitempty"`
		}{EdgeNodeID: nodeID, EdgeProcessEpoch: processEpoch, Limit: certificateDistributionMaximumMessages, Cursor: cursor}, &response, certificateDistributionMaximumBytes); err != nil {
			return nil, err
		}
		if response.Version != 1 || len(response.Messages) > certificateDistributionMaximumMessages || len(result)+len(response.Messages) > certificateDistributionMaximumTotal {
			wipeCertificateDistributionWires(response.Messages)
			return nil, ErrCertificateDistributionInvalid
		}
		if response.Complete {
			if response.NextCursor != "" {
				wipeCertificateDistributionWires(response.Messages)
				return nil, ErrCertificateDistributionInvalid
			}
		} else if response.NextCursor == "" || len(response.Messages) == 0 || response.NextCursor == cursor {
			wipeCertificateDistributionWires(response.Messages)
			return nil, ErrCertificateDistributionInvalid
		}
		for index := range response.Messages {
			message := &response.Messages[index]
			envelope, err := decodeCertificateDistribution(*message, nodeID, processEpoch, c.credential, now)
			wipeCertificateDistributionWire(message)
			if err != nil {
				wipeCertificateDistributionWires(response.Messages[index+1:])
				return nil, err
			}
			result = append(result, envelope)
		}
		if response.Complete {
			return result, nil
		}
		cursor = response.NextCursor
	}
	return nil, ErrCertificateDistributionInvalid
}

func (c *CertificateDistributionClient) Ack(ctx context.Context, envelope tlscert.DistributionEnvelope, status, code string) error {
	if c == nil || c.client == nil || status != "ready" && status != "active" && status != "retired" && status != "revoked" && status != "failed" || !certificateDistributionAckStatusMatchesAction(envelope.Action, status) {
		return ErrCertificateDistributionInvalid
	}
	if code != "" && (len(code) > 128 || strings.ContainsAny(code, "\r\n\x00")) || status == "failed" && code == "" || status != "failed" && code != "" {
		return ErrCertificateDistributionInvalid
	}
	if envelope.Action == "" || envelope.CertificateID == "" || envelope.Fingerprint == [sha256.Size]byte{} {
		return ErrCertificateDistributionInvalid
	}
	input := certificateDistributionAckWire{Version: 1, Action: envelope.Action, CertificateID: envelope.CertificateID, AccountID: envelope.Binding.AccountID, TunnelID: envelope.Binding.TunnelID, DomainID: envelope.Binding.DomainID, TargetKind: string(envelope.Binding.TargetKind), RouteID: envelope.Binding.RouteID, PreviewID: envelope.Binding.PreviewID, PreviewGeneration: envelope.Binding.PreviewGeneration, PreviewState: envelope.Binding.PreviewState, PreviewExpiresAt: envelope.Binding.PreviewExpiresAt, Hostname: envelope.Binding.Hostname, DomainGeneration: envelope.Binding.DomainGeneration, CertificateGeneration: envelope.Binding.CertificateGeneration, EdgeNodeID: envelope.Binding.EdgeNodeID, EdgeProcessEpoch: envelope.Binding.EdgeProcessEpoch, AssignmentGeneration: envelope.Binding.AssignmentGeneration, Fingerprint: base64.RawURLEncoding.EncodeToString(envelope.Fingerprint[:]), Status: status, Code: code}
	return c.client.postNodeWithMaximumAndIdentity(ctx, CertificateDistributionAckPath, envelope.Binding.EdgeNodeID, envelope.Binding.EdgeProcessEpoch, input, nil, 64<<10)
}

// RequestCertificate asks the authenticated control plane to issue and
// distribute the exact leaf for one SNI. The node and process identity are
// explicit inputs because this method is also used by the broker's production
// adapter; callers must not be able to request a sibling edge's certificate.
func (c *CertificateDistributionClient) RequestCertificate(ctx context.Context, nodeID, processEpoch, hostname string) error {
	if c == nil || c.client == nil || ctx == nil || connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return ErrCertificateDistributionInvalid
	}
	host, wildcard, err := tlscert.NormalizeHostname(hostname)
	if err != nil || wildcard || host != hostname {
		return ErrCertificateDistributionInvalid
	}
	return c.client.postNodeWithMaximumAndIdentity(ctx, CertificateDistributionRequestPath, nodeID, processEpoch, struct {
		Hostname string `json:"hostname"`
	}{Hostname: host}, nil, 8<<10)
}

// OnDemandCertificateRequester binds a distribution client to the current
// edge process. It is the only production adapter supplied to the certificate
// broker, so an SNI request cannot select arbitrary node or epoch headers.
type OnDemandCertificateRequester struct {
	client       *CertificateDistributionClient
	nodeID       string
	processEpoch string
}

func NewOnDemandCertificateRequester(client *CertificateDistributionClient, nodeID, processEpoch string) (*OnDemandCertificateRequester, error) {
	if client == nil || connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return nil, ErrCertificateDistributionInvalid
	}
	return &OnDemandCertificateRequester{client: client, nodeID: nodeID, processEpoch: processEpoch}, nil
}

func (r *OnDemandCertificateRequester) RequestCertificate(ctx context.Context, hostname string) error {
	if r == nil || r.client == nil {
		return ErrCertificateDistributionInvalid
	}
	return r.client.RequestCertificate(ctx, r.nodeID, r.processEpoch, hostname)
}

func certificateDistributionAckStatusMatchesAction(action, status string) bool {
	if status == "failed" {
		return true
	}
	switch action {
	case "stage":
		return status == "ready"
	case "activate":
		return status == "active"
	case "retire":
		return status == "retired"
	case "revoke":
		return status == "revoked"
	default:
		return false
	}
}

func decodeCertificateDistribution(message certificateDistributionWire, nodeID, processEpoch string, credential []byte, now time.Time) (tlscert.DistributionEnvelope, error) {
	if message.Version != 1 || message.EdgeNodeID != nodeID || message.EdgeProcessEpoch != processEpoch || message.Action != "stage" && message.Action != "activate" && message.Action != "retire" && message.Action != "revoke" || message.CertificateID == "" || message.AccountID == "" || message.DomainID == "" || message.Hostname == "" || message.DomainGeneration == 0 || message.CertificateGeneration == 0 || message.AssignmentGeneration == 0 || message.IssuedAt.IsZero() || message.ExpiresAt.IsZero() || !message.ExpiresAt.After(now) || message.ExpiresAt.Sub(message.IssuedAt) > certificateDistributionMaximumLifetime || message.CertificateExpiresAt.IsZero() || !message.CertificateExpiresAt.After(message.NotBefore) {
		return tlscert.DistributionEnvelope{}, ErrCertificateDistributionInvalid
	}
	if err := verifyDistributionProof(message, credential); err != nil {
		return tlscert.DistributionEnvelope{}, err
	}
	fingerprintBytes, err := base64.RawURLEncoding.Strict().DecodeString(message.Fingerprint)
	if err != nil || len(fingerprintBytes) != sha256.Size {
		return tlscert.DistributionEnvelope{}, ErrCertificateDistributionInvalid
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], fingerprintBytes)
	envelope := tlscert.DistributionEnvelope{Action: message.Action, CertificateID: message.CertificateID, Fingerprint: fingerprint, Binding: tlscert.Binding{AccountID: message.AccountID, TunnelID: message.TunnelID, DomainID: message.DomainID, TargetKind: tlscert.TargetKind(message.TargetKind), RouteID: message.RouteID, PreviewID: message.PreviewID, PreviewGeneration: message.PreviewGeneration, PreviewState: message.PreviewState, PreviewExpiresAt: message.PreviewExpiresAt, Hostname: message.Hostname, OnDemandLeaf: message.OnDemandLeaf, DomainGeneration: message.DomainGeneration, CertificateGeneration: message.CertificateGeneration, EdgeNodeID: message.EdgeNodeID, EdgeProcessEpoch: message.EdgeProcessEpoch, AssignmentGeneration: message.AssignmentGeneration}, Bundle: tlscert.Bundle{CertificatePEM: append([]byte(nil), message.CertificatePEM...), PrivateKeyPEM: append([]byte(nil), message.PrivateKeyPEM...), Issuer: message.Issuer, NotBefore: message.NotBefore, NotAfter: message.CertificateExpiresAt}, IssuedAt: message.IssuedAt, ExpiresAt: message.ExpiresAt, Proof: []byte(message.Proof)}
	if err := envelope.Binding.Validate(); err != nil || message.TargetKind == string(tlscert.TargetPreviewLease) && !message.PreviewExpiresAt.After(now) {
		return tlscert.DistributionEnvelope{}, ErrCertificateDistributionInvalid
	}
	if message.Action == "stage" && (len(envelope.Bundle.CertificatePEM) == 0 || len(envelope.Bundle.PrivateKeyPEM) == 0 || len(envelope.Bundle.CertificatePEM) > certificateDistributionMaximumBytes || len(envelope.Bundle.PrivateKeyPEM) > certificateDistributionMaximumBytes) {
		return tlscert.DistributionEnvelope{}, ErrCertificateDistributionInvalid
	}
	return envelope, nil
}

func verifyDistributionProof(message certificateDistributionWire, credential []byte) error {
	proof, err := base64.RawURLEncoding.Strict().DecodeString(message.Proof)
	if err != nil || len(proof) != sha256.Size || len(credential) < 32 {
		return ErrCertificateDistributionAuth
	}
	defer clear(proof)
	message.Proof = ""
	canonical, err := json.Marshal(message)
	if err != nil {
		return ErrCertificateDistributionAuth
	}
	defer clear(canonical)
	hash := hmac.New(sha256.New, credential)
	_, _ = hash.Write(canonical)
	if !hmac.Equal(proof, hash.Sum(nil)) {
		return ErrCertificateDistributionAuth
	}
	return nil
}

func wipeCertificateDistributionWire(message *certificateDistributionWire) {
	if message == nil {
		return
	}
	clear(message.CertificatePEM)
	clear(message.PrivateKeyPEM)
	message.CertificatePEM = nil
	message.PrivateKeyPEM = nil
}

func wipeCertificateDistributionWires(messages []certificateDistributionWire) {
	for index := range messages {
		wipeCertificateDistributionWire(&messages[index])
	}
}
