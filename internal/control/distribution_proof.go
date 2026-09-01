package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

const (
	CertificateDistributionPullPath    = "/v1/edge/certificates/distributions/pull"
	CertificateDistributionAckPath     = "/v1/edge/certificates/distributions/ack"
	CertificateDistributionRequestPath = "/v1/edge/certificates/distributions/request"
	distributionProofTimestampHeader   = "X-Paperboat-Edge-Proof-Issued-At"
	distributionProofNonceHeader       = "X-Paperboat-Edge-Proof-Nonce"
	distributionProofSignatureHeader   = "X-Paperboat-Edge-Proof"
	distributionProofNonceBytes        = 24
)

var ErrDistributionProofInvalid = errors.New("invalid edge distribution proof")

// DistributionRequestProof is the non-secret header material emitted by an
// edge process. The private key is retained only by the signer and never
// crosses the control HTTP boundary.
type DistributionRequestProof struct {
	IssuedAt  time.Time
	Nonce     string
	Signature string
}

type DistributionRequestSigner interface {
	SignDistributionRequest(context.Context, string, string, []byte) (DistributionRequestProof, error)
}

type DistributionProofSignerConfig struct {
	PrivateKey   ed25519.PrivateKey
	NodeID       string
	ProcessEpoch string
	Now          func() time.Time
	Nonce        func() ([]byte, error)
}

// Ed25519DistributionRequestSigner binds every node-scoped distribution
// request to the exact method, path, body digest, node, process epoch,
// timestamp, and single-use nonce. The server resolves the public key from
// the current registered process, so a shared bearer cannot impersonate an
// adjacent edge.
type Ed25519DistributionRequestSigner struct {
	privateKey   ed25519.PrivateKey
	nodeID       string
	processEpoch string
	now          func() time.Time
	nonce        func() ([]byte, error)
}

func NewEd25519DistributionRequestSigner(config DistributionProofSignerConfig) (*Ed25519DistributionRequestSigner, error) {
	if len(config.PrivateKey) != ed25519.PrivateKeySize || connectorprotocol.ValidateIdentifier(config.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil {
		return nil, ErrDistributionProofInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Nonce == nil {
		config.Nonce = func() ([]byte, error) {
			value := make([]byte, distributionProofNonceBytes)
			if _, err := io.ReadFull(rand.Reader, value); err != nil {
				return nil, err
			}
			return value, nil
		}
	}
	key := append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &Ed25519DistributionRequestSigner{privateKey: key, nodeID: config.NodeID, processEpoch: config.ProcessEpoch, now: config.Now, nonce: config.Nonce}, nil
}

func (s *Ed25519DistributionRequestSigner) SignDistributionRequest(ctx context.Context, method, path string, body []byte) (DistributionRequestProof, error) {
	if s == nil || ctx == nil || method != "POST" || path != CertificateDistributionPullPath && path != CertificateDistributionAckPath && path != CertificateDistributionRequestPath {
		return DistributionRequestProof{}, ErrDistributionProofInvalid
	}
	select {
	case <-ctx.Done():
		return DistributionRequestProof{}, ctx.Err()
	default:
	}
	issuedAt := s.now().UTC()
	if issuedAt.IsZero() {
		return DistributionRequestProof{}, ErrDistributionProofInvalid
	}
	nonceBytes, err := s.nonce()
	if err != nil || len(nonceBytes) != distributionProofNonceBytes {
		return DistributionRequestProof{}, ErrDistributionProofInvalid
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	digest := sha256.Sum256(body)
	transcript := distributionProofTranscript(method, path, s.nodeID, s.processEpoch, issuedAt, nonce, hex.EncodeToString(digest[:]))
	signature := ed25519.Sign(s.privateKey, []byte(transcript))
	return DistributionRequestProof{IssuedAt: issuedAt, Nonce: nonce, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func distributionProofTranscript(method, path, nodeID, processEpoch string, issuedAt time.Time, nonce, bodyDigest string) string {
	return strings.Join([]string{
		"paperboat-edge-distribution-proof-v1",
		method,
		path,
		nodeID,
		processEpoch,
		issuedAt.UTC().Format(time.RFC3339Nano),
		nonce,
		bodyDigest,
	}, "\n")
}

func distributionProofHeaders(proof DistributionRequestProof) (map[string]string, error) {
	if proof.IssuedAt.IsZero() || len(proof.Nonce) == 0 || len(proof.Nonce) > 128 || len(proof.Signature) == 0 || len(proof.Signature) > 256 {
		return nil, ErrDistributionProofInvalid
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(proof.Nonce); err != nil {
		return nil, ErrDistributionProofInvalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(proof.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrDistributionProofInvalid
	}
	return map[string]string{
		distributionProofTimestampHeader: proof.IssuedAt.UTC().Format(time.RFC3339Nano),
		distributionProofNonceHeader:     proof.Nonce,
		distributionProofSignatureHeader: proof.Signature,
	}, nil
}
