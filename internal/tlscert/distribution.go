package tlscert

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

var (
	ErrDistributionInvalid = errors.New("invalid TLS certificate distribution")
	ErrDistributionAuth    = errors.New("TLS certificate distribution is not authenticated")
)

// DistributionEnvelope is an in-memory server-to-edge message. It must be
// transported over the already authenticated control channel; it is not a
// JSON/API/audit type. Bundle bytes are released by Receiver.Close and never
// copied into a durable edge state file.
type DistributionEnvelope struct {
	Action        string
	CertificateID string
	Fingerprint   [sha256.Size]byte
	Binding       Binding
	Bundle        Bundle
	Proof         []byte
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// WipeDistributionEnvelope clears the only fields that can contain private
// key or certificate material. Callers owning a decoded envelope should call
// this after the local registry has copied what it needs, including on error.
// The registry intentionally keeps its own parsed in-memory tls.Certificate;
// this helper does not mutate that registry state.
func WipeDistributionEnvelope(envelope *DistributionEnvelope) {
	if envelope == nil {
		return
	}
	clear(envelope.Bundle.CertificatePEM)
	clear(envelope.Bundle.PrivateKeyPEM)
	clear(envelope.Proof)
	envelope.Bundle.CertificatePEM = nil
	envelope.Bundle.PrivateKeyPEM = nil
	envelope.Proof = nil
}

func clear(values []byte) {
	for index := range values {
		values[index] = 0
	}
}

// DistributionAuthenticator binds the message to the authenticated server
// control session, certificate action, and complete edge target. The proof
// implementation is responsible for checking the server key and expiry; the
// receiver still checks all local identity and generation fields.
type DistributionAuthenticator interface {
	Verify(context.Context, string, DistributionEnvelope) error
}

type ReceiverConfig struct {
	Registry       *Registry
	NodeID         string
	ProcessEpoch   string
	Authenticator  DistributionAuthenticator
	Now            func() time.Time
	MaximumMessage int
}

type DistributionReceiver struct {
	registry       *Registry
	nodeID         string
	processEpoch   string
	authenticator  DistributionAuthenticator
	now            func() time.Time
	maximumMessage int
}

func NewDistributionReceiver(config ReceiverConfig) (*DistributionReceiver, error) {
	if config.Registry == nil || !validIdentifier(config.NodeID) || !validEpoch(config.ProcessEpoch) || config.Authenticator == nil {
		return nil, fmt.Errorf("%w: receiver identity and authentication are required", ErrDistributionInvalid)
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maximum := config.MaximumMessage
	if maximum <= 0 || maximum > 32<<20 {
		maximum = 16 << 20
	}
	return &DistributionReceiver{registry: config.Registry, nodeID: config.NodeID, processEpoch: config.ProcessEpoch, authenticator: config.Authenticator, now: now, maximumMessage: maximum}, nil
}

func (r *DistributionReceiver) Stage(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "stage", envelope); err != nil {
		return err
	}
	fingerprint := distributionFingerprint(envelope.Fingerprint)
	if err := r.registry.stage(ctx, envelope.Binding, envelope.Bundle, fingerprint); err != nil {
		return err
	}
	return nil
}

// StageAndReady authenticates the single server-issued stage action once and
// then performs the local stage and readiness transitions. The distribution
// protocol deliberately carries a stage envelope whose successful result is
// ready; there is no separate wire "ready" action to authenticate. Keeping the
// authentication here prevents callers from accidentally authenticating the
// same envelope as a different action while retaining an explicit Stage method
// for transports that separate those transitions.
func (r *DistributionReceiver) StageAndReady(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "stage", envelope); err != nil {
		return err
	}
	fingerprint := distributionFingerprint(envelope.Fingerprint)
	if err := r.registry.stage(ctx, envelope.Binding, envelope.Bundle, fingerprint); err != nil {
		return err
	}
	return r.registry.markReady(ctx, envelope.Binding, fingerprint)
}

func (r *DistributionReceiver) Ready(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "ready", envelope); err != nil {
		return err
	}
	return r.registry.markReady(ctx, envelope.Binding, distributionFingerprint(envelope.Fingerprint))
}

func (r *DistributionReceiver) Activate(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "activate", envelope); err != nil {
		return err
	}
	return r.registry.activate(ctx, envelope.Binding, distributionFingerprint(envelope.Fingerprint))
}

func (r *DistributionReceiver) Retire(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "retire", envelope); err != nil {
		return err
	}
	return r.registry.retire(ctx, envelope.Binding, distributionFingerprint(envelope.Fingerprint))
}

func (r *DistributionReceiver) Revoke(ctx context.Context, envelope DistributionEnvelope) error {
	if err := r.authenticate(ctx, "revoke", envelope); err != nil {
		return err
	}
	return r.registry.revoke(ctx, envelope.Binding, distributionFingerprint(envelope.Fingerprint))
}

func distributionFingerprint(value [sha256.Size]byte) *[sha256.Size]byte {
	if value == [sha256.Size]byte{} {
		// Older in-memory callers did not carry the non-secret fingerprint;
		// authenticated wire messages do. Keep direct receiver tests and
		// idempotent local replays usable while enforcing it whenever present.
		return nil
	}
	return &value
}

func (r *DistributionReceiver) Close() error {
	if r == nil || r.registry == nil {
		return nil
	}
	return r.registry.Close()
}

func (r *DistributionReceiver) authenticate(ctx context.Context, action string, envelope DistributionEnvelope) error {
	if r == nil || r.registry == nil || r.authenticator == nil || !validIdentifier(envelope.CertificateID) {
		return ErrDistributionInvalid
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if envelope.Binding.EdgeNodeID != r.nodeID || envelope.Binding.EdgeProcessEpoch != r.processEpoch || envelope.Binding.CertificateGeneration == 0 || envelope.Binding.AssignmentGeneration == 0 || envelope.Binding.DomainGeneration == 0 {
		return fmt.Errorf("%w: edge target binding is stale", ErrGenerationConflict)
	}
	if len(envelope.Bundle.CertificatePEM) > r.maximumMessage || len(envelope.Bundle.PrivateKeyPEM) > r.maximumMessage || len(envelope.Proof) > 64<<10 || len(envelope.Proof) == 0 || envelope.ExpiresAt.IsZero() || !envelope.ExpiresAt.After(r.now().UTC()) || envelope.IssuedAt.IsZero() || envelope.ExpiresAt.Sub(envelope.IssuedAt) > 10*time.Minute {
		return ErrDistributionInvalid
	}
	if err := r.authenticator.Verify(ctx, action, envelope); err != nil {
		if errors.Is(err, ErrDistributionAuth) {
			return err
		}
		return ErrDistributionAuth
	}
	return nil
}
