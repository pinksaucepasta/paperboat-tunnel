package connectorprotocol

import (
	"context"
	"errors"
	"time"
)

// Runtime is the tunnel-owned boundary for control-plane configuration and
// stream draining. It intentionally exposes staging and lifecycle hooks, not
// frp/Caddy internals. Stage methods must not alter active traffic until the
// returned PreparedConfig is activated.
type Runtime interface {
	StageSnapshot(context.Context, Snapshot) (PreparedConfig, error)
	StageDelta(context.Context, Delta) (PreparedConfig, error)
	StopNewStreams(context.Context) error
	ActiveStreams(context.Context) (uint32, error)
	ForceClose(context.Context) error
}

// RotationRuntime is the tunnel-side credential lifecycle boundary. The
// implementation owns key custody and replacement-session startup; the wire
// adapter only passes signed metadata and write-only credential references.
// Returning an error is a real rejection, never an implicit network success.
type RotationRuntime interface {
	ProveCredentialRotation(context.Context, CredentialRotationChallenge) (CredentialRotationProof, error)
	InstallCredentialRotation(context.Context, CredentialRotationInstall) error
	RevokeCredentialRotation(context.Context, CredentialRotationRevoke) error
}

type runtimeApplier struct{ runtime Runtime }

func (a runtimeApplier) PrepareSnapshot(ctx context.Context, snapshot Snapshot) (PreparedConfig, error) {
	if a.runtime == nil {
		return nil, ErrInvalidInput
	}
	return a.runtime.StageSnapshot(ctx, snapshot)
}

func (a runtimeApplier) PrepareDelta(ctx context.Context, delta Delta) (PreparedConfig, error) {
	if a.runtime == nil {
		return nil, ErrInvalidInput
	}
	return a.runtime.StageDelta(ctx, delta)
}

type runtimeDrainer struct{ runtime Runtime }

func (d runtimeDrainer) StopNewStreams(ctx context.Context) error {
	if d.runtime == nil {
		return ErrInvalidInput
	}
	return d.runtime.StopNewStreams(ctx)
}

func (d runtimeDrainer) ActiveStreams(ctx context.Context) (uint32, error) {
	if d.runtime == nil {
		return 0, ErrInvalidInput
	}
	return d.runtime.ActiveStreams(ctx)
}

func (d runtimeDrainer) ForceClose(ctx context.Context) error {
	if d.runtime == nil {
		return ErrInvalidInput
	}
	return d.runtime.ForceClose(ctx)
}

// Consumer is the tunnel-side wire adapter. It validates the shared frame,
// dispatches it to the bound ClientSession, and serializes protocol ACKs. It
// does not report network success or create data-plane streams.
type Consumer struct {
	session  *ClientSession
	rotation RotationRuntime
}

func NewConsumer(hello Hello, runtime Runtime, clock Clock) (*Consumer, error) {
	if runtime == nil {
		return nil, ErrInvalidInput
	}
	session, err := NewClientSession(ClientSessionConfig{Hello: hello, Applier: runtimeApplier{runtime: runtime}, Drainer: runtimeDrainer{runtime: runtime}, Clock: clock})
	if err != nil {
		return nil, err
	}
	rotation, _ := runtime.(RotationRuntime)
	return &Consumer{session: session, rotation: rotation}, nil
}

func (c *Consumer) Session() *ClientSession {
	if c == nil {
		return nil
	}
	return c.session
}

func (c *Consumer) AcceptWelcomeFrame(frame Frame) error {
	if c == nil || c.session == nil || frame.Type != MessageWelcome {
		return ErrInvalidInput
	}
	var welcome Welcome
	if err := frame.DecodePayload(&welcome); err != nil {
		return err
	}
	return c.session.AcceptWelcome(welcome)
}

func (c *Consumer) AcceptWelcome(welcome Welcome) error {
	if c == nil || c.session == nil {
		return ErrInvalidInput
	}
	return c.session.AcceptWelcome(welcome)
}

// HandleFrame returns a response frame for messages that require one. A
// session error is returned alongside a valid rejection/ACK when possible so
// the transport can choose whether to close or retry based on CodeOf.
func (c *Consumer) HandleFrame(ctx context.Context, frame Frame) (Frame, error) {
	if c == nil || c.session == nil || ctx == nil {
		return Frame{}, ErrInvalidInput
	}
	if err := frame.Validate(); err != nil {
		return Frame{}, err
	}
	switch frame.Type {
	case MessageSnapshot:
		var snapshot Snapshot
		if err := frame.DecodePayload(&snapshot); err != nil {
			return Frame{}, err
		}
		ack, applyErr := c.session.ApplySnapshot(ctx, snapshot)
		return c.applyAck(frame.RequestID, AckSnapshot, snapshot.Generation, snapshot.ContentHash, ack, applyErr)
	case MessageDelta:
		var delta Delta
		if err := frame.DecodePayload(&delta); err != nil {
			return Frame{}, err
		}
		ack, applyErr := c.session.ApplyDelta(ctx, delta)
		return c.applyAck(frame.RequestID, AckDelta, delta.Generation, delta.ContentHash, ack, applyErr)
	case MessageHeartbeatAck:
		var ack HeartbeatAck
		if err := frame.DecodePayload(&ack); err != nil {
			return Frame{}, err
		}
		return Frame{}, c.session.AcceptHeartbeatAck(ack)
	case MessageAuthRenewed:
		var result AuthResult
		if err := frame.DecodePayload(&result); err != nil {
			return Frame{}, err
		}
		return Frame{}, c.session.ApplyRenewal(result)
	case MessageDrain:
		var request Drain
		if err := frame.DecodePayload(&request); err != nil {
			return Frame{}, err
		}
		ack, err := c.session.HandleDrain(ctx, request)
		response, frameErr := NewFrame(MessageDrainAck, frame.RequestID, ack)
		if frameErr != nil {
			return Frame{}, frameErr
		}
		return response, err
	case MessageCredentialRotationChallenge:
		var challenge CredentialRotationChallenge
		if err := frame.DecodePayload(&challenge); err != nil {
			return Frame{}, err
		}
		if err := c.validateRotationIdentity(challenge.AccountID, challenge.TunnelID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration); err != nil {
			return c.rotationAckError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
		}
		if c.rotation == nil {
			return c.rotationAckError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("credential rotation runtime is not configured")))
		}
		proof, err := c.rotation.ProveCredentialRotation(ctx, challenge)
		if err != nil {
			return c.rotationAckError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
		}
		if err := proof.Validate(c.session.config.Clock.Now().UTC()); err != nil || !rotationProofMatchesChallenge(proof, challenge, challenge.Target) {
			if err == nil {
				err = codeError(ErrIdentityMismatch, ReasonAuthentication, false, errors.New("rotation proof identity does not match challenge"))
			}
			return c.rotationAckError(frame.RequestID, challenge.AccountID, challenge.TunnelID, challenge.OperationID, challenge.ConnectorID, challenge.HostID, challenge.SessionID, challenge.ProcessGeneration, challenge.TargetSetHash, challenge.OldCredentialGeneration, challenge.NewCredentialGeneration, err)
		}
		return NewFrame(MessageCredentialRotationProof, frame.RequestID, proof)
	case MessageCredentialRotationInstall:
		var install CredentialRotationInstall
		if err := frame.DecodePayload(&install); err != nil {
			return Frame{}, err
		}
		if err := c.validateRotationIdentity(install.AccountID, install.TunnelID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration); err != nil {
			return c.rotationAckError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, err)
		}
		if c.rotation == nil {
			return c.rotationAckError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("credential rotation runtime is not configured")))
		}
		if err := c.rotation.InstallCredentialRotation(ctx, install); err != nil {
			return c.rotationAckError(frame.RequestID, install.AccountID, install.TunnelID, install.OperationID, install.ConnectorID, install.HostID, install.SessionID, install.ProcessGeneration, install.TargetSetHash, install.OldCredentialGeneration, install.NewCredentialGeneration, err)
		}
		return NewFrame(MessageCredentialRotationAck, frame.RequestID, CredentialRotationAck{AccountID: install.AccountID, TunnelID: install.TunnelID, OperationID: install.OperationID, ConnectorID: install.ConnectorID, HostID: install.HostID, SessionID: install.SessionID, ProcessGeneration: install.ProcessGeneration, TargetSetHash: install.TargetSetHash, OldCredentialGeneration: install.OldCredentialGeneration, NewCredentialGeneration: install.NewCredentialGeneration, Status: RotationAckInstalled})
	case MessageCredentialRotationRevoke:
		var revoke CredentialRotationRevoke
		if err := frame.DecodePayload(&revoke); err != nil {
			return Frame{}, err
		}
		if err := c.validateRotationIdentity(revoke.AccountID, revoke.TunnelID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration); err != nil {
			return c.rotationAckError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
		}
		if c.rotation == nil {
			return c.rotationAckError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("credential rotation runtime is not configured")))
		}
		if err := c.rotation.RevokeCredentialRotation(ctx, revoke); err != nil {
			return c.rotationAckError(frame.RequestID, revoke.AccountID, revoke.TunnelID, revoke.OperationID, revoke.ConnectorID, revoke.HostID, revoke.SessionID, revoke.ProcessGeneration, revoke.TargetSetHash, revoke.OldCredentialGeneration, revoke.NewCredentialGeneration, err)
		}
		return NewFrame(MessageCredentialRotationAck, frame.RequestID, CredentialRotationAck{AccountID: revoke.AccountID, TunnelID: revoke.TunnelID, OperationID: revoke.OperationID, ConnectorID: revoke.ConnectorID, HostID: revoke.HostID, SessionID: revoke.SessionID, ProcessGeneration: revoke.ProcessGeneration, TargetSetHash: revoke.TargetSetHash, OldCredentialGeneration: revoke.OldCredentialGeneration, NewCredentialGeneration: revoke.NewCredentialGeneration, Status: RotationAckRevoked})
	case MessageCredentialRotationAck:
		var ack CredentialRotationAck
		if err := frame.DecodePayload(&ack); err != nil {
			return Frame{}, err
		}
		if err := c.validateRotationIdentity(ack.AccountID, ack.TunnelID, ack.ConnectorID, ack.HostID, ack.SessionID, ack.ProcessGeneration); err != nil {
			return Frame{}, err
		}
		return Frame{}, nil
	case MessageCredentialRotationReady:
		// Ready is emitted by the replacement connector session toward the
		// server. Accepting it in the server-to-connector direction would make
		// a peer able to claim readiness without installing anything.
		return Frame{}, codeError(ErrUnsupportedMessage, ReasonMalformed, false, errors.New("credential rotation ready is connector-to-server"))
	case MessageDisconnect:
		var disconnect Disconnect
		if err := frame.DecodePayload(&disconnect); err != nil {
			return Frame{}, err
		}
		return Frame{}, c.session.Close(disconnect.Reason)
	default:
		return Frame{}, codeError(ErrUnsupportedMessage, ReasonMalformed, false, nil)
	}
}

func (c *Consumer) validateRotationIdentity(accountID, tunnelID, connectorID, hostID, sessionID string, processGeneration uint64) error {
	if c == nil || c.session == nil {
		return ErrInvalidInput
	}
	now := c.session.config.Clock.Now().UTC()
	c.session.mu.RLock()
	defer c.session.mu.RUnlock()
	if err := c.session.ensureActiveReadLocked(now); err != nil {
		return err
	}
	if !hasCapability(c.session.welcome.Capabilities, CapabilityCredentialRotation) {
		return codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, nil)
	}
	if accountID != c.session.config.Hello.AccountID || tunnelID != c.session.config.Hello.TunnelID || connectorID != c.session.config.Hello.ConnectorID || hostID != c.session.auth.HostID || sessionID != c.session.welcome.SessionID || processGeneration != c.session.config.Hello.ProcessGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	return nil
}

func (c *Consumer) rotationAckError(requestID, accountID, tunnelID, operationID, connectorID, hostID, sessionID string, processGeneration uint64, targetSetHash string, oldGeneration, newGeneration uint64, cause error) (Frame, error) {
	code := CodeOf(cause)
	if code == "" || code == CodeInvalidInput || code == CodeUnsupportedMessage {
		code = CodeCredentialRotationRejected
	}
	ack := CredentialRotationAck{AccountID: accountID, TunnelID: tunnelID, OperationID: operationID, ConnectorID: connectorID, HostID: hostID, SessionID: sessionID, ProcessGeneration: processGeneration, TargetSetHash: targetSetHash, OldCredentialGeneration: oldGeneration, NewCredentialGeneration: newGeneration, Status: RotationAckRejected, Code: code}
	response, frameErr := NewFrame(MessageCredentialRotationAck, requestID, ack)
	if frameErr != nil {
		return Frame{}, errors.Join(cause, frameErr)
	}
	return response, cause
}

// applyAck always preserves a protocol acknowledgement when the incoming
// snapshot/delta was structurally valid and carried a bound identity. Session
// apply methods already return a recovery acknowledgement for generation gaps;
// a preparation/activation rejection returns no Ack, so synthesize the typed
// rejection here. Returning both values lets the transport send the recovery
// instruction before deciding whether the session should be closed.
func (c *Consumer) applyAck(requestID string, kind AckKind, generation uint64, contentHash string, ack Ack, applyErr error) (Frame, error) {
	if ack.Validate() != nil {
		code := CodeOf(applyErr)
		if code == "" {
			if kind == AckSnapshot {
				code = CodeSnapshotRejected
			} else {
				code = CodeDeltaRejected
			}
		}
		ack = c.session.RejectionAck(kind, generation, contentHash, code)
	}
	response, frameErr := NewFrame(MessageAck, requestID, ack)
	if frameErr != nil {
		if applyErr != nil {
			return Frame{}, errors.Join(applyErr, frameErr)
		}
		return Frame{}, frameErr
	}
	return response, applyErr
}

func (c *Consumer) HeartbeatFrame(requestID string, now time.Time) (Frame, error) {
	if c == nil || c.session == nil {
		return Frame{}, ErrInvalidInput
	}
	heartbeat, err := c.session.Heartbeat(now)
	if err != nil {
		return Frame{}, err
	}
	return NewFrame(MessageHeartbeat, requestID, heartbeat)
}

func (c *Consumer) RenewalFrame(requestID string, now time.Time, nonce, signedProof string) (Frame, error) {
	if c == nil || c.session == nil {
		return Frame{}, ErrInvalidInput
	}
	request, err := c.session.RenewalRequest(now, nonce, signedProof)
	if err != nil {
		return Frame{}, err
	}
	return NewFrame(MessageAuthRenew, requestID, request)
}

func (c *Consumer) ReadyFrame(requestID string, ctx context.Context, edgeReady, routeReady, originReady bool) (Frame, error) {
	if c == nil || c.session == nil || ctx == nil {
		return Frame{}, ErrInvalidInput
	}
	readiness, err := c.session.MarkReadyContext(ctx, edgeReady, routeReady, originReady)
	if err != nil {
		return Frame{}, err
	}
	return NewFrame(MessageReady, requestID, readiness)
}

func (c *Consumer) CompleteDrainFrame(requestID string, ctx context.Context, force bool) (Frame, error) {
	if c == nil || c.session == nil || ctx == nil {
		return Frame{}, ErrInvalidInput
	}
	ack, err := c.session.CompleteDrain(ctx, force)
	if err != nil {
		return Frame{}, err
	}
	return NewFrame(MessageDrainAck, requestID, ack)
}

func (c *Consumer) CloseFrame(requestID string, reason DisconnectReason) (Frame, error) {
	if c == nil || c.session == nil {
		return Frame{}, ErrInvalidInput
	}
	disconnect := c.session.Disconnect()
	if err := c.session.Close(reason); err != nil {
		return Frame{}, err
	}
	disconnect.Reason = reason
	disconnect.Retryable = reason == ReasonLeaseExpired || reason == ReasonHeartbeatTimeout || reason == ReasonCredentialExpired || reason == ReasonSessionReplaced
	return NewFrame(MessageDisconnect, requestID, disconnect)
}
