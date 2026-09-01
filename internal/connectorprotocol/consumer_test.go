package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type consumerPrepared struct {
	runtime *testRuntime
	active  bool
}

func (p *consumerPrepared) Activate(context.Context) error {
	p.runtime.mu.Lock()
	defer p.runtime.mu.Unlock()
	p.active = true
	p.runtime.activations++
	return nil
}

func (p *consumerPrepared) Abort(context.Context) error {
	p.runtime.mu.Lock()
	defer p.runtime.mu.Unlock()
	p.runtime.aborts++
	return nil
}

type testRuntime struct {
	mu          sync.Mutex
	prepared    int
	activations int
	aborts      int
	active      uint32
	stopCalls   int
	forceCalls  int
	stageErr    error
}

// rotationConsumerRuntime exercises the tunnel-side credential boundary
// without putting key custody or transport behavior in Consumer. The adapter
// receives protocol metadata and returns a proof/side effect result; all
// cryptographic material remains test-local.
type rotationConsumerRuntime struct {
	*testRuntime
	proof      CredentialRotationProof
	installErr error
	revokeErr  error
	installed  []CredentialRotationInstall
	revoked    []CredentialRotationRevoke
}

func (r *rotationConsumerRuntime) ProveCredentialRotation(context.Context, CredentialRotationChallenge) (CredentialRotationProof, error) {
	return r.proof, nil
}

func (r *rotationConsumerRuntime) InstallCredentialRotation(_ context.Context, install CredentialRotationInstall) error {
	if r.installErr != nil {
		return r.installErr
	}
	r.installed = append(r.installed, install)
	return nil
}

func (r *rotationConsumerRuntime) RevokeCredentialRotation(_ context.Context, revoke CredentialRotationRevoke) error {
	if r.revokeErr != nil {
		return r.revokeErr
	}
	r.revoked = append(r.revoked, revoke)
	return nil
}

func (r *testRuntime) StageSnapshot(context.Context, Snapshot) (PreparedConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stageErr != nil {
		return nil, r.stageErr
	}
	r.prepared++
	return &consumerPrepared{runtime: r}, nil
}

func (r *testRuntime) StageDelta(ctx context.Context, delta Delta) (PreparedConfig, error) {
	return r.StageSnapshot(ctx, Snapshot{Generation: delta.Generation})
}

func (r *testRuntime) StopNewStreams(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopCalls++
	return nil
}

func (r *testRuntime) ActiveStreams(context.Context) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active, nil
}

func (r *testRuntime) ForceClose(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forceCalls++
	r.active = 0
	return nil
}

func newConsumerTest(t *testing.T) (*Consumer, AuthRequest, *testRuntime, *testClock, Welcome) {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	auth, _ := testAuth(t, now, 1)
	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth}
	runtime := &testRuntime{}
	consumer, err := NewConsumer(hello, runtime, clock)
	if err != nil {
		t.Fatal(err)
	}
	welcome := Welcome{Protocol: ProtocolName, Version: ProtocolVersion, SessionID: "sess_1", Capabilities: requiredCapabilityList(), Lease: Lease{SessionID: "sess_1", ExpiresAt: now.Add(time.Minute), HeartbeatIntervalMS: 10000}, RequiresSnapshot: true, ServerTime: now}
	if err := consumer.AcceptWelcome(welcome); err != nil {
		t.Fatal(err)
	}
	return consumer, auth, runtime, clock, welcome
}

func TestConsumerDispatchesBoundSnapshotAndReadiness(t *testing.T) {
	consumer, auth, runtime, _, _ := newConsumerTest(t)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = auth.AccountID, auth.ConnectorID, "sess_1", 1
	frame, err := NewFrame(MessageSnapshot, "req_snapshot", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	response, err := consumer.HandleFrame(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	var ack Ack
	if err := response.DecodePayload(&ack); err != nil {
		t.Fatal(err)
	}
	if response.Type != MessageAck || ack.Status != AckApplied || ack.Generation != 1 {
		t.Fatalf("snapshot response=%+v ack=%+v", response, ack)
	}
	ready, err := consumer.ReadyFrame("req_ready", context.Background(), true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	var readiness Readiness
	if err := ready.DecodePayload(&readiness); err != nil || readiness.Generation != 1 {
		t.Fatalf("ready=%+v err=%v", readiness, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.prepared != 1 || runtime.activations != 1 {
		t.Fatalf("runtime staging=%d activation=%d", runtime.prepared, runtime.activations)
	}
}

func TestConsumerDrainFramesUseRuntimeHookAndTypedForcedOutcome(t *testing.T) {
	consumer, auth, runtime, clock, welcome := newConsumerTest(t)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = auth.AccountID, auth.ConnectorID, welcome.SessionID, 1
	snapshotFrame, _ := NewFrame(MessageSnapshot, "req_snapshot", snapshot)
	if _, err := consumer.HandleFrame(context.Background(), snapshotFrame); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ReadyFrame("req_ready", context.Background(), true, true, true); err != nil {
		t.Fatal(err)
	}
	request := Drain{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, DrainID: "drain_1", Generation: 1, ContentHash: snapshot.ContentHash, Deadline: clock.Now().Add(20 * time.Second), StopNewStreams: true, ForceAfterDeadline: true}
	drainFrame, err := NewFrame(MessageDrain, "req_drain", request)
	if err != nil {
		t.Fatal(err)
	}
	runtime.active = 1
	response, err := consumer.HandleFrame(context.Background(), drainFrame)
	if err != nil {
		t.Fatal(err)
	}
	var accepted DrainAck
	if err := response.DecodePayload(&accepted); err != nil || accepted.Status != DrainAccepted || accepted.ActiveStreams != 1 {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	if runtime.stopCalls != 1 {
		t.Fatalf("stop calls=%d", runtime.stopCalls)
	}
	forced, err := consumer.CompleteDrainFrame("req_drain_done", context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	var completed DrainAck
	if err := forced.DecodePayload(&completed); err != nil || completed.Status != DrainForced || completed.Code != CodeDrainTimeout || !completed.ForcedClose {
		t.Fatalf("forced=%+v err=%v", completed, err)
	}
	if runtime.forceCalls != 1 {
		t.Fatalf("force calls=%d", runtime.forceCalls)
	}
}

func TestConsumerRejectsUnboundSnapshotFrame(t *testing.T) {
	consumer, auth, _, _, _ := newConsumerTest(t)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewFrame(MessageSnapshot, "req_snapshot", snapshot)
	if err == nil {
		t.Fatal("unbound snapshot frame constructed")
	}
	if _, err := consumer.HandleFrame(context.Background(), Frame{Type: MessageSnapshot, Version: ProtocolVersion, RequestID: "req_snapshot", Payload: mustJSON(t, snapshot)}); err == nil {
		t.Fatal("unbound snapshot accepted")
	}
}

func TestConsumerReturnsRejectedAckWhenSnapshotPreparationFails(t *testing.T) {
	consumer, auth, runtime, _, welcome := newConsumerTest(t)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AccountID, snapshot.ConnectorID, snapshot.SessionID, snapshot.ProcessGeneration = auth.AccountID, auth.ConnectorID, welcome.SessionID, 1
	runtime.stageErr = errors.New("staging failed")
	frame, err := NewFrame(MessageSnapshot, "req_snapshot_rejected", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	response, applyErr := consumer.HandleFrame(context.Background(), frame)
	if applyErr == nil || CodeOf(applyErr) != CodeSnapshotRejected {
		t.Fatalf("apply error=%v", applyErr)
	}
	if response.Type != MessageAck {
		t.Fatalf("response=%+v", response)
	}
	var ack Ack
	if err := response.DecodePayload(&ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status != AckRejected || ack.Code != CodeSnapshotRejected || ack.Generation != snapshot.Generation || ack.ContentHash != snapshot.ContentHash {
		t.Fatalf("rejection ack=%+v", ack)
	}
}

func TestConsumerReturnsSnapshotRecoveryAckWithGenerationGapError(t *testing.T) {
	consumer, auth, runtime, _, welcome := newConsumerTest(t)
	initial, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	initial.AccountID, initial.ConnectorID, initial.SessionID, initial.ProcessGeneration = auth.AccountID, auth.ConnectorID, welcome.SessionID, 1
	initialFrame, err := NewFrame(MessageSnapshot, "req_snapshot", initial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.HandleFrame(context.Background(), initialFrame); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ReadyFrame("req_ready", context.Background(), true, true, true); err != nil {
		t.Fatal(err)
	}
	previous, err := NewSnapshot(auth.TunnelID, 2, testConfigPayload(2, "next.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	delta, err := NewDelta(auth.TunnelID, previous, 3, testConfigPayload(3, "third.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	delta.AccountID, delta.ConnectorID, delta.SessionID, delta.ProcessGeneration = auth.AccountID, auth.ConnectorID, welcome.SessionID, 1
	deltaFrame, err := NewFrame(MessageDelta, "req_delta_gap", delta)
	if err != nil {
		t.Fatal(err)
	}
	response, applyErr := consumer.HandleFrame(context.Background(), deltaFrame)
	if applyErr == nil || CodeOf(applyErr) != CodeGenerationGap {
		t.Fatalf("apply error=%v", applyErr)
	}
	if response.Type != MessageAck {
		t.Fatalf("response=%+v", response)
	}
	var ack Ack
	if err := response.DecodePayload(&ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status != AckSnapshotRequired || ack.Generation != delta.Generation || ack.ContentHash != delta.ContentHash {
		t.Fatalf("recovery ack=%+v", ack)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.prepared != 1 {
		t.Fatalf("unexpected prepare count=%d", runtime.prepared)
	}
}

func newRotationConsumerTest(t *testing.T) (*Consumer, AuthRequest, *rotationConsumerRuntime, *testClock, Welcome, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	auth, oldPrivate := testAuth(t, now, 1)
	capabilities := append(requiredCapabilityList(), CapabilityCredentialRotation)
	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: capabilities, Auth: auth}
	runtime := &rotationConsumerRuntime{testRuntime: &testRuntime{}}
	consumer, err := NewConsumer(hello, runtime, clock)
	if err != nil {
		t.Fatal(err)
	}
	welcome := Welcome{Protocol: ProtocolName, Version: ProtocolVersion, SessionID: "sess_1", Capabilities: capabilities, Lease: Lease{SessionID: "sess_1", ExpiresAt: now.Add(time.Minute), HeartbeatIntervalMS: 10000}, RequiresSnapshot: true, ServerTime: now}
	if err := consumer.AcceptWelcome(welcome); err != nil {
		t.Fatal(err)
	}
	return consumer, auth, runtime, clock, welcome, oldPrivate
}

func TestConsumerDispatchesCredentialRotationChallengeInstallAndRevoke(t *testing.T) {
	consumer, auth, runtime, clock, welcome, oldPrivate := newRotationConsumerTest(t)
	newPrivate, _, _ := rotationKey(81)
	plan, err := NewRotationPlan(auth.AccountID, auth.TunnelID, "op_rotate_consumer", []RotationTarget{{ConnectorID: auth.ConnectorID, HostID: auth.HostID, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := CredentialRotationChallenge{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0], OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, OldIdentityKeyID: auth.IdentityKeyID, OldIdentityKeyThumbprint: auth.IdentityKeyThumbprint, ChallengeNonce: "nonce-consumer-rotation", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Minute), OverlapUntil: clock.Now().Add(10 * time.Minute), NewCredentialValidUntil: clock.Now().Add(24 * time.Hour)}
	runtime.proof = rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/consumer", clock.Now())
	challengeFrame, err := NewFrame(MessageCredentialRotationChallenge, "req_rotation_challenge", challenge)
	if err != nil {
		t.Fatal(err)
	}
	proofFrame, err := consumer.HandleFrame(context.Background(), challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	if proofFrame.Type != MessageCredentialRotationProof {
		t.Fatalf("challenge response type=%s", proofFrame.Type)
	}
	var proof CredentialRotationProof
	if err := proofFrame.DecodePayload(&proof); err != nil || proof != runtime.proof {
		t.Fatalf("proof=%+v err=%v", proof, err)
	}

	install := CredentialRotationInstall{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint, NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference, ChallengeNonce: challenge.ChallengeNonce, OverlapUntil: challenge.OverlapUntil, NewCredentialValidUntil: challenge.NewCredentialValidUntil, ReplacementProcessGeneration: 2}
	installFrame, err := NewFrame(MessageCredentialRotationInstall, "req_rotation_install", install)
	if err != nil {
		t.Fatal(err)
	}
	response, err := consumer.HandleFrame(context.Background(), installFrame)
	if err != nil {
		t.Fatal(err)
	}
	var installed CredentialRotationAck
	if err := response.DecodePayload(&installed); err != nil || response.Type != MessageCredentialRotationAck || installed.Status != RotationAckInstalled {
		t.Fatalf("install response=%+v ack=%+v err=%v", response, installed, err)
	}

	revoke := CredentialRotationRevoke{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, RevokeNonce: "nonce-consumer-revoke", IssuedAt: clock.Now(), Deadline: clock.Now().Add(DefaultAbortTimeout)}
	revokeFrame, err := NewFrame(MessageCredentialRotationRevoke, "req_rotation_revoke", revoke)
	if err != nil {
		t.Fatal(err)
	}
	response, err = consumer.HandleFrame(context.Background(), revokeFrame)
	if err != nil {
		t.Fatal(err)
	}
	var revoked CredentialRotationAck
	if err := response.DecodePayload(&revoked); err != nil || response.Type != MessageCredentialRotationAck || revoked.Status != RotationAckRevoked {
		t.Fatalf("revoke response=%+v ack=%+v err=%v", response, revoked, err)
	}
	if len(runtime.installed) != 1 || len(runtime.revoked) != 1 {
		t.Fatalf("runtime installs=%d revokes=%d", len(runtime.installed), len(runtime.revoked))
	}
}

func TestConsumerReturnsTypedRotationRejectionForMissingCapabilityAndRuntimeFailure(t *testing.T) {
	consumer, auth, _, clock, welcome := newConsumerTest(t)
	plan, err := NewRotationPlan(auth.AccountID, auth.TunnelID, "op_rotate_consumer_reject", []RotationTarget{{ConnectorID: auth.ConnectorID, HostID: auth.HostID, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := CredentialRotationChallenge{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0], OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, OldIdentityKeyID: auth.IdentityKeyID, OldIdentityKeyThumbprint: auth.IdentityKeyThumbprint, ChallengeNonce: "nonce-consumer-reject", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Minute), OverlapUntil: clock.Now().Add(10 * time.Minute), NewCredentialValidUntil: clock.Now().Add(24 * time.Hour)}
	frame, err := NewFrame(MessageCredentialRotationChallenge, "req_rotation_reject", challenge)
	if err == nil {
		response, handleErr := consumer.HandleFrame(context.Background(), frame)
		if handleErr == nil || response.Type != MessageCredentialRotationAck {
			t.Fatalf("missing capability response=%+v err=%v", response, handleErr)
		}
		var ack CredentialRotationAck
		if decodeErr := response.DecodePayload(&ack); decodeErr != nil || ack.Status != RotationAckRejected || ack.Code != CodeCapabilityMissing {
			t.Fatalf("missing capability ack=%+v decodeErr=%v", ack, decodeErr)
		}
	} else {
		t.Fatal(err)
	}

	rotationConsumer, auth, runtime, clock, welcome, oldPrivate := newRotationConsumerTest(t)
	newPrivate, _, _ := rotationKey(82)
	plan, err = NewRotationPlan(auth.AccountID, auth.TunnelID, "op_rotate_consumer_runtime_error", []RotationTarget{{ConnectorID: auth.ConnectorID, HostID: auth.HostID, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1}})
	if err != nil {
		t.Fatal(err)
	}
	challenge = CredentialRotationChallenge{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, Target: plan.Targets[0], OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, OldIdentityKeyID: auth.IdentityKeyID, OldIdentityKeyThumbprint: auth.IdentityKeyThumbprint, ChallengeNonce: "nonce-consumer-runtime", IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Minute), OverlapUntil: clock.Now().Add(10 * time.Minute), NewCredentialValidUntil: clock.Now().Add(24 * time.Hour)}
	runtime.proof = rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/consumer-error", clock.Now())
	runtime.installErr = codeError(ErrCredentialExpired, ReasonCredentialExpired, true, errors.New("replacement expired"))
	challengeFrame, err := NewFrame(MessageCredentialRotationChallenge, "req_rotation_runtime_challenge", challenge)
	if err != nil {
		t.Fatal(err)
	}
	proofFrame, err := rotationConsumer.HandleFrame(context.Background(), challengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	var proof CredentialRotationProof
	if err := proofFrame.DecodePayload(&proof); err != nil {
		t.Fatal(err)
	}
	install := CredentialRotationInstall{AccountID: auth.AccountID, TunnelID: auth.TunnelID, OperationID: plan.OperationID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, SessionID: welcome.SessionID, ProcessGeneration: 1, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: auth.CredentialGeneration, NewCredentialGeneration: auth.CredentialGeneration + 1, NewIdentityKeyID: proof.NewIdentityKeyID, NewIdentityKeyThumbprint: proof.NewIdentityKeyThumbprint, NewPublicKey: proof.NewPublicKey, NewCredentialReference: proof.NewCredentialReference, ChallengeNonce: challenge.ChallengeNonce, OverlapUntil: challenge.OverlapUntil, NewCredentialValidUntil: challenge.NewCredentialValidUntil, ReplacementProcessGeneration: 2}
	installFrame, err := NewFrame(MessageCredentialRotationInstall, "req_rotation_runtime_install", install)
	if err != nil {
		t.Fatal(err)
	}
	response, handleErr := rotationConsumer.HandleFrame(context.Background(), installFrame)
	if handleErr == nil || CodeOf(handleErr) != CodeCredentialExpired || response.Type != MessageCredentialRotationAck {
		t.Fatalf("runtime rejection response=%+v err=%v", response, handleErr)
	}
	var ack CredentialRotationAck
	if err := response.DecodePayload(&ack); err != nil || ack.Status != RotationAckRejected || ack.Code != CodeCredentialExpired {
		t.Fatalf("runtime rejection ack=%+v err=%v", ack, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
