package runtime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
)

var (
	ErrPreviewCarrierRuntimeInvalid = errors.New("invalid preview carrier runtime")
	ErrPreviewCarrierRuntimeClosed  = errors.New("preview carrier runtime is closed")
)

const (
	defaultPreviewCarrierPollInterval = 15 * time.Second
	defaultPreviewCarrierWaitTimeout  = 30 * time.Second
	maxPreviewCarrierPollInterval     = 5 * time.Minute
	previewCarrierReconcileInterval   = 100 * time.Millisecond
	previewCarrierReadyRetryInterval  = time.Second
)

// PreviewCarrierWorker reconciles the node-scoped, server-issued admission
// set. It never turns a failed control pull into an empty set: last-known-good
// admissions remain active until a successful pull explicitly removes them.
// Local routes are removed immediately when the successful snapshot removes or
// expires them, while detach observations are retried idempotently. A
// successful pull is required to be complete; the control client rejects
// incomplete or over-limit responses before this worker can commit them.
type PreviewCarrierWorker struct {
	source       control.PreviewCarrierSource
	expected     *datacarrier.ExpectedAdmissionRegistry
	registry     *edgehttp.DataCarrierPreviewRegistry
	nodeID       string
	processEpoch string
	interval     time.Duration
	timeout      time.Duration
	now          func() time.Time

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
	// pending contains only server-created terminal detach commands. Their
	// generation is authoritative and may be ACKed durably. Informational
	// local expiry/shutdown observations use the separate map below and never
	// acknowledge a fabricated terminal generation.
	pending             map[string]control.PreviewCarrierDetachment
	pendingObservations map[string]control.PreviewCarrierObservation
}

type PreviewCarrierWorkerConfig struct {
	Source       control.PreviewCarrierSource
	Expected     *datacarrier.ExpectedAdmissionRegistry
	Registry     *edgehttp.DataCarrierPreviewRegistry
	NodeID       string
	ProcessEpoch string
	Interval     time.Duration
	Timeout      time.Duration
	Clock        func() time.Time
}

func NewPreviewCarrierWorker(config PreviewCarrierWorkerConfig) (*PreviewCarrierWorker, error) {
	if config.Source == nil || config.Expected == nil || config.Registry == nil || connectorprotocol.ValidateIdentifier(config.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil || config.Expected.NodeID() != config.NodeID || config.Expected.ProcessEpoch() != config.ProcessEpoch {
		return nil, ErrPreviewCarrierRuntimeInvalid
	}
	if config.Interval == 0 {
		config.Interval = defaultPreviewCarrierPollInterval
	}
	if config.Timeout == 0 {
		config.Timeout = defaultPreviewCarrierWaitTimeout
	}
	if config.Interval <= 0 || config.Interval > maxPreviewCarrierPollInterval || config.Timeout <= 0 || config.Timeout > time.Minute {
		return nil, ErrPreviewCarrierRuntimeInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &PreviewCarrierWorker{source: config.Source, expected: config.Expected, registry: config.Registry, nodeID: config.NodeID, processEpoch: config.ProcessEpoch, interval: config.Interval, timeout: config.Timeout, now: config.Clock, pending: make(map[string]control.PreviewCarrierDetachment), pendingObservations: make(map[string]control.PreviewCarrierObservation)}, nil
}

func (w *PreviewCarrierWorker) Start(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrPreviewCarrierRuntimeInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrPreviewCarrierRuntimeClosed
	}
	if w.started {
		return ErrPreviewCarrierRuntimeInvalid
	}
	runCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})
	w.started = true
	go w.loop(runCtx)
	return nil
}

func (w *PreviewCarrierWorker) loop(ctx context.Context) {
	defer close(w.done)
	// Pull immediately, but do not block startup on a control endpoint that is
	// still being rolled out. A later successful pull publishes the first set.
	w.reconcile(ctx)
	timer := time.NewTimer(w.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.reconcile(ctx)
			timer.Reset(w.interval)
		}
	}
}

func (w *PreviewCarrierWorker) reconcile(parent context.Context) {
	if w == nil || parent == nil || parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	now := w.now().UTC()
	w.expireLocal(now)
	var (
		admissions  []control.PreviewCarrierAdmission
		detachments []control.PreviewCarrierDetachment
		err         error
	)
	if source, ok := w.source.(control.PreviewCarrierSnapshotSource); ok {
		var snapshot control.PreviewCarrierSnapshot
		snapshot, err = source.PreviewCarrierSnapshot(ctx, w.nodeID, w.processEpoch)
		if err == nil {
			admissions = snapshot.Admissions
			detachments = snapshot.Detachments
		}
	} else {
		admissions, err = w.source.PreviewCarrierAdmissions(ctx, w.nodeID, w.processEpoch)
	}
	if err != nil {
		// ErrControlUnavailable includes rollout/temporary network failures. Do
		// not clear the last-known-good admission set on any failed pull.
		return
	}
	expected := make([]datacarrier.ExpectedAdmission, 0, len(admissions))
	for _, admission := range admissions {
		value, convertErr := admission.Expected(w.nodeID, now)
		if convertErr != nil {
			return
		}
		expected = append(expected, value)
	}
	if err := w.expected.InstallPending(expected, now); err != nil {
		return
	}
	if err := w.source.AcknowledgePreviewCarrierAdmissions(ctx, w.nodeID, w.processEpoch, admissions); err != nil {
		return
	}
	for index := range expected {
		expected[index].Admitted = true
	}
	if err := w.expected.MarkAdmitted(expected); err != nil {
		return
	}
	if err := w.expected.Commit(expected); err != nil {
		return
	}
	aliases := make([]edgehttp.DataCarrierPreviewAlias, 0)
	for _, admission := range admissions {
		normalized, normalizeErr := admission.Normalize()
		if normalizeErr != nil {
			return
		}
		for _, alias := range normalized.Aliases {
			aliases = append(aliases, edgehttp.DataCarrierPreviewAlias{
				DomainID: alias.DomainID, RouteID: normalized.Binding.RouteID, Hostname: alias.Hostname, MatchType: alias.MatchType,
				PreviewGeneration: alias.PreviewGeneration, DomainGeneration: alias.DomainGeneration, CertificateGeneration: alias.CertificateGeneration,
			})
		}
	}
	if err := w.registry.ReconcilePreviewAliases(aliases); err != nil {
		return
	}
	w.detachRemoved(expected, now)
	w.applyServerDetachments(ctx, detachments)
	w.expireLocal(now)
	_ = w.flushPending(ctx)
	_ = w.flushPendingObservations(ctx)
}

// expireLocal fails closed when a lease expires while the control plane is
// unavailable. The route is removed from the edge gateway immediately; the
// durable detach observation is retried on later successful control calls.
func (w *PreviewCarrierWorker) expireLocal(now time.Time) {
	if w == nil {
		return
	}
	for _, route := range w.registry.Snapshot() {
		if route.ExpiresAt.IsZero() || route.ExpiresAt.After(now) {
			continue
		}
		_ = w.registry.Detach(route.RouteID, route.Identity, route.Revision)
		for _, admission := range w.expected.Snapshot() {
			if admission.OperationID == route.OperationID && admission.RouteID == route.RouteID && admission.AttachmentGeneration == route.AttachmentGeneration {
				_ = w.expected.Remove(admission)
				break
			}
		}
		key := route.OperationID + "\x00" + route.RouteID
		w.mu.Lock()
		w.pendingObservations[key] = observationFromRoute(route, now, "expired", "lease_expired")
		w.mu.Unlock()
	}
}

func (w *PreviewCarrierWorker) detachRemoved(expected []datacarrier.ExpectedAdmission, now time.Time) {
	if w == nil {
		return
	}
	allowed := make(map[string]datacarrier.ExpectedAdmission, len(expected))
	for _, admission := range expected {
		allowed[admission.OperationID+"\x00"+admission.RouteID] = admission
	}
	for _, route := range w.registry.Snapshot() {
		key := route.OperationID + "\x00" + route.RouteID
		current, exists := allowed[key]
		if exists && current.Identity == route.Identity && current.AttachmentGeneration == route.AttachmentGeneration && current.RouteRevision == route.Revision && current.ExpiresAt.After(now) {
			continue
		}
		_ = w.registry.Detach(route.RouteID, route.Identity, route.Revision)
	}
}

// applyServerDetachments removes routes using the exact durable terminal
// generation supplied by the server and then reports those same commands as
// an idempotent acknowledgement. It intentionally does not synthesize a
// generation from the local route: release/expiry may have advanced the
// server row while this process was disconnected.
func (w *PreviewCarrierWorker) applyServerDetachments(ctx context.Context, detachments []control.PreviewCarrierDetachment) {
	if w == nil || len(detachments) == 0 || ctx == nil || ctx.Err() != nil {
		return
	}
	for _, detachment := range detachments {
		for _, route := range w.registry.Snapshot() {
			if route.OperationID != detachment.Binding.OperationID || route.RouteID != detachment.Binding.RouteID || route.Identity.AccountID != detachment.Binding.AccountID || route.Identity.HostID != detachment.Binding.HostID || route.Identity.TunnelID != detachment.Binding.TunnelID || route.Identity.ConnectorID != detachment.Binding.ConnectorID || route.Identity.SessionID != detachment.Binding.SessionID || route.Identity.ProcessGeneration != detachment.Binding.ProcessGeneration || route.Identity.Generation != detachment.Binding.ConfigGeneration || route.Revision != detachment.Binding.RouteGeneration || route.OwnerDeviceID != detachment.Binding.OwnerDeviceID || route.OwnerSessionID != detachment.Binding.OwnerSessionID || route.AttachmentGeneration >= detachment.AttachmentGeneration {
				continue
			}
			_ = w.registry.Detach(route.RouteID, route.Identity, route.Revision)
		}
		for _, admission := range w.expected.Snapshot() {
			if admission.OperationID == detachment.Binding.OperationID && admission.RouteID == detachment.Binding.RouteID && admission.Identity.AccountID == detachment.Binding.AccountID && admission.Identity.HostID == detachment.Binding.HostID && admission.Identity.TunnelID == detachment.Binding.TunnelID && admission.Identity.ConnectorID == detachment.Binding.ConnectorID && admission.Identity.SessionID == detachment.Binding.SessionID && admission.Identity.ProcessGeneration == detachment.Binding.ProcessGeneration && admission.Identity.Generation == detachment.Binding.ConfigGeneration && admission.RouteRevision == detachment.Binding.RouteGeneration && admission.AttachmentGeneration < detachment.AttachmentGeneration {
				_ = w.expected.Remove(admission)
			}
		}
	}
	if err := w.source.DetachPreviewCarriers(ctx, w.nodeID, w.processEpoch, detachments); err != nil {
		// Keep exact commands for retry. The server endpoint is idempotent and
		// the next complete snapshot will replay them after a lost response.
		w.mu.Lock()
		for _, detachment := range detachments {
			w.pending[detachment.Binding.OperationID+"\x00"+detachment.Binding.RouteID] = detachment
		}
		w.mu.Unlock()
	}
}

func (w *PreviewCarrierWorker) flushPending(ctx context.Context) error {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return nil
	}
	values := make([]control.PreviewCarrierDetachment, 0, len(w.pending))
	for _, value := range w.pending {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Binding.OperationID != values[j].Binding.OperationID {
			return values[i].Binding.OperationID < values[j].Binding.OperationID
		}
		return values[i].Binding.RouteID < values[j].Binding.RouteID
	})
	w.mu.Unlock()
	if err := w.source.DetachPreviewCarriers(ctx, w.nodeID, w.processEpoch, values); err != nil {
		return err
	}
	w.mu.Lock()
	for _, value := range values {
		delete(w.pending, value.Binding.OperationID+"\x00"+value.Binding.RouteID)
	}
	w.mu.Unlock()
	return nil
}

func (w *PreviewCarrierWorker) flushPendingObservations(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrPreviewCarrierRuntimeInvalid
	}
	w.mu.Lock()
	if len(w.pendingObservations) == 0 {
		w.mu.Unlock()
		return nil
	}
	values := make([]control.PreviewCarrierObservation, 0, len(w.pendingObservations))
	for _, value := range w.pendingObservations {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Binding.OperationID != values[j].Binding.OperationID {
			return values[i].Binding.OperationID < values[j].Binding.OperationID
		}
		return values[i].Binding.RouteID < values[j].Binding.RouteID
	})
	w.mu.Unlock()
	if err := w.source.ObservePreviewCarriers(ctx, w.nodeID, w.processEpoch, values); err != nil {
		return err
	}
	w.mu.Lock()
	for _, value := range values {
		delete(w.pendingObservations, value.Binding.OperationID+"\x00"+value.Binding.RouteID)
	}
	w.mu.Unlock()
	return nil
}

func (w *PreviewCarrierWorker) Shutdown(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrPreviewCarrierRuntimeInvalid
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Remove local routes before carrier listeners close. Shutdown is an
	// informational observation; the server's durable detach command is the
	// only source of a terminal attachment generation.
	now := w.now().UTC()
	routes := w.registry.Snapshot()
	observations := make([]control.PreviewCarrierObservation, 0, len(routes))
	for _, route := range routes {
		_ = w.registry.Detach(route.RouteID, route.Identity, route.Revision)
		observations = append(observations, observationFromRoute(route, now, "detached", "edge_shutdown"))
	}
	if len(observations) != 0 {
		if err := w.source.ObservePreviewCarriers(ctx, w.nodeID, w.processEpoch, observations); err != nil && ctx.Err() == nil {
			w.mu.Lock()
			for _, value := range observations {
				w.pendingObservations[value.Binding.OperationID+"\x00"+value.Binding.RouteID] = value
			}
			w.mu.Unlock()
		}
	}
	if err := w.flushPending(ctx); err != nil {
		return err
	}
	if err := w.flushPendingObservations(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// PreviewCarrierHandler is passed to CarrierAssembly. Its input server has
// already passed TLS client authentication and ExpectedAdmissionRegistry's
// PeerBinding. It still waits for the exact operation admission, because an
// authenticated connector may have no active preview assignment.
type PreviewCarrierHandler struct {
	source       control.PreviewCarrierSource
	expected     *datacarrier.ExpectedAdmissionRegistry
	registry     *edgehttp.DataCarrierPreviewRegistry
	nodeID       string
	processEpoch string
	waitTimeout  time.Duration
	now          func() time.Time
}

type PreviewCarrierHandlerConfig struct {
	Source       control.PreviewCarrierSource
	Expected     *datacarrier.ExpectedAdmissionRegistry
	Registry     *edgehttp.DataCarrierPreviewRegistry
	NodeID       string
	ProcessEpoch string
	WaitTimeout  time.Duration
	Clock        func() time.Time
}

type previewCarrierPendingReady struct {
	admission datacarrier.ExpectedAdmission
	retryAt   time.Time
}

func NewPreviewCarrierHandler(config PreviewCarrierHandlerConfig) (*PreviewCarrierHandler, error) {
	if config.Source == nil || config.Expected == nil || config.Registry == nil || connectorprotocol.ValidateIdentifier(config.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil || config.Expected.NodeID() != config.NodeID || config.Expected.ProcessEpoch() != config.ProcessEpoch {
		return nil, ErrPreviewCarrierRuntimeInvalid
	}
	if config.WaitTimeout == 0 {
		config.WaitTimeout = defaultPreviewCarrierWaitTimeout
	}
	if config.WaitTimeout <= 0 || config.WaitTimeout > time.Minute {
		return nil, ErrPreviewCarrierRuntimeInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &PreviewCarrierHandler{source: config.Source, expected: config.Expected, registry: config.Registry, nodeID: config.NodeID, processEpoch: config.ProcessEpoch, waitTimeout: config.WaitTimeout, now: config.Clock}, nil
}

func (h *PreviewCarrierHandler) Handle(ctx context.Context, server *datacarrier.Server) error {
	if h == nil || ctx == nil || server == nil {
		return ErrPreviewCarrierRuntimeInvalid
	}
	identity := server.Identity()
	waitContext, cancel := context.WithTimeout(ctx, h.waitTimeout)
	_, err := h.expected.WaitForIdentity(waitContext, identity, func() time.Time { return h.now().UTC() })
	cancel()
	if err != nil {
		return fmt.Errorf("wait for preview admission: %w", err)
	}
	attached := make(map[string]datacarrier.ExpectedAdmission)
	pendingReady := make(map[string]previewCarrierPendingReady)
	if err := h.reconcile(ctx, server, identity, attached, pendingReady); err != nil {
		_ = h.closeAttached(ctx, attached, "handler_error")
		return err
	}
	ticker := time.NewTicker(previewCarrierReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-server.Done():
			return h.closeAttached(ctx, attached, "carrier_closed")
		case <-ctx.Done():
			return h.closeAttached(ctx, attached, "carrier_closed")
		case <-ticker.C:
			if err := h.reconcile(ctx, server, identity, attached, pendingReady); err != nil {
				_ = h.closeAttached(ctx, attached, "handler_error")
				return err
			}
		}
	}
}

func (h *PreviewCarrierHandler) detachLocal(admissions []datacarrier.ExpectedAdmission) {
	for _, admission := range admissions {
		_ = h.registry.DetachAdmission(admission)
	}
}

func (h *PreviewCarrierHandler) reconcile(ctx context.Context, server *datacarrier.Server, identity datacarrier.Identity, attached map[string]datacarrier.ExpectedAdmission, pendingReady map[string]previewCarrierPendingReady) error {
	desired := h.expected.ForIdentity(identity, h.now().UTC())
	sort.Slice(desired, func(i, j int) bool {
		return previewCarrierAdmissionKey(desired[i]) < previewCarrierAdmissionKey(desired[j])
	})
	desiredByKey := make(map[string]datacarrier.ExpectedAdmission, len(desired))
	for _, admission := range desired {
		desiredByKey[previewCarrierAdmissionKey(admission)] = admission
	}

	detached := make([]datacarrier.ExpectedAdmission, 0)
	for key, admission := range attached {
		next, exists := desiredByKey[key]
		if exists && previewCarrierAdmissionEqual(admission, next) {
			continue
		}
		_ = h.registry.DetachAdmission(admission)
		delete(attached, key)
		detached = append(detached, admission)
	}
	for key, admission := range pendingReady {
		if next, exists := desiredByKey[key]; !exists || !previewCarrierAdmissionEqual(admission.admission, next) {
			delete(pendingReady, key)
		}
	}

	// Detach is informational after the local generation-fenced route removal.
	// The server may have already finalized the row, so a 404/stale response is
	// not allowed to close unrelated active sibling routes.
	for _, admission := range detached {
		now := h.now().UTC()
		state, reason := previewCarrierDetachState(admission, now, "admission_removed")
		_ = h.observe(ctx, []control.PreviewCarrierObservation{observationFromAdmission(admission, state, reason, now)})
	}

	for _, admission := range desired {
		key := previewCarrierAdmissionKey(admission)
		if _, exists := attached[key]; exists {
			continue
		}
		if pending, exists := pendingReady[key]; exists {
			if !previewCarrierAdmissionEqual(pending.admission, admission) {
				delete(pendingReady, key)
			} else if time.Now().Before(pending.retryAt) {
				continue
			}
		}
		if err := h.registry.AttachAdmission(admission, server); err != nil {
			pendingReady[key] = previewCarrierPendingReady{admission: admission, retryAt: time.Now().Add(previewCarrierReadyRetryInterval)}
			continue
		}
		now := h.now().UTC()
		if err := h.observe(ctx, []control.PreviewCarrierObservation{observationFromAdmission(admission, "edge_ready", "", now)}); err != nil {
			_ = h.registry.DetachAdmission(admission)
			pendingReady[key] = previewCarrierPendingReady{admission: admission, retryAt: time.Now().Add(previewCarrierReadyRetryInterval)}
			continue
		}
		attached[key] = admission
		delete(pendingReady, key)
	}
	return nil
}

func (h *PreviewCarrierHandler) closeAttached(ctx context.Context, attached map[string]datacarrier.ExpectedAdmission, reason string) error {
	if len(attached) == 0 {
		return nil
	}
	admissions := make([]datacarrier.ExpectedAdmission, 0, len(attached))
	for _, admission := range attached {
		admissions = append(admissions, admission)
	}
	sort.Slice(admissions, func(i, j int) bool {
		return previewCarrierAdmissionKey(admissions[i]) < previewCarrierAdmissionKey(admissions[j])
	})
	h.detachLocal(admissions)
	now := h.now().UTC()
	observations := make([]control.PreviewCarrierObservation, 0, len(admissions))
	for _, admission := range admissions {
		state, observationReason := previewCarrierDetachState(admission, now, reason)
		observations = append(observations, observationFromAdmission(admission, state, observationReason, now))
	}
	if err := h.observe(ctx, observations); err != nil && ctx.Err() == nil {
		return fmt.Errorf("observe preview carrier detach: %w", err)
	}
	return nil
}

func (h *PreviewCarrierHandler) observe(ctx context.Context, observations []control.PreviewCarrierObservation) error {
	if len(observations) == 0 {
		return nil
	}
	observeContext, cancel := context.WithTimeout(ctx, h.waitTimeout)
	defer cancel()
	return h.source.ObservePreviewCarriers(observeContext, h.nodeID, h.processEpoch, observations)
}

func previewCarrierAdmissionKey(admission datacarrier.ExpectedAdmission) string {
	return admission.OperationID + "\x00" + admission.RouteID
}

func previewCarrierAdmissionEqual(left, right datacarrier.ExpectedAdmission) bool {
	expiresEqual := left.ExpiresAt.Equal(right.ExpiresAt)
	left.ExpiresAt = time.Time{}
	right.ExpiresAt = time.Time{}
	left.Admitted = false
	right.Admitted = false
	return expiresEqual && left == right
}

func previewCarrierDetachState(admission datacarrier.ExpectedAdmission, now time.Time, reason string) (string, string) {
	if !admission.ExpiresAt.After(now) {
		return "expired", "lease_expired"
	}
	return "detached", reason
}

func observationFromAdmission(admission datacarrier.ExpectedAdmission, state, reason string, observedAt time.Time) control.PreviewCarrierObservation {
	return control.PreviewCarrierObservation{Schema: controlPreviewCarrierSchema, Kind: controlPreviewCarrierKind, Binding: bindingFromAdmission(admission), AttachmentGeneration: admission.AttachmentGeneration, State: state, Reason: reason, ObservedAt: observedAt}
}

func observationFromRoute(route edgehttp.DataCarrierPreviewRoute, observedAt time.Time, state, reason string) control.PreviewCarrierObservation {
	return control.PreviewCarrierObservation{Schema: controlPreviewCarrierSchema, Kind: controlPreviewCarrierKind, Binding: control.PreviewCarrierBinding{AccountID: route.Identity.AccountID, PreviewID: route.PreviewID, OperationID: route.OperationID, OwnerDeviceID: route.OwnerDeviceID, OwnerSessionID: route.OwnerSessionID, HostID: route.Identity.HostID, LeaseGeneration: route.LeaseGeneration, TunnelID: route.Identity.TunnelID, ConnectorID: route.Identity.ConnectorID, SessionID: route.Identity.SessionID, ProcessGeneration: route.Identity.ProcessGeneration, ConfigGeneration: route.Identity.Generation, RouteID: route.RouteID, RouteGeneration: route.Revision, EdgeNodeID: route.EdgeNodeID, EdgeProcessEpoch: route.EdgeProcessEpoch, EdgeCarrierServerSPKISHA256: route.EdgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: route.EdgeCarrierServerCertificateChainPEM, MachineIdentityPublicKey: route.MachineIdentityPublicKey, MachineIdentityThumbprint: route.MachineIdentityThumbprint}, AttachmentGeneration: route.AttachmentGeneration, State: state, Reason: reason, ObservedAt: observedAt}
}

func bindingFromAdmission(admission datacarrier.ExpectedAdmission) control.PreviewCarrierBinding {
	return control.PreviewCarrierBinding{AccountID: admission.Identity.AccountID, PreviewID: admission.PreviewID, OperationID: admission.OperationID, OwnerDeviceID: admission.OwnerDeviceID, OwnerSessionID: admission.OwnerSessionID, HostID: admission.Identity.HostID, LeaseGeneration: admission.LeaseGeneration, TunnelID: admission.Identity.TunnelID, ConnectorID: admission.Identity.ConnectorID, SessionID: admission.Identity.SessionID, ProcessGeneration: admission.Identity.ProcessGeneration, ConfigGeneration: admission.Identity.Generation, RouteID: admission.RouteID, RouteGeneration: admission.RouteRevision, EdgeNodeID: admission.EdgeNodeID, EdgeProcessEpoch: admission.EdgeProcessEpoch, EdgeCarrierServerSPKISHA256: admission.EdgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: admission.EdgeCarrierServerCertificateChainPEM, MachineIdentityPublicKey: admission.MachineIdentityPublicKey, MachineIdentityThumbprint: admission.MachineIdentityThumbprint}
}

const (
	controlPreviewCarrierSchema = "paperboat.preview-tunnel/v1"
	controlPreviewCarrierKind   = "preview_carrier_attachment"
)

var _ Component = (*PreviewCarrierWorker)(nil)
