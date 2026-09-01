package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

var ErrWorkerInvalid = errors.New("runtime worker configuration is invalid")

type UsageWorker struct {
	Queue    *usage.Queue
	Sink     control.UsageSink
	Prepare  interface{ Flush() error }
	Persist  func() error
	Interval time.Duration
	Pulse    <-chan time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (w *UsageWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Queue == nil || w.Sink == nil || (w.Pulse == nil && w.Interval <= 0) || w.done != nil {
		return ErrWorkerInvalid
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done = cancel, make(chan struct{})
	go w.run(workerCtx)
	return nil
}

func (w *UsageWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-w.Pulse:
				if !ok {
					return
				}
				_, _, err := w.deliver(ctx)
				w.recordError(err)
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := w.deliver(ctx)
			w.recordError(err)
		}
	}
}

func (w *UsageWorker) deliver(ctx context.Context) (control.UsageResult, bool, error) {
	if w.Prepare != nil {
		if err := w.Prepare.Flush(); err != nil {
			return control.UsageResult{}, false, err
		}
	}
	result, delivered, err := control.DeliverNext(ctx, w.Queue, w.Sink)
	if err != nil || !delivered || w.Persist == nil {
		return result, delivered, err
	}
	if err := w.Persist(); err != nil {
		return control.UsageResult{}, true, err
	}
	return result, true, nil
}

func (w *UsageWorker) recordError(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

func (w *UsageWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *UsageWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		_, delivered, err := w.deliver(ctx)
		if err != nil {
			return err
		}
		if !delivered {
			return nil
		}
	}
}

type NodeWorker struct {
	Manager      *node.Manager
	Sink         control.NodeSink
	Registration control.NodeRegistration
	Interval     time.Duration
	Pulse        <-chan time.Time
	Now          func() time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (w *NodeWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Manager == nil || w.Sink == nil || (w.Pulse == nil && w.Interval <= 0) || w.done != nil {
		return ErrWorkerInvalid
	}
	if err := w.Manager.RegisterAndHeartbeat(ctx, w.Sink, w.Registration, w.now()); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done = cancel, make(chan struct{})
	go w.run(workerCtx)
	return nil
}

func (w *NodeWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case at, ok := <-w.Pulse:
				if !ok {
					return
				}
				w.recordError(w.heartbeat(ctx, at))
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			w.recordError(w.heartbeat(ctx, at))
		}
	}
}

func (w *NodeWorker) heartbeat(ctx context.Context, at time.Time) error {
	err := w.Sink.Heartbeat(ctx, w.Manager.Observation(w.Registration.NodeID, w.Registration.ProcessEpoch, at))
	if !errors.Is(err, control.ErrNodeObservationStale) {
		return err
	}
	return w.Manager.RegisterAndHeartbeat(ctx, w.Sink, w.Registration, at)
}

func (w *NodeWorker) recordError(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

func (w *NodeWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *NodeWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return w.Sink.Heartbeat(ctx, w.Manager.Observation(w.Registration.NodeID, w.Registration.ProcessEpoch, w.now()))
}

func (w *NodeWorker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}

type RouteWorker struct {
	// Registry owns the canonical durable HTTP generation. Legacy helper and
	// retained preview assignments use LegacyRegistry so a successful empty
	// canonical snapshot cannot erase their independent ownership.
	Registry       *route.Registry
	LegacyRegistry *route.Registry
	Source         control.RouteSource
	Observer       control.RouteObserver
	State          *node.State
	NodeID         string
	// ProcessEpoch fences desired assignments and observations to this exact
	// edge process. Canonical tunnel assignments must never be applied by an
	// old process instance.
	ProcessEpoch string
	// Carrier is the only readiness/forwarding boundary for durable tunnel
	// routes. It opens authenticated connector-v1 streams; it must not dial a
	// host-local origin address.
	Carrier RouteCarrier
	// DurableAdmissions is the edge's authenticated connector admission
	// authority. It is replaced from the complete server snapshot before a
	// staged route is probed, so a carrier cannot be selected from route data
	// alone.
	DurableAdmissions interface {
		Replace([]datacarrier.DurableAdmission, time.Time) error
	}
	AccessorSource interface {
		PrivateAccessCarrierAdmissions(context.Context, string, string) ([]control.PrivateAccessCarrierAdmission, error)
	}
	AccessorAdmissions interface {
		Replace([]datacarrier.DurableAdmission, time.Time) error
	}
	Interval time.Duration
	Pulse    <-chan time.Time
	// Ready must probe the complete candidate generation, including its edge
	// and origin paths, before the generation is promoted. It is required for
	// the canonical config-generation contract; legacy assignments continue to
	// use the existing atomic snapshot path until that contract is available.
	Ready        func(context.Context, []route.RouteRule) error
	DrainTimeout time.Duration

	mu                         sync.Mutex
	cancel                     context.CancelFunc
	done                       chan struct{}
	starting                   bool
	lastErr                    error
	canonicalSet               bool
	canonicalHash              [sha256.Size]byte
	canonicalGeneration        uint64
	canonicalPendingSet        bool
	canonicalPendingHash       [sha256.Size]byte
	canonicalPendingGeneration uint64
	canonicalPendingAdmissions bool
	canonicalAssignments       []control.RouteAssignment
	canonicalPendingDetached   []control.RouteAssignment
}

// RouteCarrier is implemented by the edge's authenticated carrier registry.
// ProbeRoutes is called before a complete generation is promoted and
// OpenRouteStream is used by the gateway transport after the route is active.
// Keeping both operations on one boundary prevents readiness from being a
// synthetic control-plane ping.
type RouteCarrier interface {
	ProbeRoutes(context.Context, []route.RouteRule) error
	OpenRouteStream(context.Context, route.RouteRule, string) (io.ReadWriteCloser, error)
}

// PrivateRouteCarrier is the optional access-only probe boundary. Private TCP
// assignments are retained in the durable admission registry but deliberately
// never enter the HTTP GenerationRegistry.
type PrivateRouteCarrier interface {
	ProbePrivateRoutes(context.Context, []route.RouteRule) error
}

func (w *RouteWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	if ctx == nil || w.Registry == nil || w.Source == nil || w.State == nil || w.NodeID == "" || (w.Pulse == nil && w.Interval <= 0) || w.done != nil || w.starting {
		w.mu.Unlock()
		return ErrWorkerInvalid
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w.cancel, w.done, w.starting = cancel, done, true
	w.mu.Unlock()

	err := w.reconcile(workerCtx)
	if err != nil && transientControlUnavailable(err) && workerCtx.Err() == nil {
		// A transient control outage is a valid degraded startup. The worker
		// remains alive and retries on its configured pulse/ticker.
	} else if err != nil {
		// Invalid local state and canceled startup are terminal. Publish the
		// result before releasing a concurrent Shutdown waiter, then close the
		// reserved lifecycle channel because no run goroutine was started.
		w.mu.Lock()
		w.lastErr = err
		w.starting = false
		w.cancel = nil
		w.done = nil
		w.mu.Unlock()
		close(done)
		cancel()
		return err
	}
	if workerCtx.Err() != nil {
		err = workerCtx.Err()
		w.mu.Lock()
		w.lastErr = err
		w.starting = false
		w.cancel = nil
		w.done = nil
		w.mu.Unlock()
		close(done)
		cancel()
		return err
	}
	w.mu.Lock()
	w.lastErr = err
	w.starting = false
	if err == nil {
		w.State.SetControlAvailable(true)
	}
	w.mu.Unlock()
	go w.run(workerCtx)
	return nil
}

func (w *RouteWorker) run(ctx context.Context) {
	defer close(w.done)
	if w.Pulse != nil {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-w.Pulse:
				if !ok {
					return
				}
				w.recordReconcile(w.reconcile(ctx))
			}
		}
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.recordReconcile(w.reconcile(ctx))
		}
	}
}

func (w *RouteWorker) recordReconcile(err error) {
	// A transient control outage must not withdraw this process's ready
	// registration. The control endpoints intentionally reject unready nodes,
	// so doing that would turn a short outage into a permanent startup loop.
	// Non-transient failures still make the node unavailable until a successful
	// reconcile proves the local state safe again.
	if err == nil || !transientControlUnavailable(err) {
		w.State.SetControlAvailable(err == nil)
	}
	// Publish the diagnostic only after the readiness projection has been
	// updated. Callers use LastError as the completion fence for a reconcile;
	// publishing it first would let them observe the failure while the node
	// still reported Ready, and made a failed replacement look successful.
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
	if err != nil {
		slog.Warn("route reconciliation failed", "edge_node_id", w.NodeID, "error", err)
	}
}

// transientControlUnavailable reports whether every leaf of a possibly joined
// error is the typed control-plane outage. This keeps local validation and
// readiness failures terminal while allowing independent route/accessor pulls
// to fail together during a control rollout.
func transientControlUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !transientControlUnavailable(cause) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, control.ErrControlUnavailable)
}

func (w *RouteWorker) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *RouteWorker) reconcile(ctx context.Context) error {
	if w.AccessorSource != nil || w.AccessorAdmissions != nil {
		if w.AccessorSource == nil || w.AccessorAdmissions == nil {
			return route.ErrInvalid
		}
	}

	routeErr := w.reconcileRoutes(ctx)
	accessorErr := w.reconcileAccessor(ctx)
	if routeErr == nil {
		return accessorErr
	}
	if accessorErr == nil {
		return routeErr
	}
	return errors.Join(routeErr, accessorErr)
}

func (w *RouteWorker) reconcileAccessor(ctx context.Context) error {
	if w.AccessorSource != nil || w.AccessorAdmissions != nil {
		if w.AccessorSource == nil || w.AccessorAdmissions == nil {
			return route.ErrInvalid
		}
		values, err := w.AccessorSource.PrivateAccessCarrierAdmissions(ctx, w.NodeID, w.ProcessEpoch)
		if err != nil {
			return err
		}
		mapped := make([]datacarrier.DurableAdmission, 0, len(values))
		for _, value := range values {
			mapped = append(mapped, value.Durable())
		}
		if err = w.AccessorAdmissions.Replace(mapped, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (w *RouteWorker) reconcileRoutes(ctx context.Context) error {
	var (
		desired   []control.RouteAssignment
		canonical bool
		snapshot  control.RouteSnapshot
		err       error
	)
	if source, ok := w.Source.(control.RouteSnapshotSource); ok {
		snapshot, err = source.DesiredRouteSnapshot(ctx, w.NodeID, w.ProcessEpoch)
		if err != nil {
			return err
		}
		if !snapshot.Complete && snapshot.Canonical {
			return route.ErrInvalid
		}
		desired, canonical = snapshot.Routes, snapshot.Canonical
	} else {
		desired, err = w.Source.DesiredRoutes(ctx, w.NodeID)
		if err != nil {
			return err
		}
		for _, assignment := range desired {
			if isCanonicalAssignment(assignment) || assignment.ConfigGeneration != 0 {
				canonical = true
				break
			}
		}
	}
	if canonical {
		// A canonical assignment is not safe to activate without both an
		// authenticated carrier/readiness source and the control-plane ACK
		// boundary. Legacy callbacks cannot establish the durable assignment
		// ownership contract by themselves.
		if w.ProcessEpoch == "" || w.Carrier == nil && w.Ready == nil || w.Observer == nil {
			return route.ErrGenerationNotReady
		}
		activeAssignments, err := selectCanonicalAssignments(desired, w.NodeID, w.ProcessEpoch)
		if err != nil {
			return err
		}
		if w.DurableAdmissions == nil {
			return route.ErrGenerationNotReady
		}
		supersededAssignments, err := canonicalSupersededAssignments(desired, activeAssignments, w.NodeID, w.ProcessEpoch)
		if err != nil {
			return err
		}
		httpAssignments, privateAssignments := splitCanonicalAssignments(activeAssignments)
		rules := canonicalRouteRules(httpAssignments)
		privateRules := canonicalPrivateRouteRules(privateAssignments)
		sortRouteRules(rules)
		contentHash := canonicalRouteHash(activeAssignments)
		localGeneration := w.canonicalGeneration
		changed := !w.canonicalSet || contentHash != w.canonicalHash || !w.Registry.HasActiveGeneration()
		if changed {
			if w.canonicalPendingSet && contentHash == w.canonicalPendingHash {
				localGeneration = w.canonicalPendingGeneration
			} else {
				if w.canonicalPendingGeneration > localGeneration {
					localGeneration = w.canonicalPendingGeneration
				}
				localGeneration++
			}
			if localGeneration == 0 {
				localGeneration = 1
			}
			for index := range rules {
				rules[index].Generation = localGeneration
			}
			if err := w.Registry.StageGeneration(localGeneration, rules); err != nil {
				return err
			}
			w.canonicalPendingSet = true
			w.canonicalPendingHash = contentHash
			w.canonicalPendingGeneration = localGeneration
			// Keep the last-known-good active assignment authorized while a
			// replacement is staged and probed. The matcher still serves the old
			// generation until the exact ready observation is accepted, so dropping
			// its admission at this point would make existing LKG routes fail
			// closed for new streams even though they remain authoritative.
			if !w.canonicalPendingAdmissions {
				admissionAssignments := canonicalPendingAdmissionAssignments(activeAssignments, w.canonicalAssignments, desired)
				admissions, admissionErr := canonicalDurableAdmissions(admissionAssignments)
				if admissionErr != nil {
					return admissionErr
				}
				if err := w.DurableAdmissions.Replace(admissions, time.Now().UTC()); err != nil {
					return err
				}
				w.canonicalPendingAdmissions = true
			}
			ready := w.Ready
			if len(rules) != 0 && ready == nil {
				ready = w.Carrier.ProbeRoutes
			}
			if len(rules) != 0 && ready == nil {
				return route.ErrGenerationNotReady
			}
			if ready != nil && len(rules) != 0 {
				if err := ready(ctx, rules); err != nil {
					return err
				}
			}
			if len(privateRules) != 0 {
				privateProbe, ok := w.Carrier.(PrivateRouteCarrier)
				if !ok {
					return route.ErrGenerationNotReady
				}
				if err := privateProbe.ProbePrivateRoutes(ctx, privateRules); err != nil {
					return err
				}
			}
			// The server must durably accept the exact ready tuple before local
			// promotion. A failed or uncertain ACK leaves the pending candidate
			// staged while the old generation remains authoritative.
			if err := w.Observer.ObserveRoutes(ctx, w.NodeID, canonicalRouteObservations(activeAssignments, "ready")); err != nil {
				return err
			}
			if err := w.Registry.MarkGenerationReady(localGeneration); err != nil {
				return err
			}
			drainErr := w.Registry.ActivateGeneration(ctx, localGeneration, w.DrainTimeout)
			if drainErr != nil && !errors.Is(drainErr, route.ErrDrainTimeout) {
				return drainErr
			}
			// Promotion is now complete. Retire the prior admission so future
			// requests cannot select the drained connector, while streams that
			// were already established continue under their stream lifetime.
			admissions, admissionErr := canonicalDurableAdmissions(activeAssignments)
			if admissionErr != nil {
				return admissionErr
			}
			if err := w.DurableAdmissions.Replace(admissions, time.Now().UTC()); err != nil {
				return err
			}
			w.canonicalPendingAdmissions = false
			w.canonicalGeneration, w.canonicalHash, w.canonicalSet = localGeneration, contentHash, true
			w.canonicalPendingSet = false
			w.canonicalPendingDetached = mergeCanonicalAssignments(
				detachedCanonicalAssignments(w.canonicalAssignments, activeAssignments), supersededAssignments,
			)
			w.canonicalAssignments = append([]control.RouteAssignment(nil), activeAssignments...)
			if err := w.flushCanonicalDetached(ctx); err != nil {
				return err
			}
		}
		if !changed {
			admissions, admissionErr := canonicalDurableAdmissions(activeAssignments)
			if admissionErr != nil {
				return admissionErr
			}
			if err := w.DurableAdmissions.Replace(admissions, time.Now().UTC()); err != nil {
				return err
			}
			w.canonicalPendingDetached = mergeCanonicalAssignments(w.canonicalPendingDetached, supersededAssignments)
			if err := w.flushCanonicalDetached(ctx); err != nil {
				return err
			}
			if err := w.Observer.ObserveRoutes(ctx, w.NodeID, canonicalRouteObservations(activeAssignments, "ready")); err != nil {
				return err
			}
		}
	}

	// A process-fenced canonical snapshot may contain the retained legacy
	// control_routes projection as well. Keep that projection in its own
	// registry and report its observations independently; canonical activation
	// above must never replace or erase it. For a legacy-only response, desired
	// is unchanged and this remains the original atomic replacement path.
	legacyDesired := desired
	if canonical {
		legacyDesired = make([]control.RouteAssignment, 0, len(desired))
		for _, assignment := range desired {
			if !isCanonicalAssignment(assignment) {
				legacyDesired = append(legacyDesired, assignment)
			}
		}
	}
	legacyRegistry := w.LegacyRegistry
	if legacyRegistry == nil {
		legacyRegistry = w.Registry
	}
	attachments := make([]route.Attachment, 0, len(legacyDesired))
	for _, assignment := range legacyDesired {
		if assignment.NodeID != w.NodeID {
			return route.ErrInvalid
		}
		attachments = append(attachments, route.Attachment{ID: assignment.RouteID, Revision: assignment.Revision, Environment: assignment.Environment, Node: assignment.NodeID, Generation: assignment.Generation, Kind: route.Kind(assignment.Kind), Host: assignment.PublicHost, Target: net.JoinHostPort(assignment.TargetHost, strconv.Itoa(int(assignment.TargetPort))), PreviewState: assignment.PreviewState, PreviewReason: assignment.PreviewReason})
	}
	if err := legacyRegistry.Replace(attachments); err != nil {
		return err
	}
	if w.Observer == nil {
		return nil
	}
	if len(legacyDesired) == 0 {
		return nil
	}
	observations := make([]control.RouteObservation, 0, len(legacyDesired))
	for _, assignment := range legacyDesired {
		observations = append(observations, control.RouteObservation{RouteID: assignment.RouteID, RouteRevision: assignment.Revision, EdgeNodeID: assignment.NodeID, ConnectorGeneration: assignment.Generation})
	}
	return w.Observer.ObserveRoutes(ctx, w.NodeID, observations)
}

func selectCanonicalAssignments(desired []control.RouteAssignment, nodeID, processEpoch string) ([]control.RouteAssignment, error) {
	selected := make(map[string]control.RouteAssignment)
	for _, assignment := range desired {
		if !isCanonicalAssignment(assignment) {
			// The control endpoint may return legacy helper rows alongside
			// canonical durable assignments. They belong to the legacy owner.
			continue
		}
		if err := validateCanonicalAssignment(assignment, nodeID, processEpoch); err != nil {
			return nil, err
		}
		state := assignment.State
		if state == "" {
			state = "active"
		}
		if state == "draining" || state == "detached" {
			continue
		}
		if state != "staged" && state != "active" {
			return nil, route.ErrInvalid
		}
		selectionKey := assignment.RouteID + "\x00" + assignment.ConnectorID
		current, exists := selected[selectionKey]
		if !exists {
			selected[selectionKey] = assignment
			continue
		}
		currentState := current.State
		if currentState == "" {
			currentState = "active"
		}
		switch {
		case current.AssignmentID == assignment.AssignmentID:
			// A repeated row is idempotent. Keep the staged form when the
			// server changes only its observation state.
			if currentState == "active" && state == "staged" {
				selected[selectionKey] = assignment
			}
		case currentState == "active" && state == "staged":
			selected[selectionKey] = assignment
		case currentState == "staged" && state == "active":
			// The staged candidate remains authoritative until its exact ready
			// acknowledgement is accepted.
		default:
			return nil, route.ErrMatchConflict
		}
	}
	result := make([]control.RouteAssignment, 0, len(selected))
	for _, assignment := range selected {
		result = append(result, assignment)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].RouteID != result[j].RouteID {
			return result[i].RouteID < result[j].RouteID
		}
		return result[i].AssignmentID < result[j].AssignmentID
	})
	return result, nil
}

func canonicalRouteRules(assignments []control.RouteAssignment) []route.RouteRule {
	// One matcher rule owns public route precedence. Replica assignments for
	// that route remain in DurableAdmissions and are selected by the carrier
	// registry after the matcher has admitted exactly one request.
	byRoute := make(map[string]control.RouteAssignment, len(assignments))
	for _, assignment := range assignments {
		if assignment.Kind != string(route.TunnelHTTPSWSS) {
			continue
		}
		current, exists := byRoute[assignment.RouteID]
		if exists && current.ConnectorID <= assignment.ConnectorID {
			continue
		}
		byRoute[assignment.RouteID] = assignment
	}
	rules := make([]route.RouteRule, 0, len(byRoute)*2)
	for _, assignment := range byRoute {
		hostname := assignment.MatchHostname
		if hostname == "" && assignment.MatchType != route.MatchOneLabelWildcard {
			hostname = assignment.PublicHost
		}
		observedState := assignment.ObservedState
		if observedState == "" {
			observedState = "ready"
		}
		base := route.RouteRule{
			ID: assignment.RouteID, Revision: assignment.Revision, Environment: assignment.Environment,
			RouteID: assignment.RouteID, RouteGeneration: assignment.Revision,
			AccountID: assignment.AccountID, HostID: assignment.HostID, TunnelID: assignment.TunnelID, ConnectorID: assignment.ConnectorID,
			MachineIdentityPublicKey: assignment.MachineIdentityPublicKey, MachineIdentityThumbprint: assignment.MachineIdentityThumbprint,
			ConnectorSessionID: assignment.ConnectorSessionID, ConnectorProcessGeneration: assignment.ConnectorProcessGeneration,
			ConfigGeneration: assignment.ConfigGeneration, ConfigContentHash: assignment.ConfigContentHash,
			AssignmentID: assignment.AssignmentID, AssignmentGeneration: assignment.AssignmentGeneration,
			ResourceKind: "tunnel", SessionGeneration: assignment.Generation,
			Node: assignment.NodeID, EdgeProcessEpoch: assignment.EdgeProcessEpoch, EdgeFailureDomain: assignment.EdgeFailureDomain,
			Kind: route.Kind(assignment.Kind), MatchType: assignment.MatchType, Hostname: hostname,
			WildcardSuffix: assignment.WildcardSuffix, PathPrefix: assignment.PathPrefix, Priority: assignment.Priority,
			Target: assignment.RouteID, Protocol: assignment.Protocol, OriginScheme: assignment.OriginScheme,
			AccessMode:   assignment.AccessMode,
			PreserveHost: assignment.PreserveHost, HostOverride: assignment.HostOverride,
			DesiredState: assignment.DesiredState, ObservedState: observedState, Reason: assignment.PreviewReason,
		}
		rules = append(rules, base)
		for _, domain := range assignment.DomainBindings {
			alias := base
			alias.ID = assignment.RouteID + "@" + domain.ID
			alias.Target = assignment.RouteID
			alias.Revision = domain.Generation
			alias.MatchType = domain.MatchType
			alias.Hostname = domain.Hostname
			alias.WildcardSuffix = ""
			if domain.MatchType == route.MatchOneLabelWildcard {
				alias.Hostname = ""
				alias.WildcardSuffix = strings.TrimPrefix(domain.Hostname, "*.")
			}
			rules = append(rules, alias)
		}
	}
	return rules
}

func canonicalPrivateRouteRules(assignments []control.RouteAssignment) []route.RouteRule {
	rules := make([]route.RouteRule, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment.Kind != string(route.TunnelPrivateTCP) {
			continue
		}
		rules = append(rules, route.RouteRule{
			ID: assignment.RouteID, Revision: assignment.Revision,
			AssignmentID: assignment.AssignmentID, AssignmentGeneration: assignment.AssignmentGeneration,
			AccountID: assignment.AccountID, HostID: assignment.HostID, TunnelID: assignment.TunnelID,
			ConnectorID: assignment.ConnectorID, ConnectorSessionID: assignment.ConnectorSessionID,
			ConnectorProcessGeneration: assignment.ConnectorProcessGeneration, ConfigGeneration: assignment.ConfigGeneration,
			MachineIdentityPublicKey: assignment.MachineIdentityPublicKey, MachineIdentityThumbprint: assignment.MachineIdentityThumbprint,
			ConfigContentHash: assignment.ConfigContentHash, Node: assignment.NodeID, EdgeProcessEpoch: assignment.EdgeProcessEpoch,
			EdgeFailureDomain: assignment.EdgeFailureDomain, Kind: route.TunnelPrivateTCP, Protocol: assignment.Protocol,
			AccessMode: assignment.AccessMode, Target: assignment.RouteID, DesiredState: assignment.DesiredState,
			ObservedState: assignment.ObservedState,
		})
	}
	sortRouteRules(rules)
	return rules
}

func splitCanonicalAssignments(assignments []control.RouteAssignment) (httpAssignments, privateAssignments []control.RouteAssignment) {
	for _, assignment := range assignments {
		switch assignment.Kind {
		case string(route.TunnelHTTPSWSS):
			httpAssignments = append(httpAssignments, assignment)
		case string(route.TunnelPrivateTCP):
			privateAssignments = append(privateAssignments, assignment)
		}
	}
	return httpAssignments, privateAssignments
}

func isCanonicalAssignment(assignment control.RouteAssignment) bool {
	return assignment.Canonical || assignment.AssignmentID != "" || assignment.Kind == string(route.TunnelHTTPSWSS) || assignment.Kind == string(route.TunnelPrivateTCP) || assignment.ConfigContentHash != ""
}

// canonicalPendingAdmissionAssignments returns the candidate set needed while
// a generation is being staged. A complete server snapshot can contain both
// the currently active assignment and a newer staged replacement for the same
// route. The matcher keeps the active generation authoritative until the
// ready observation is durably accepted, so the old active identity must stay
// in the carrier authorizer during that window as well. Once promotion
// succeeds the caller replaces the registry with activeAssignments only.
func canonicalPendingAdmissionAssignments(candidate, previous, desired []control.RouteAssignment) []control.RouteAssignment {
	result := append([]control.RouteAssignment(nil), candidate...)
	selected := make(map[string]struct{}, len(result))
	for _, assignment := range result {
		selected[assignment.AssignmentID] = struct{}{}
	}
	desiredState := make(map[string]string, len(desired))
	for _, assignment := range desired {
		if !isCanonicalAssignment(assignment) || assignment.AssignmentID == "" {
			continue
		}
		state := assignment.State
		if state == "" {
			state = "active"
		}
		desiredState[assignment.AssignmentID] = state
	}
	for _, assignment := range previous {
		if assignment.AssignmentID == "" {
			continue
		}
		if _, exists := selected[assignment.AssignmentID]; exists {
			continue
		}
		// An assignment omitted from the complete snapshot, or already marked
		// draining/detached by the server, is no longer an LKG authorization.
		state, exists := desiredState[assignment.AssignmentID]
		if !exists || state != "active" {
			continue
		}
		result = append(result, assignment)
		selected[assignment.AssignmentID] = struct{}{}
	}
	return result
}

func canonicalDurableAdmissions(assignments []control.RouteAssignment) ([]datacarrier.DurableAdmission, error) {
	result := make([]datacarrier.DurableAdmission, 0, len(assignments))
	for _, assignment := range assignments {
		if err := validateCanonicalAssignment(assignment, assignment.NodeID, assignment.EdgeProcessEpoch); err != nil {
			return nil, err
		}
		state := assignment.State
		if state == "" {
			state = "active"
		}
		result = append(result, datacarrier.DurableAdmission{
			Identity: datacarrier.Identity{
				AccountID: assignment.AccountID, HostID: assignment.HostID, TunnelID: assignment.TunnelID,
				ConnectorID: assignment.ConnectorID, SessionID: assignment.ConnectorSessionID,
				ProcessGeneration: assignment.ConnectorProcessGeneration, Generation: assignment.ConfigGeneration,
			},
			EdgeNodeID: assignment.NodeID, EdgeProcessEpoch: assignment.EdgeProcessEpoch,
			AssignmentID: assignment.AssignmentID, RouteID: assignment.RouteID,
			AssignmentGeneration: assignment.AssignmentGeneration, RouteGeneration: assignment.Revision,
			ConfigContentHash: assignment.ConfigContentHash, MachineIdentityPublicKey: assignment.MachineIdentityPublicKey,
			MachineIdentityThumbprint: assignment.MachineIdentityThumbprint, State: state,
		})
	}
	return result, nil
}

func canonicalRouteObservations(assignments []control.RouteAssignment, observedState string) []control.RouteObservation {
	result := make([]control.RouteObservation, 0, len(assignments))
	for _, assignment := range assignments {
		result = append(result, control.RouteObservation{
			RouteID: assignment.RouteID, RouteRevision: assignment.Revision, AssignmentID: assignment.AssignmentID,
			AssignmentGeneration: assignment.AssignmentGeneration, EdgeNodeID: assignment.NodeID,
			EdgeProcessEpoch: assignment.EdgeProcessEpoch,
			ConnectorID:      assignment.ConnectorID, HostID: assignment.HostID, ConnectorGeneration: assignment.Generation,
			ConnectorSessionID: assignment.ConnectorSessionID, ConnectorProcessGeneration: assignment.ConnectorProcessGeneration,
			ConfigGeneration: assignment.ConfigGeneration, ConfigContentHash: assignment.ConfigContentHash,
			State: observedState, ObservedState: observedState,
		})
	}
	return result
}

func detachedCanonicalAssignments(previous, current []control.RouteAssignment) []control.RouteAssignment {
	currentIDs := make(map[string]struct{}, len(current))
	for _, assignment := range current {
		currentIDs[assignment.AssignmentID] = struct{}{}
	}
	result := make([]control.RouteAssignment, 0, len(previous))
	for _, assignment := range previous {
		if _, exists := currentIDs[assignment.AssignmentID]; !exists {
			result = append(result, assignment)
		}
	}
	return result
}

func canonicalSupersededAssignments(desired, selected []control.RouteAssignment, nodeID, processEpoch string) ([]control.RouteAssignment, error) {
	selectedIDs := make(map[string]struct{}, len(selected))
	for _, assignment := range selected {
		selectedIDs[assignment.AssignmentID] = struct{}{}
	}
	seen := make(map[string]struct{})
	result := make([]control.RouteAssignment, 0)
	for _, assignment := range desired {
		if !isCanonicalAssignment(assignment) {
			continue
		}
		if err := validateCanonicalAssignment(assignment, nodeID, processEpoch); err != nil {
			return nil, err
		}
		state := assignment.State
		if state == "" {
			state = "active"
		}
		if state != "active" && state != "draining" {
			continue
		}
		if _, exists := selectedIDs[assignment.AssignmentID]; exists {
			continue
		}
		if _, exists := seen[assignment.AssignmentID]; exists {
			continue
		}
		seen[assignment.AssignmentID] = struct{}{}
		result = append(result, assignment)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AssignmentID < result[j].AssignmentID })
	return result, nil
}

func mergeCanonicalAssignments(left, right []control.RouteAssignment) []control.RouteAssignment {
	if len(right) == 0 {
		return left
	}
	result := append([]control.RouteAssignment(nil), left...)
	seen := make(map[string]struct{}, len(result)+len(right))
	for _, assignment := range result {
		seen[assignment.AssignmentID] = struct{}{}
	}
	for _, assignment := range right {
		if _, exists := seen[assignment.AssignmentID]; exists {
			continue
		}
		seen[assignment.AssignmentID] = struct{}{}
		result = append(result, assignment)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AssignmentID < result[j].AssignmentID })
	return result
}

func (w *RouteWorker) flushCanonicalDetached(ctx context.Context) error {
	if w == nil || len(w.canonicalPendingDetached) == 0 {
		return nil
	}
	if err := w.Observer.ObserveRoutes(ctx, w.NodeID, canonicalRouteObservations(w.canonicalPendingDetached, "detached")); err != nil {
		return err
	}
	w.canonicalPendingDetached = nil
	return nil
}

func validateCanonicalAssignment(assignment control.RouteAssignment, nodeID, processEpoch string) error {
	if assignment.AssignmentID == "" || connectorprotocol.ValidateIdentifier(assignment.AssignmentID) != nil ||
		assignment.RouteID == "" || connectorprotocol.ValidateIdentifier(assignment.RouteID) != nil ||
		assignment.AccountID == "" || connectorprotocol.ValidateIdentifier(assignment.AccountID) != nil ||
		assignment.HostID == "" || connectorprotocol.ValidateIdentifier(assignment.HostID) != nil ||
		assignment.MachineIdentityPublicKey == "" || assignment.MachineIdentityThumbprint == "" ||
		assignment.TunnelID == "" || connectorprotocol.ValidateIdentifier(assignment.TunnelID) != nil ||
		assignment.ConnectorID == "" || connectorprotocol.ValidateIdentifier(assignment.ConnectorID) != nil ||
		assignment.ConnectorSessionID == "" || connectorprotocol.ValidateIdentifier(assignment.ConnectorSessionID) != nil ||
		assignment.NodeID != nodeID || assignment.EdgeProcessEpoch != processEpoch ||
		connectorprotocol.ValidateOpaqueEpoch(assignment.EdgeProcessEpoch) != nil ||
		assignment.AssignmentGeneration == 0 || assignment.Revision == 0 || assignment.Generation == 0 ||
		assignment.ConnectorProcessGeneration == 0 || assignment.ConfigGeneration == 0 ||
		assignment.OriginAddress != "" || assignment.TargetHost != "" || assignment.TargetPort != 0 {
		return route.ErrInvalid
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(assignment.MachineIdentityPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return route.ErrInvalid
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(publicKey))
	if err != nil || thumbprint != assignment.MachineIdentityThumbprint {
		return route.ErrInvalid
	}
	if assignment.TargetRouteID != "" && assignment.TargetRouteID != assignment.RouteID {
		return route.ErrInvalid
	}
	if assignment.TargetConnectorSessionID != "" && assignment.TargetConnectorSessionID != assignment.ConnectorSessionID {
		return route.ErrInvalid
	}
	if assignment.TargetConnectorProcessGen != 0 && assignment.TargetConnectorProcessGen != assignment.ConnectorProcessGeneration {
		return route.ErrInvalid
	}
	if assignment.TargetConfigGeneration != 0 && assignment.TargetConfigGeneration != assignment.ConfigGeneration {
		return route.ErrInvalid
	}
	if len(assignment.ConfigContentHash) != len("sha256:")+64 || !strings.HasPrefix(assignment.ConfigContentHash, "sha256:") {
		return route.ErrInvalid
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(assignment.ConfigContentHash, "sha256:")); err != nil {
		return route.ErrInvalid
	}
	if assignment.EdgeFailureDomain == "" {
		return route.ErrInvalid
	}
	switch assignment.Kind {
	case string(route.TunnelHTTPSWSS):
		if assignment.AccessMode != "public" && assignment.AccessMode != "private" || assignment.PublicHost == "" || assignment.MatchType == "" || assignment.Protocol == "" {
			return route.ErrInvalid
		}
		if assignment.MatchType == route.MatchManagedExact {
			managedHost := assignment.MatchHostname
			if managedHost == "" {
				managedHost = assignment.PublicHost
			}
			if !route.ValidOpaqueTunnelHostname(managedHost) {
				return route.ErrInvalid
			}
		}
		if err := validateDomainBindings(assignment.DomainBindings); err != nil {
			return err
		}
	case string(route.TunnelPrivateTCP):
		// Private TCP is an access-only carrier binding. It has no public
		// hostname/path and therefore must never be fed to GenerationRegistry.
		if assignment.AccessMode != "private" || assignment.Protocol != "private_tcp" || assignment.PublicHost != "" || assignment.MatchType != "" || assignment.MatchHostname != "" || assignment.WildcardSuffix != "" || assignment.PathPrefix != "" || assignment.Priority != 0 || assignment.HostOverride != "" || assignment.PreserveHost || len(assignment.DomainBindings) != 0 {
			return route.ErrInvalid
		}
	default:
		return route.ErrInvalid
	}
	if assignment.State != "" && assignment.State != "staged" && assignment.State != "active" && assignment.State != "draining" && assignment.State != "detached" {
		return route.ErrInvalid
	}
	return nil
}

func validateDomainBindings(bindings []control.DomainBinding) error {
	if len(bindings) > 256 {
		return route.ErrInvalid
	}
	identities := make(map[string]struct{}, len(bindings))
	hostnames := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if connectorprotocol.ValidateIdentifier(binding.ID) != nil || binding.Generation == 0 || binding.Hostname == "" ||
			binding.Hostname != strings.ToLower(binding.Hostname) || strings.HasSuffix(binding.Hostname, ".") ||
			strings.ContainsAny(binding.Hostname, "/:@\r\n\x00") {
			return route.ErrInvalid
		}
		hostname := binding.Hostname
		switch binding.MatchType {
		case route.MatchExact:
			if strings.Contains(hostname, "*") {
				return route.ErrInvalid
			}
		case route.MatchOneLabelWildcard:
			if !strings.HasPrefix(hostname, "*.") || strings.Contains(strings.TrimPrefix(hostname, "*."), "*") {
				return route.ErrInvalid
			}
			hostname = strings.TrimPrefix(hostname, "*.")
		default:
			return route.ErrInvalid
		}
		if net.ParseIP(hostname) != nil || len(hostname) > 253 || strings.HasPrefix(hostname, ".") || strings.Contains(hostname, "..") {
			return route.ErrInvalid
		}
		if _, exists := identities[binding.ID]; exists {
			return route.ErrInvalid
		}
		if _, exists := hostnames[binding.Hostname]; exists {
			return route.ErrInvalid
		}
		identities[binding.ID] = struct{}{}
		hostnames[binding.Hostname] = struct{}{}
	}
	return nil
}

func sortRouteRules(rules []route.RouteRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].ID != rules[j].ID {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].AssignmentID < rules[j].AssignmentID
	})
}

func canonicalRouteHash(assignments []control.RouteAssignment) [sha256.Size]byte {
	type immutableAssignment struct {
		AssignmentID               string                  `json:"assignment_id"`
		AssignmentGeneration       uint64                  `json:"assignment_generation"`
		RouteID                    string                  `json:"route_id"`
		RouteRevision              uint64                  `json:"route_revision"`
		AccountID                  string                  `json:"account_id"`
		HostID                     string                  `json:"host_id"`
		MachineIdentityPublicKey   string                  `json:"machine_identity_public_key"`
		MachineIdentityThumbprint  string                  `json:"machine_identity_thumbprint"`
		TunnelID                   string                  `json:"tunnel_id"`
		ConnectorID                string                  `json:"connector_id"`
		ConnectorGeneration        uint64                  `json:"connector_generation"`
		ConnectorSessionID         string                  `json:"connector_session_id"`
		ConnectorProcessGeneration uint64                  `json:"connector_process_generation"`
		ConfigGeneration           uint64                  `json:"config_generation"`
		ConfigContentHash          string                  `json:"config_content_hash"`
		EdgeNodeID                 string                  `json:"edge_node_id"`
		EdgeProcessEpoch           string                  `json:"edge_process_epoch"`
		EdgeFailureDomain          string                  `json:"edge_failure_domain"`
		Kind                       string                  `json:"kind"`
		PublicHost                 string                  `json:"public_host"`
		MatchType                  string                  `json:"match_type"`
		MatchHostname              string                  `json:"match_hostname"`
		WildcardSuffix             string                  `json:"wildcard_suffix"`
		PathPrefix                 string                  `json:"path_prefix"`
		Priority                   int                     `json:"priority"`
		Protocol                   string                  `json:"protocol"`
		OriginScheme               string                  `json:"origin_scheme"`
		AccessMode                 string                  `json:"access_mode"`
		PreserveHost               bool                    `json:"preserve_host"`
		HostOverride               string                  `json:"host_override"`
		TargetRouteID              string                  `json:"target_route_id"`
		TargetConnectorSessionID   string                  `json:"target_connector_session_id"`
		TargetConnectorProcessGen  uint64                  `json:"target_connector_process_generation"`
		TargetConfigGeneration     uint64                  `json:"target_config_generation"`
		DomainBindings             []control.DomainBinding `json:"domain_bindings"`
	}
	ordered := make([]immutableAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		ordered = append(ordered, immutableAssignment{
			AssignmentID: assignment.AssignmentID, AssignmentGeneration: assignment.AssignmentGeneration,
			RouteID: assignment.RouteID, RouteRevision: assignment.Revision, AccountID: assignment.AccountID,
			HostID: assignment.HostID, TunnelID: assignment.TunnelID, ConnectorID: assignment.ConnectorID,
			MachineIdentityPublicKey: assignment.MachineIdentityPublicKey, MachineIdentityThumbprint: assignment.MachineIdentityThumbprint,
			ConnectorGeneration: assignment.Generation, ConnectorSessionID: assignment.ConnectorSessionID,
			ConnectorProcessGeneration: assignment.ConnectorProcessGeneration, ConfigGeneration: assignment.ConfigGeneration,
			ConfigContentHash: assignment.ConfigContentHash, EdgeNodeID: assignment.NodeID,
			EdgeProcessEpoch: assignment.EdgeProcessEpoch, EdgeFailureDomain: assignment.EdgeFailureDomain,
			Kind: assignment.Kind, PublicHost: assignment.PublicHost, MatchType: assignment.MatchType,
			MatchHostname: assignment.MatchHostname, WildcardSuffix: assignment.WildcardSuffix,
			PathPrefix: assignment.PathPrefix, Priority: assignment.Priority, Protocol: assignment.Protocol,
			OriginScheme: assignment.OriginScheme, PreserveHost: assignment.PreserveHost, HostOverride: assignment.HostOverride,
			AccessMode:     assignment.AccessMode,
			DomainBindings: canonicalDomainBindings(assignment.DomainBindings),
			TargetRouteID:  assignment.TargetRouteID, TargetConnectorSessionID: assignment.TargetConnectorSessionID,
			TargetConnectorProcessGen: assignment.TargetConnectorProcessGen, TargetConfigGeneration: assignment.TargetConfigGeneration,
		})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].RouteID != ordered[j].RouteID {
			return ordered[i].RouteID < ordered[j].RouteID
		}
		return ordered[i].AssignmentID < ordered[j].AssignmentID
	})
	payload, _ := json.Marshal(ordered)
	return sha256.Sum256(payload)
}

func canonicalDomainBindings(bindings []control.DomainBinding) []control.DomainBinding {
	result := append([]control.DomainBinding(nil), bindings...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Hostname != result[j].Hostname {
			return result[i].Hostname < result[j].Hostname
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func (w *RouteWorker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
