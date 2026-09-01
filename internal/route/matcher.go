package route

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	MatchExact            = "exact"
	MatchManagedExact     = "managed_exact"
	MatchOneLabelWildcard = "one_label_wildcard"
	MatchCatchAll         = "catch_all"
	DefaultMaximumRoutes  = 4096
	DefaultMaximumStreams = 16384
	DefaultDrainTimeout   = 30 * time.Second
)

var (
	ErrNoMatch            = errors.New("route does not match request")
	ErrMatchConflict      = errors.New("route match is ambiguous")
	ErrGenerationStale    = errors.New("route generation is stale")
	ErrGenerationNotReady = errors.New("route generation is not ready")
	ErrGenerationConflict = errors.New("route generation conflicts with current state")
	ErrGenerationClosed   = errors.New("route generation registry is closed")
	ErrDrainTimeout       = errors.New("route generation drain timed out")
	ErrStreamOverloaded   = errors.New("route generation stream capacity exhausted")
)

type GenerationRegistryOptions struct {
	TelemetrySink  RouteTelemetrySink
	TelemetryClock func() time.Time
	MaximumStreams int
}

// RouteRule is the edge-owned representation of a route match and its
// readiness projection. Hostname is used by exact routes; WildcardSuffix is
// the suffix without the "*." prefix for one-label wildcards.
//
// Rules are deliberately self-contained. A generation can therefore be
// validated and swapped atomically without consulting a mutable route map.
type RouteRule struct {
	ID         string
	Revision   uint64
	Generation uint64
	// RouteID and RouteGeneration are the server-owned route identity. ID and
	// Revision may identify a custom-domain matcher alias and must never replace
	// the authoritative route tuple in access grants or carrier frames.
	RouteID         string
	RouteGeneration uint64
	// Assignment fields are present only for durable connector-v1 routes.
	// Generation is the local complete-snapshot generation used by the edge
	// matcher; ConfigGeneration is the server-owned connector config fence.
	AssignmentID               string
	AssignmentGeneration       uint64
	ResourceKind               string
	SessionGeneration          uint64
	Environment                string
	AccountID                  string
	HostID                     string
	MachineIdentityPublicKey   string
	MachineIdentityThumbprint  string
	TunnelID                   string
	ConnectorID                string
	ConnectorSessionID         string
	ConnectorProcessGeneration uint64
	ConfigGeneration           uint64
	ConfigContentHash          string
	Node                       string
	EdgeProcessEpoch           string
	EdgeFailureDomain          string
	Kind                       Kind
	MatchType                  string
	Hostname                   string
	WildcardSuffix             string
	PathPrefix                 string
	Priority                   int
	Target                     string
	Protocol                   string
	OriginScheme               string
	AccessMode                 string
	PreserveHost               bool
	HostOverride               string
	DesiredState               string
	ObservedState              string
	Reason                     string
}

type RouteMatch struct {
	Rule       RouteRule
	Host       string
	Path       string
	Generation uint64
}

// StreamLease fences a request to the generation that admitted it. Closing a
// generation cancels the lease context, while normal request cancellation
// releases the active-stream count automatically.
type StreamLease struct {
	ctx      context.Context
	cancel   context.CancelFunc
	registry *GenerationRegistry
	state    *generationState
	match    RouteMatch
	done     chan struct{}
	once     sync.Once
}

func (l *StreamLease) Context() context.Context { return l.ctx }

func (l *StreamLease) Match() RouteMatch { return l.match }

func (l *StreamLease) Done() <-chan struct{} { return l.done }

func (l *StreamLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}
		if l.registry != nil && l.state != nil {
			l.registry.release(l.state)
		}
		close(l.done)
	})
	return nil
}

type generationState struct {
	generation uint64
	rules      []RouteRule
	ctx        context.Context
	cancel     context.CancelFunc
	ready      bool
	accepting  bool
	streams    int
	drained    chan struct{}
	drainOnce  sync.Once
}

func newGenerationState(generation uint64, rules []RouteRule) *generationState {
	ctx, cancel := context.WithCancel(context.Background())
	return &generationState{generation: generation, rules: rules, ctx: ctx, cancel: cancel, drained: make(chan struct{})}
}

func (s *generationState) markDrained() {
	s.drainOnce.Do(func() {
		close(s.drained)
		s.cancel()
	})
}

// GenerationRegistry stages complete route generations and atomically
// promotes a ready generation. The old generation remains available only to
// already-acquired StreamLeases while it drains.
type GenerationRegistry struct {
	mu               sync.RWMutex
	maximumRoutes    int
	maximumStreams   int
	active           *generationState
	pending          *generationState
	closed           bool
	telemetrySink    RouteTelemetrySink
	telemetryClock   func() time.Time
	telemetryDropped atomic.Uint64
}

func NewGenerationRegistry(maximumRoutes int) *GenerationRegistry {
	registry, _ := NewGenerationRegistryWithOptions(maximumRoutes, GenerationRegistryOptions{})
	return registry
}

func NewGenerationRegistryWithOptions(maximumRoutes int, options GenerationRegistryOptions) (*GenerationRegistry, error) {
	if maximumRoutes <= 0 {
		maximumRoutes = DefaultMaximumRoutes
	}
	if options.MaximumStreams < 0 {
		return nil, ErrInvalid
	}
	if options.MaximumStreams == 0 {
		options.MaximumStreams = DefaultMaximumStreams
	}
	if options.TelemetryClock == nil {
		options.TelemetryClock = time.Now
	}
	return &GenerationRegistry{
		maximumRoutes: maximumRoutes, maximumStreams: options.MaximumStreams,
		telemetrySink: options.TelemetrySink, telemetryClock: options.TelemetryClock,
	}, nil
}

func (g *GenerationRegistry) TelemetryDrops() uint64 {
	if g == nil {
		return 0
	}
	return g.telemetryDropped.Load()
}

func (g *GenerationRegistry) emitStageRejection(generation uint64, rules []RouteRule, cause error) {
	g.emitLifecycle(LifecycleStageRejected, generation, 0, rules, 0)
	if errors.Is(cause, ErrGenerationStale) {
		g.emitLifecycle(LifecycleStaleRejected, generation, 0, rules, 0)
	}
}

func (g *GenerationRegistry) emitLifecycle(event LifecycleType, generation, previousGeneration uint64, rules []RouteRule, activeStreams int) {
	if g == nil || g.telemetrySink == nil {
		return
	}
	defer func() {
		if recover() != nil {
			g.telemetryDropped.Add(1)
		}
	}()
	at := g.telemetryClock()
	if at.IsZero() {
		g.telemetryDropped.Add(1)
		return
	}
	correlationID, ids, generations := routeTelemetryIdentity(generation, rules)
	record := RouteTelemetryRecord{
		At: at.UTC().Round(0), Type: event, Generation: generation, PreviousGeneration: previousGeneration,
		RouteCount: len(rules), ActiveStreams: activeStreams, MaximumStreams: g.maximumStreams,
		CorrelationID: correlationID, IDs: ids, Generations: generations,
	}
	if err := g.telemetrySink.RecordRouteTelemetry(record); err != nil {
		g.telemetryDropped.Add(1)
	}
}

func (g *GenerationRegistry) activeStreamCount(generation uint64) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.active != nil && g.active.generation == generation {
		return g.active.streams
	}
	return 0
}

func (g *GenerationRegistry) streamCount(state *generationState) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return state.streams
}

func rulesForTelemetryRule(rules []RouteRule, selected RouteRule) []RouteRule {
	for _, rule := range rules {
		if rule.ID == selected.ID {
			return []RouteRule{rule}
		}
	}
	return []RouteRule{selected}
}

func (g *GenerationRegistry) StageGeneration(generation uint64, rules []RouteRule) error {
	if g == nil {
		return ErrGenerationClosed
	}
	if generation == 0 {
		g.emitStageRejection(generation, rules, ErrInvalid)
		return ErrInvalid
	}
	normalized, err := normalizeRules(generation, rules, g.maximumRoutes)
	if err != nil {
		g.emitStageRejection(generation, rules, err)
		return err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.emitStageRejection(generation, normalized, ErrGenerationClosed)
		return ErrGenerationClosed
	}
	if g.active != nil {
		switch {
		case generation < g.active.generation:
			g.mu.Unlock()
			g.emitStageRejection(generation, normalized, ErrGenerationStale)
			return ErrGenerationStale
		case generation == g.active.generation:
			if reflect.DeepEqual(g.active.rules, normalized) {
				g.mu.Unlock()
				g.emitLifecycle(LifecycleStageAccepted, generation, 0, normalized, 0)
				return nil
			}
			g.mu.Unlock()
			g.emitStageRejection(generation, normalized, ErrGenerationConflict)
			return ErrGenerationConflict
		}
	}
	if g.pending != nil {
		switch {
		case generation < g.pending.generation:
			g.mu.Unlock()
			g.emitStageRejection(generation, normalized, ErrGenerationStale)
			return ErrGenerationStale
		case generation == g.pending.generation:
			if reflect.DeepEqual(g.pending.rules, normalized) {
				g.mu.Unlock()
				g.emitLifecycle(LifecycleStageAccepted, generation, 0, normalized, 0)
				return nil
			}
			g.mu.Unlock()
			g.emitStageRejection(generation, normalized, ErrGenerationConflict)
			return ErrGenerationConflict
		default:
			g.pending.cancel()
		}
	}
	g.pending = newGenerationState(generation, normalized)
	g.mu.Unlock()
	g.emitLifecycle(LifecycleStageAccepted, generation, 0, normalized, 0)
	return nil
}

func (g *GenerationRegistry) MarkGenerationReady(generation uint64) error {
	if g == nil {
		return ErrGenerationClosed
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrGenerationClosed
	}
	if g.active != nil && g.active.generation == generation {
		rules := g.active.rules
		g.mu.Unlock()
		g.emitLifecycle(LifecycleGenerationReady, generation, 0, rules, 0)
		return nil
	}
	if g.pending == nil || g.pending.generation != generation {
		if g.pending != nil && generation < g.pending.generation || g.active != nil && generation <= g.active.generation {
			g.mu.Unlock()
			g.emitLifecycle(LifecycleStaleRejected, generation, 0, nil, 0)
			return ErrGenerationStale
		}
		g.mu.Unlock()
		return ErrGenerationNotReady
	}
	g.pending.ready = true
	rules := g.pending.rules
	g.mu.Unlock()
	g.emitLifecycle(LifecycleGenerationReady, generation, 0, rules, 0)
	return nil
}

// ActivateGeneration makes a ready generation the sole admission source and
// waits for the previous generation's active streams to drain. A timeout
// force-cancels old streams but leaves the new generation active.
func (g *GenerationRegistry) ActivateGeneration(ctx context.Context, generation uint64, drainTimeout time.Duration) error {
	if g == nil {
		return ErrGenerationClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrGenerationClosed
	}
	if g.active != nil && g.active.generation == generation && g.pending == nil {
		rules := g.active.rules
		g.mu.Unlock()
		g.emitLifecycle(LifecycleActivated, generation, 0, rules, g.activeStreamCount(generation))
		return nil
	}
	if g.pending == nil || g.pending.generation != generation {
		if g.active != nil && generation < g.active.generation || g.pending != nil && generation < g.pending.generation {
			g.mu.Unlock()
			g.emitLifecycle(LifecycleStaleRejected, generation, 0, nil, 0)
			return ErrGenerationStale
		}
		g.mu.Unlock()
		return ErrGenerationNotReady
	}
	if !g.pending.ready {
		g.mu.Unlock()
		return ErrGenerationNotReady
	}
	old := g.active
	newState := g.pending
	newState.accepting = true
	g.active = newState
	g.pending = nil
	immediatelyDrained := false
	oldStreams := 0
	newStreams := newState.streams
	if old != nil {
		old.accepting = false
		oldStreams = old.streams
		if old.streams == 0 {
			immediatelyDrained = true
		}
	}
	g.mu.Unlock()
	previousGeneration := uint64(0)
	if old != nil {
		previousGeneration = old.generation
	}
	g.emitLifecycle(LifecycleActivated, newState.generation, previousGeneration, newState.rules, newStreams)
	if old == nil {
		return nil
	}
	g.emitLifecycle(LifecycleDrainStarted, old.generation, newState.generation, old.rules, oldStreams)
	if immediatelyDrained {
		old.markDrained()
		g.emitLifecycle(LifecycleDrainCompleted, old.generation, newState.generation, old.rules, 0)
		return nil
	}
	timer := time.NewTimer(drainTimeout)
	defer timer.Stop()
	select {
	case <-old.drained:
		g.emitLifecycle(LifecycleDrainCompleted, old.generation, newState.generation, old.rules, 0)
		return nil
	case <-ctx.Done():
		activeStreams := g.streamCount(old)
		g.emitLifecycle(LifecycleDrainForced, old.generation, newState.generation, old.rules, activeStreams)
		old.cancel()
		return ctx.Err()
	case <-timer.C:
		activeStreams := g.streamCount(old)
		g.emitLifecycle(LifecycleDrainForced, old.generation, newState.generation, old.rules, activeStreams)
		old.cancel()
		return ErrDrainTimeout
	}
}

// ApplyGeneration is the safe high-level handoff. The callback must confirm
// actual edge/origin readiness; nil is rejected to prevent fake activation.
func (g *GenerationRegistry) ApplyGeneration(ctx context.Context, generation uint64, rules []RouteRule, ready func(context.Context, []RouteRule) error, drainTimeout time.Duration) error {
	if ready == nil {
		return ErrGenerationNotReady
	}
	if err := g.StageGeneration(generation, rules); err != nil {
		return err
	}
	normalized, err := normalizeRules(generation, rules, g.maximumRoutes)
	if err != nil {
		return err
	}
	if err := ready(ctx, normalized); err != nil {
		g.discardPending(generation)
		g.emitLifecycle(LifecycleStageRejected, generation, 0, normalized, 0)
		return err
	}
	if err := g.MarkGenerationReady(generation); err != nil {
		return err
	}
	return g.ActivateGeneration(ctx, generation, drainTimeout)
}

func (g *GenerationRegistry) discardPending(generation uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending != nil && g.pending.generation == generation {
		g.pending.cancel()
		g.pending = nil
	}
}

func (g *GenerationRegistry) Match(host, requestPath string) (RouteMatch, error) {
	if g == nil {
		return RouteMatch{}, ErrNoMatch
	}
	host, err := normalizeMatchHost(host)
	if err != nil {
		return RouteMatch{}, ErrNoMatch
	}
	requestPath, err = normalizeRequestPath(requestPath)
	if err != nil {
		return RouteMatch{}, ErrNoMatch
	}
	g.mu.RLock()
	active := g.active
	if active == nil || !active.accepting {
		g.mu.RUnlock()
		return RouteMatch{}, ErrNoMatch
	}
	rules := active.rules
	generation := active.generation
	g.mu.RUnlock()
	rule, err := chooseRule(rules, host, requestPath)
	if err != nil {
		return RouteMatch{}, err
	}
	return RouteMatch{Rule: rule, Host: host, Path: requestPath, Generation: generation}, nil
}

func (g *GenerationRegistry) Acquire(ctx context.Context, host, requestPath string) (*StreamLease, RouteMatch, error) {
	if g == nil {
		return nil, RouteMatch{}, ErrNoMatch
	}
	if ctx == nil {
		ctx = context.Background()
	}
	host, err := normalizeMatchHost(host)
	if err != nil {
		return nil, RouteMatch{}, ErrNoMatch
	}
	requestPath, err = normalizeRequestPath(requestPath)
	if err != nil {
		return nil, RouteMatch{}, ErrNoMatch
	}
	g.mu.Lock()
	active := g.active
	if active == nil || !active.accepting {
		g.mu.Unlock()
		return nil, RouteMatch{}, ErrNoMatch
	}
	rule, err := chooseRule(active.rules, host, requestPath)
	if err != nil {
		g.mu.Unlock()
		return nil, RouteMatch{}, err
	}
	if active.streams >= g.maximumStreams {
		activeStreams := active.streams
		generation := active.generation
		rules := active.rules
		g.mu.Unlock()
		g.emitLifecycle(LifecycleStreamOverloaded, generation, 0, rulesForTelemetryRule(rules, rule), activeStreams)
		return nil, RouteMatch{}, ErrStreamOverloaded
	}
	active.streams++
	activeStreams := active.streams
	generation := active.generation
	g.mu.Unlock()
	streamCtx, cancel := context.WithCancel(ctx)
	lease := &StreamLease{ctx: streamCtx, cancel: cancel, registry: g, state: active, match: RouteMatch{Rule: rule, Host: host, Path: requestPath, Generation: active.generation}, done: make(chan struct{})}
	g.emitLifecycle(LifecycleStreamAcquired, generation, 0, []RouteRule{rule}, activeStreams)
	go func() {
		select {
		case <-streamCtx.Done():
			_ = lease.Close()
		case <-active.ctx.Done():
			_ = lease.Close()
		}
	}()
	return lease, lease.match, nil
}

func (g *GenerationRegistry) release(state *generationState) {
	g.mu.Lock()
	if state.streams > 0 {
		state.streams--
	}
	activeStreams := state.streams
	drained := !state.accepting && state.streams == 0
	g.mu.Unlock()
	g.emitLifecycle(LifecycleStreamReleased, state.generation, 0, state.rules, activeStreams)
	if drained {
		state.markDrained()
	}
}

func (g *GenerationRegistry) RouteState(host string) (string, string, string, bool) {
	host, err := normalizeMatchHost(host)
	if err != nil {
		return "", "", "", false
	}
	g.mu.RLock()
	active := g.active
	if active == nil || !active.accepting {
		g.mu.RUnlock()
		return "", "", "", false
	}
	rules := active.rules
	g.mu.RUnlock()
	rule, ok := chooseHostRule(rules, host)
	if !ok {
		return "", "", "", false
	}
	state := rule.ObservedState
	if state == "" {
		state = "ready"
	}
	return string(rule.Kind), state, rule.Reason, true
}

func (g *GenerationRegistry) HasActiveGeneration() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active != nil && g.active.accepting
}

func (g *GenerationRegistry) Generation() uint64 {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.active == nil || !g.active.accepting {
		return 0
	}
	return g.active.generation
}

func (g *GenerationRegistry) Snapshot() (uint64, []RouteRule, bool) {
	if g == nil {
		return 0, nil, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.active == nil || !g.active.accepting {
		return 0, nil, false
	}
	rules := append([]RouteRule(nil), g.active.rules...)
	return g.active.generation, rules, true
}

func (g *GenerationRegistry) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	if g.pending != nil {
		g.pending.cancel()
	}
	if g.active != nil {
		g.active.cancel()
		g.active.markDrained()
	}
	g.mu.Unlock()
	return nil
}

func normalizeRules(generation uint64, rules []RouteRule, maximum int) ([]RouteRule, error) {
	if len(rules) > maximum {
		return nil, ErrInvalid
	}
	result := make([]RouteRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		normalized, err := normalizeRule(generation, rule)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized.ID]; exists {
			return nil, ErrMatchConflict
		}
		seen[normalized.ID] = struct{}{}
		result = append(result, normalized)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	for left := 0; left < len(result); left++ {
		for right := left + 1; right < len(result); right++ {
			if !rulesOverlap(result[left], result[right]) {
				continue
			}
			leftClass, leftLabels, _ := hostMatch(result[left], overlapHost(result[left]))
			rightClass, rightLabels, _ := hostMatch(result[right], overlapHost(result[right]))
			if compareCandidates(routeCandidate{rule: result[left], hostClass: leftClass, suffixLabels: leftLabels}, routeCandidate{rule: result[right], hostClass: rightClass, suffixLabels: rightLabels}) == 0 {
				return nil, ErrMatchConflict
			}
		}
	}
	return result, nil
}

func rulesOverlap(left, right RouteRule) bool {
	if !hostsOverlap(left, right) {
		return false
	}
	return pathMatches(left.PathPrefix, right.PathPrefix) || pathMatches(right.PathPrefix, left.PathPrefix)
}

func hostsOverlap(left, right RouteRule) bool {
	if left.MatchType == MatchCatchAll || right.MatchType == MatchCatchAll {
		return true
	}
	if isExactMatchType(left.MatchType) && isExactMatchType(right.MatchType) {
		return left.Hostname == right.Hostname
	}
	if left.MatchType == MatchOneLabelWildcard && right.MatchType == MatchOneLabelWildcard {
		return left.WildcardSuffix == right.WildcardSuffix
	}
	if isExactMatchType(left.MatchType) && right.MatchType == MatchOneLabelWildcard {
		return exactFallsUnderWildcard(left.Hostname, right.WildcardSuffix)
	}
	if isExactMatchType(right.MatchType) && left.MatchType == MatchOneLabelWildcard {
		return exactFallsUnderWildcard(right.Hostname, left.WildcardSuffix)
	}
	return false
}

func isExactMatchType(matchType string) bool {
	return matchType == MatchExact || matchType == MatchManagedExact
}

func exactFallsUnderWildcard(host, suffix string) bool {
	if host == suffix || !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	return !strings.Contains(strings.TrimSuffix(host, "."+suffix), ".")
}

func overlapHost(rule RouteRule) string {
	switch rule.MatchType {
	case MatchExact, MatchManagedExact:
		return rule.Hostname
	case MatchOneLabelWildcard:
		return "edge." + rule.WildcardSuffix
	default:
		return "edge.example.test"
	}
}

func normalizeRule(generation uint64, rule RouteRule) (RouteRule, error) {
	if rule.ID == "" || strings.ContainsAny(rule.ID, "\r\n\x00") {
		return RouteRule{}, ErrInvalid
	}
	if rule.Generation == 0 {
		rule.Generation = generation
	}
	if rule.Generation != generation {
		return RouteRule{}, ErrInvalid
	}
	if rule.Kind != HelperHTTPSWSS && rule.Kind != PreviewHTTPSWSS && rule.Kind != TunnelHTTPSWSS {
		return RouteRule{}, ErrInvalid
	}
	matchType := strings.ToLower(strings.TrimSpace(rule.MatchType))
	if matchType == "" {
		matchType = MatchExact
	}
	switch matchType {
	case MatchExact, MatchManagedExact:
		if rule.Hostname == "" && rule.WildcardSuffix != "" {
			return RouteRule{}, ErrInvalid
		}
		if strings.Contains(rule.Hostname, "*") || strings.Contains(rule.WildcardSuffix, "*") {
			return RouteRule{}, ErrInvalid
		}
		host, err := normalizeMatchHost(rule.Hostname)
		if err != nil || host == "" || net.ParseIP(host) != nil {
			return RouteRule{}, ErrInvalid
		}
		if matchType == MatchManagedExact && rule.Kind == TunnelHTTPSWSS && !ValidOpaqueTunnelHostname(host) {
			return RouteRule{}, ErrInvalid
		}
		rule.Hostname, rule.WildcardSuffix = host, ""
	case MatchOneLabelWildcard:
		suffix := rule.WildcardSuffix
		if suffix == "" && strings.HasPrefix(rule.Hostname, "*.") {
			suffix = strings.TrimPrefix(rule.Hostname, "*.")
		}
		if suffix == "" || strings.Contains(suffix, "*") {
			return RouteRule{}, ErrInvalid
		}
		suffix, err := normalizeMatchHost(suffix)
		if err != nil || suffix == "" || net.ParseIP(suffix) != nil || !strings.Contains(suffix, ".") {
			return RouteRule{}, ErrInvalid
		}
		rule.Hostname, rule.WildcardSuffix = "", suffix
	case MatchCatchAll:
		if rule.Hostname != "" || rule.WildcardSuffix != "" {
			return RouteRule{}, ErrInvalid
		}
		rule.Hostname = ""
		rule.WildcardSuffix = ""
	default:
		return RouteRule{}, ErrInvalid
	}
	pathPrefix, err := normalizeRequestPath(rule.PathPrefix)
	if err != nil {
		return RouteRule{}, ErrInvalid
	}
	rule.MatchType = matchType
	rule.PathPrefix = pathPrefix
	if rule.DesiredState == "" {
		rule.DesiredState = "active"
	}
	switch rule.DesiredState {
	case "active", "ready", "degraded", "offline", "registering", "disabled", "deleted", "expired", "removed":
	default:
		return RouteRule{}, ErrInvalid
	}
	if rule.HostOverride != "" && strings.ContainsAny(rule.HostOverride, "\r\n\x00/?# \t") {
		return RouteRule{}, ErrInvalid
	}
	if rule.OriginScheme != "" {
		switch strings.ToLower(rule.OriginScheme) {
		case "http", "https", "h2c", "unix":
			rule.OriginScheme = strings.ToLower(rule.OriginScheme)
		default:
			return RouteRule{}, ErrInvalid
		}
	}
	if rule.Target == "" || strings.ContainsAny(rule.Target, "\r\n\x00") {
		return RouteRule{}, ErrInvalid
	}
	if rule.Kind == TunnelHTTPSWSS {
		// Durable tunnel assignments carry an opaque route binding. The edge
		// must resolve it through an authenticated datacarrier, so never parse
		// or dial Target as an origin address here.
		if strings.ContainsAny(rule.Target, " \t?#") {
			return RouteRule{}, ErrInvalid
		}
		return rule, nil
	}
	if rule.OriginScheme == "unix" {
		if !strings.HasPrefix(rule.Target, "/") || strings.ContainsAny(rule.Target, "?#") {
			return RouteRule{}, ErrInvalid
		}
	} else if rule.OriginScheme != "" {
		if _, _, err := net.SplitHostPort(rule.Target); err != nil {
			return RouteRule{}, ErrInvalid
		}
	}
	return rule, nil
}

func normalizeMatchHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "\r\n\x00 /?") {
		return "", ErrInvalid
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else if strings.Count(host, ":") > 0 {
		return "", ErrInvalid
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || net.ParseIP(host) != nil {
		return "", ErrInvalid
	}
	if !utf8.ValidString(host) {
		return "", ErrInvalid
	}
	if !utf8.ValidString(host) {
		return "", ErrInvalid
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" || len(ascii) > 253 || strings.Contains(ascii, "..") {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
	}
	return strings.ToLower(ascii), nil
}

func normalizeRequestPath(requestPath string) (string, error) {
	if requestPath == "" {
		return "/", nil
	}
	if !strings.HasPrefix(requestPath, "/") || strings.ContainsAny(requestPath, "\r\n\x00?#") || strings.Contains(requestPath, "//") {
		return "", ErrInvalid
	}
	for _, segment := range strings.Split(requestPath, "/") {
		if segment == "." || segment == ".." {
			return "", ErrInvalid
		}
	}
	if len(requestPath) > 1 {
		requestPath = strings.TrimSuffix(requestPath, "/")
	}
	return requestPath, nil
}

type routeCandidate struct {
	rule         RouteRule
	hostClass    int
	suffixLabels int
}

func chooseRule(rules []RouteRule, host, requestPath string) (RouteRule, error) {
	var best routeCandidate
	found := false
	for _, rule := range rules {
		if rule.DesiredState == "disabled" || rule.DesiredState == "deleted" || rule.DesiredState == "expired" || rule.DesiredState == "removed" {
			continue
		}
		class, labels, ok := hostMatch(rule, host)
		if !ok || !pathMatches(rule.PathPrefix, requestPath) {
			continue
		}
		candidate := routeCandidate{rule: rule, hostClass: class, suffixLabels: labels}
		if !found {
			best, found = candidate, true
			continue
		}
		comparison := compareCandidates(candidate, best)
		if comparison > 0 {
			best = candidate
		} else if comparison == 0 {
			return RouteRule{}, ErrMatchConflict
		}
	}
	if !found {
		return RouteRule{}, ErrNoMatch
	}
	return best.rule, nil
}

func chooseHostRule(rules []RouteRule, host string) (RouteRule, bool) {
	var best routeCandidate
	found := false
	for _, rule := range rules {
		if rule.DesiredState == "disabled" || rule.DesiredState == "deleted" || rule.DesiredState == "expired" || rule.DesiredState == "removed" {
			continue
		}
		class, labels, ok := hostMatch(rule, host)
		if !ok {
			continue
		}
		candidate := routeCandidate{rule: rule, hostClass: class, suffixLabels: labels}
		if !found || compareHostCandidates(candidate, best) > 0 {
			best, found = candidate, true
		}
	}
	return best.rule, found
}

func hostMatch(rule RouteRule, host string) (int, int, bool) {
	switch rule.MatchType {
	case MatchExact, MatchManagedExact:
		return 3, 0, host == rule.Hostname
	case MatchOneLabelWildcard:
		if host == rule.WildcardSuffix || !strings.HasSuffix(host, "."+rule.WildcardSuffix) {
			return 0, 0, false
		}
		prefix := strings.TrimSuffix(host, "."+rule.WildcardSuffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return 0, 0, false
		}
		return 2, strings.Count(rule.WildcardSuffix, ".") + 1, true
	case MatchCatchAll:
		return 1, 0, true
	default:
		return 0, 0, false
	}
}

func compareCandidates(left, right routeCandidate) int {
	if left.hostClass != right.hostClass {
		return compareInt(left.hostClass, right.hostClass)
	}
	if left.suffixLabels != right.suffixLabels {
		return compareInt(left.suffixLabels, right.suffixLabels)
	}
	if len(left.rule.PathPrefix) != len(right.rule.PathPrefix) {
		return compareInt(len(left.rule.PathPrefix), len(right.rule.PathPrefix))
	}
	if left.rule.Priority != right.rule.Priority {
		// Lower priority numbers are preferred.
		if left.rule.Priority < right.rule.Priority {
			return 1
		}
		return -1
	}
	return 0
}

func compareHostCandidates(left, right routeCandidate) int {
	if left.hostClass != right.hostClass {
		return compareInt(left.hostClass, right.hostClass)
	}
	if left.suffixLabels != right.suffixLabels {
		return compareInt(left.suffixLabels, right.suffixLabels)
	}
	if left.rule.Priority != right.rule.Priority {
		if left.rule.Priority < right.rule.Priority {
			return 1
		}
		return -1
	}
	return 0
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func pathMatches(prefix, requestPath string) bool {
	if prefix == "/" {
		return true
	}
	return requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}

func attachmentToRule(a Attachment) RouteRule {
	generation := a.ConfigGeneration
	if generation == 0 {
		generation = a.Generation
	}
	matchType := a.MatchType
	hostname := a.Host
	wildcardSuffix := a.WildcardSuffix
	if matchType == "" {
		matchType = MatchExact
	}
	if matchType == MatchOneLabelWildcard && wildcardSuffix == "" {
		wildcardSuffix = strings.TrimPrefix(hostname, "*.")
		hostname = ""
	}
	state := a.PreviewState
	return RouteRule{ID: a.ID, Revision: a.Revision, Generation: generation, Environment: a.Environment, Node: a.Node, Kind: a.Kind, MatchType: matchType, Hostname: hostname, WildcardSuffix: wildcardSuffix, PathPrefix: a.PathPrefix, Priority: a.Priority, Target: a.Target, Protocol: a.Protocol, OriginScheme: a.OriginScheme, PreserveHost: a.PreserveHost, HostOverride: a.HostOverride, DesiredState: a.DesiredState, ObservedState: state, Reason: a.PreviewReason}
}

func newNoopStreamLease(ctx context.Context, match RouteMatch) *StreamLease {
	if ctx == nil {
		ctx = context.Background()
	}
	streamCtx, cancel := context.WithCancel(ctx)
	return &StreamLease{ctx: streamCtx, cancel: cancel, match: match, done: make(chan struct{})}
}

// NewStreamLease creates a request-scoped lease for an external route owner.
// The owner is responsible for generation fencing; this constructor is used
// by exact-host registries that are not backed by GenerationRegistry's route
// table (for example the authenticated preview carrier registry).
func NewStreamLease(ctx context.Context, match RouteMatch) *StreamLease {
	return newNoopStreamLease(ctx, match)
}
