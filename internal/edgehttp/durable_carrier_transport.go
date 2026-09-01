package edgehttp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

const (
	defaultDataCarrierRouteOpenTimeout = 10 * time.Second
	maximumDataCarrierRoutes           = 4096
	maximumDataCarrierProbeHeader      = 64 << 10
)

var (
	ErrDataCarrierRouteInvalid     = errors.New("invalid durable data-carrier route")
	ErrDataCarrierRouteUnavailable = errors.New("durable data-carrier route is unavailable")
	ErrDataCarrierRouteTransport   = errors.New("durable data-carrier route transport failed")
)

// DataCarrierRouteRegistry owns the edge's authenticated connector sessions.
// A single connector carrier may serve many route assignments; assignments
// select it by the complete connector/session/process/config identity tuple.
// It never stores or accepts a host-local origin address.
type DataCarrierRouteRegistry struct {
	maximum int
	done    chan struct{}
	once    sync.Once
	mu      sync.RWMutex
	closed  bool
	byKey   map[string]*dataCarrierRouteEntry
}

type dataCarrierRouteEntry struct {
	identity                  datacarrier.Identity
	machineIdentityPublicKey  string
	machineIdentityThumbprint string
	server                    *datacarrier.Server
	done                      chan struct{}
	once                      sync.Once
	state                     ReplicaState
}

// ReplicaState is the edge-local, secret-free selection observation for one
// authenticated connector session. RouteIDs is the exact admission set for
// this carrier. Updates replace the complete observation atomically.
type ReplicaState struct {
	Ready         bool
	Generation    uint64
	RouteIDs      []string
	HealthyRoutes []string
	RouteBindings []ReplicaRouteBinding
	FailureDomain string
	Latency       time.Duration
	Capacity      uint32
}

// ReplicaRouteBinding retains the immutable server assignment tuple for one
// route on a replica. RouteIDs alone are insufficient because a stale or
// forged route rule can reuse the same route ID across assignment changes.
type ReplicaRouteBinding struct {
	RouteID              string
	AssignmentID         string
	AssignmentGeneration uint64
	RouteGeneration      uint64
	ConfigContentHash    string
}

type DataCarrierRouteRegistryConfig struct {
	MaximumRoutes int
}

func NewDataCarrierRouteRegistry(config DataCarrierRouteRegistryConfig) (*DataCarrierRouteRegistry, error) {
	if config.MaximumRoutes == 0 {
		config.MaximumRoutes = maximumDataCarrierRoutes
	}
	if config.MaximumRoutes < 1 || config.MaximumRoutes > maximumDataCarrierRoutes {
		return nil, ErrDataCarrierRouteInvalid
	}
	return &DataCarrierRouteRegistry{maximum: config.MaximumRoutes, done: make(chan struct{}), byKey: make(map[string]*dataCarrierRouteEntry)}, nil
}

// Attach registers one already-authenticated server. The Server identity is
// authoritative; caller-supplied route metadata cannot broaden it.
func (r *DataCarrierRouteRegistry) Attach(server *datacarrier.Server) error {
	return r.attach(server, "", "")
}

// AttachBound registers one authenticated server together with the exact
// enrolled machine verifier material that admitted it. Production durable
// routes use this method so a same-identity replacement cannot accidentally
// reuse an older carrier while the new key is being installed.
func (r *DataCarrierRouteRegistry) AttachBound(server *datacarrier.Server, machineIdentityPublicKey, machineIdentityThumbprint string) error {
	if machineIdentityPublicKey == "" || machineIdentityThumbprint == "" {
		return ErrDataCarrierRouteInvalid
	}
	return r.attach(server, machineIdentityPublicKey, machineIdentityThumbprint)
}

// AttachReplica registers a carrier with its exact route compatibility and
// current health. It is the production multi-connector entry point.
func (r *DataCarrierRouteRegistry) AttachReplica(server *datacarrier.Server, machineIdentityPublicKey, machineIdentityThumbprint string, state ReplicaState) error {
	if err := validateReplicaState(server, state); err != nil {
		return err
	}
	return r.attachState(server, machineIdentityPublicKey, machineIdentityThumbprint, state)
}

func (r *DataCarrierRouteRegistry) attach(server *datacarrier.Server, machineIdentityPublicKey, machineIdentityThumbprint string) error {
	state := ReplicaState{}
	if server != nil {
		state.Generation = server.Identity().Generation
	}
	return r.attachState(server, machineIdentityPublicKey, machineIdentityThumbprint, state)
}

func (r *DataCarrierRouteRegistry) attachState(server *datacarrier.Server, machineIdentityPublicKey, machineIdentityThumbprint string, state ReplicaState) error {
	if r == nil || server == nil {
		return ErrDataCarrierRouteInvalid
	}
	identity := server.Identity()
	if err := identity.Validate(); err != nil {
		return ErrDataCarrierRouteInvalid
	}
	entry := &dataCarrierRouteEntry{identity: identity, machineIdentityPublicKey: machineIdentityPublicKey, machineIdentityThumbprint: machineIdentityThumbprint, server: server, done: make(chan struct{}), state: normalizeReplicaState(state)}
	key := carrierRouteIdentityKey(identity)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrDataCarrierRouteUnavailable
	}
	old := r.byKey[key]
	if old != nil {
		if old.server == server {
			if old.machineIdentityPublicKey != "" && (old.machineIdentityPublicKey != machineIdentityPublicKey || old.machineIdentityThumbprint != machineIdentityThumbprint) {
				r.mu.Unlock()
				return ErrDataCarrierRouteUnavailable
			}
			old.machineIdentityPublicKey = machineIdentityPublicKey
			old.machineIdentityThumbprint = machineIdentityThumbprint
			r.mu.Unlock()
			return nil
		}
		old.once.Do(func() { close(old.done) })
	}
	if old == nil && len(r.byKey) >= r.maximum {
		r.mu.Unlock()
		return ErrDataCarrierRouteInvalid
	}
	r.byKey[key] = entry
	r.mu.Unlock()
	go r.watch(entry, key)
	return nil
}

// UpdateReplicaState applies an observation only to the exact live session.
// A delayed observation from an overlapping old session cannot mutate its
// replacement, even when both share connector and host identity.
func (r *DataCarrierRouteRegistry) UpdateReplicaState(server *datacarrier.Server, state ReplicaState) error {
	if err := validateReplicaState(server, state); err != nil {
		return err
	}
	key := carrierRouteIdentityKey(server.Identity())
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.byKey[key]
	if entry == nil || entry.server != server {
		return ErrDataCarrierRouteUnavailable
	}
	entry.state = normalizeReplicaState(state)
	return nil
}

func (r *DataCarrierRouteRegistry) recordOpenLatency(entry *dataCarrierRouteEntry, sample time.Duration) {
	if r == nil || entry == nil || sample <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.byKey[carrierRouteIdentityKey(entry.identity)]
	if current != entry || len(entry.state.RouteIDs) == 0 {
		return
	}
	if entry.state.Latency <= 0 {
		entry.state.Latency = sample
	} else {
		// Bounded EWMA smooths transient setup jitter without making a dead
		// carrier sticky; readiness and stream failures remain hard gates.
		entry.state.Latency = (entry.state.Latency*7 + sample) / 8
	}
}

func validateReplicaState(server *datacarrier.Server, state ReplicaState) error {
	if server == nil || state.Generation == 0 || state.Generation != server.Identity().Generation || state.FailureDomain == "" || state.Latency < 0 || state.Capacity == 0 {
		return ErrDataCarrierRouteInvalid
	}
	if len(state.RouteIDs) == 0 || len(state.RouteIDs) > maximumDataCarrierRoutes || len(state.HealthyRoutes) > len(state.RouteIDs) || len(state.RouteBindings) != len(state.RouteIDs) {
		return ErrDataCarrierRouteInvalid
	}
	seen := make(map[string]bool, len(state.RouteIDs))
	for _, id := range state.RouteIDs {
		if connectorprotocol.ValidateIdentifier(id) != nil || seen[id] {
			return ErrDataCarrierRouteInvalid
		}
		seen[id] = true
	}
	for _, id := range state.HealthyRoutes {
		if !seen[id] {
			return ErrDataCarrierRouteInvalid
		}
	}
	bindingSeen := make(map[string]bool, len(state.RouteBindings))
	for _, binding := range state.RouteBindings {
		if !seen[binding.RouteID] || bindingSeen[binding.RouteID] || connectorprotocol.ValidateIdentifier(binding.AssignmentID) != nil || binding.AssignmentGeneration == 0 || binding.RouteGeneration == 0 || !validRouteContentHash(binding.ConfigContentHash) {
			return ErrDataCarrierRouteInvalid
		}
		bindingSeen[binding.RouteID] = true
	}
	return nil
}

func normalizeReplicaState(state ReplicaState) ReplicaState {
	state.RouteIDs = append([]string(nil), state.RouteIDs...)
	state.HealthyRoutes = append([]string(nil), state.HealthyRoutes...)
	state.RouteBindings = append([]ReplicaRouteBinding(nil), state.RouteBindings...)
	sort.Strings(state.RouteIDs)
	sort.Strings(state.HealthyRoutes)
	sort.Slice(state.RouteBindings, func(i, j int) bool { return state.RouteBindings[i].RouteID < state.RouteBindings[j].RouteID })
	return state
}

func validRouteContentHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func (r *DataCarrierRouteRegistry) watch(entry *dataCarrierRouteEntry, key string) {
	if entry == nil || entry.server == nil {
		return
	}
	select {
	case <-entry.server.Done():
		r.detach(entry, key)
	case <-entry.done:
	case <-r.done:
	}
}

func (r *DataCarrierRouteRegistry) detach(entry *dataCarrierRouteEntry, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.byKey[key]; current == entry {
		delete(r.byKey, key)
		entry.once.Do(func() { close(entry.done) })
	}
}

// Detach is pointer-fenced so a closed/replaced carrier cannot remove a new
// session that happens to share a connector identity prefix.
func (r *DataCarrierRouteRegistry) Detach(server *datacarrier.Server) error {
	if r == nil || server == nil {
		return ErrDataCarrierRouteInvalid
	}
	key := carrierRouteIdentityKey(server.Identity())
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.byKey[key]
	if entry == nil {
		return nil
	}
	if entry.server != server {
		return ErrDataCarrierRouteUnavailable
	}
	delete(r.byKey, key)
	entry.once.Do(func() { close(entry.done) })
	return nil
}

// Handle owns only the registry registration. CarrierAssembly remains the
// owner that closes the server after this wait returns.
func (r *DataCarrierRouteRegistry) Handle(ctx context.Context, server *datacarrier.Server) error {
	if ctx == nil || server == nil {
		return ErrDataCarrierRouteInvalid
	}
	if err := r.Attach(server); err != nil {
		return err
	}
	defer func() { _ = r.Detach(server) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-server.Done():
		return nil
	case <-r.done:
		return ErrDataCarrierRouteUnavailable
	}
}

func (r *DataCarrierRouteRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		for key, entry := range r.byKey {
			delete(r.byKey, key)
			entry.once.Do(func() { close(entry.done) })
		}
		r.mu.Unlock()
		close(r.done)
	})
	return nil
}

func (r *DataCarrierRouteRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byKey)
}

func carrierRouteIdentityKey(identity datacarrier.Identity) string {
	return strings.Join([]string{identity.AccountID, identity.HostID, identity.TunnelID, identity.ConnectorID, identity.SessionID, fmt.Sprint(identity.ProcessGeneration), fmt.Sprint(identity.Generation)}, "\x00")
}

func (r *DataCarrierRouteRegistry) entryFor(rule route.RouteRule, requestID string) (*dataCarrierRouteEntry, error) {
	if r == nil || rule.Kind != route.TunnelHTTPSWSS && rule.Kind != route.TunnelPrivateTCP || rule.AccountID == "" || rule.HostID == "" || rule.TunnelID == "" || rule.ConnectorID == "" || rule.ConnectorSessionID == "" || rule.ConnectorProcessGeneration == 0 || rule.ConfigGeneration == 0 {
		return nil, ErrDataCarrierRouteInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var eligible []*dataCarrierRouteEntry
	for _, entry := range r.byKey {
		if entry == nil || entry.server == nil || entry.identity.AccountID != rule.AccountID || entry.identity.TunnelID != rule.TunnelID {
			continue
		}
		select {
		case <-entry.server.Done():
			continue
		default:
		}
		// Legacy exact assignments remain usable until their admission metadata
		// is refreshed into replica state.
		if len(entry.state.RouteIDs) == 0 {
			if entry.identity.HostID == rule.HostID && entry.identity.ConnectorID == rule.ConnectorID && entry.identity.SessionID == rule.ConnectorSessionID && entry.identity.ProcessGeneration == rule.ConnectorProcessGeneration && entry.identity.Generation == rule.ConfigGeneration && (rule.MachineIdentityPublicKey == "" || entry.machineIdentityPublicKey == rule.MachineIdentityPublicKey && entry.machineIdentityThumbprint == rule.MachineIdentityThumbprint) {
				eligible = append(eligible, entry)
			}
			continue
		}
		routeID := carrierRouteID(rule)
		binding, bindingOK := replicaRouteBinding(entry.state.RouteBindings, routeID)
		// The matcher owns one route-level rule while the registry owns every
		// replica-specific assignment. Do not pin selection to the representative
		// connector embedded in the matcher rule; instead require each candidate's
		// authoritative server-issued binding to match the immutable route/config
		// tuple. The entry identity and verifier material were already authenticated
		// when this binding was attached.
		if !entry.state.Ready || entry.state.Generation != rule.ConfigGeneration || entry.identity.Generation != rule.ConfigGeneration || !sortedContains(entry.state.RouteIDs, routeID) || !sortedContains(entry.state.HealthyRoutes, routeID) || !bindingOK || binding.RouteGeneration != rule.RouteGeneration || binding.ConfigContentHash != rule.ConfigContentHash || uint32(entry.server.ActiveStreams()) >= entry.state.Capacity {
			continue
		}
		eligible = append(eligible, entry)
	}
	if len(eligible) == 0 {
		return nil, ErrDataCarrierRouteUnavailable
	}
	sort.Slice(eligible, func(i, j int) bool { return replicaLess(eligible[i], eligible[j], requestID) })
	return eligible[0], nil
}

// entryForExactAssignment resolves a private-access request to the one
// connector assignment authorized by its signed grant. Public routing may
// select among healthy replicas, but private TCP must not switch to a sibling
// assignment after authorization.
func (r *DataCarrierRouteRegistry) entryForExactAssignment(rule route.RouteRule) (*dataCarrierRouteEntry, error) {
	if r == nil || rule.AccountID == "" || rule.HostID == "" || rule.TunnelID == "" || rule.ConnectorID == "" || rule.ConnectorSessionID == "" || rule.ConnectorProcessGeneration == 0 || rule.ConfigGeneration == 0 {
		return nil, ErrDataCarrierRouteInvalid
	}
	identity := datacarrier.Identity{AccountID: rule.AccountID, HostID: rule.HostID, TunnelID: rule.TunnelID, ConnectorID: rule.ConnectorID, SessionID: rule.ConnectorSessionID, ProcessGeneration: rule.ConnectorProcessGeneration, Generation: rule.ConfigGeneration}
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry := r.byKey[carrierRouteIdentityKey(identity)]
	if entry == nil || entry.identity != identity || entry.server == nil || !entry.state.Ready || entry.state.Generation != rule.ConfigGeneration || uint32(entry.server.ActiveStreams()) >= entry.state.Capacity {
		return nil, ErrDataCarrierRouteUnavailable
	}
	select {
	case <-entry.server.Done():
		return nil, ErrDataCarrierRouteUnavailable
	default:
	}
	binding, ok := replicaRouteBinding(entry.state.RouteBindings, carrierRouteID(rule))
	if !ok || !sortedContains(entry.state.HealthyRoutes, carrierRouteID(rule)) || binding.AssignmentID != rule.AssignmentID || binding.AssignmentGeneration != rule.AssignmentGeneration || binding.RouteGeneration != rule.RouteGeneration || binding.ConfigContentHash != rule.ConfigContentHash {
		return nil, ErrDataCarrierRouteUnavailable
	}
	return entry, nil
}

func replicaRouteBinding(bindings []ReplicaRouteBinding, routeID string) (ReplicaRouteBinding, bool) {
	index := sort.Search(len(bindings), func(index int) bool { return bindings[index].RouteID >= routeID })
	if index >= len(bindings) || bindings[index].RouteID != routeID {
		return ReplicaRouteBinding{}, false
	}
	return bindings[index], true
}

func sortedContains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func replicaLess(left, right *dataCarrierRouteEntry, requestID string) bool {
	if left.state.Latency != right.state.Latency {
		return left.state.Latency < right.state.Latency
	}
	leftLoad := uint64(left.server.ActiveStreams()) * uint64(right.state.Capacity)
	rightLoad := uint64(right.server.ActiveStreams()) * uint64(left.state.Capacity)
	if leftLoad != rightLoad {
		return leftLoad < rightLoad
	}
	// Rotate equal candidates deterministically across failure domains without
	// ever opening more than one stream for a request.
	leftScore := replicaTieScore(requestID, left.state.FailureDomain)
	rightScore := replicaTieScore(requestID, right.state.FailureDomain)
	if leftScore != rightScore {
		return leftScore > rightScore
	}
	return carrierRouteIdentityKey(left.identity) < carrierRouteIdentityKey(right.identity)
}

func replicaTieScore(requestID, failureDomain string) uint64 {
	digest := sha256.Sum256([]byte(requestID + "\x00" + failureDomain))
	return binary.BigEndian.Uint64(digest[:8])
}

// OpenRouteStream opens the canonical connector-v1 StreamOpen through one
// healthy replica for the immutable route/config tuple. The opaque route
// target is never interpreted locally.
func (r *DataCarrierRouteRegistry) OpenRouteStream(ctx context.Context, rule route.RouteRule, requestID string) (io.ReadWriteCloser, error) {
	if ctx == nil || requestID == "" || connectorprotocol.ValidateIdentifier(requestID) != nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	entry, err := r.entryFor(rule, requestID)
	if err != nil {
		return nil, err
	}
	open := connectorprotocol.StreamOpen{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion,
		AccountID: entry.identity.AccountID, TunnelID: entry.identity.TunnelID, ConnectorID: entry.identity.ConnectorID,
		SessionID: entry.identity.SessionID, ProcessGeneration: entry.identity.ProcessGeneration,
		Generation: entry.identity.Generation, RouteID: carrierRouteID(rule), RequestID: requestID,
		Kind: durableStreamKind(rule.Protocol),
	}
	openContext, cancel := context.WithTimeout(ctx, defaultDataCarrierRouteOpenTimeout)
	defer cancel()
	started := time.Now()
	stream, err := entry.server.OpenStreamWithLifetime(openContext, ctx, open)
	if err != nil {
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	r.recordOpenLatency(entry, time.Since(started))
	return stream, nil
}

// OpenPrivateTCPStream is the non-HTTP access-only carrier seam. Unlike
// public HTTP replica selection, it resolves the exact connector/session and
// assignment authorized by the private-access grant.
func (r *DataCarrierRouteRegistry) OpenPrivateTCPStream(ctx context.Context, rule route.RouteRule, requestID string) (io.ReadWriteCloser, error) {
	if ctx == nil || requestID == "" || connectorprotocol.ValidateIdentifier(requestID) != nil || rule.Kind != route.TunnelPrivateTCP || rule.AccessMode != "private" || rule.Protocol != "private_tcp" {
		return nil, ErrDataCarrierRouteInvalid
	}
	openContext, cancel := context.WithTimeout(ctx, defaultDataCarrierRouteOpenTimeout)
	defer cancel()
	return r.openExactAssignmentWithTimeout(openContext, ctx, rule, requestID)
}

// ProbeRoutes performs a bounded HTTP request through each staged route. It
// deliberately uses the carrier stream and does not dial OriginAddress.
func (r *DataCarrierRouteRegistry) ProbeRoutes(ctx context.Context, rules []route.RouteRule) error {
	if ctx == nil {
		return ErrDataCarrierRouteInvalid
	}
	ordered := append([]route.RouteRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for index, rule := range ordered {
		probeContext, cancel := context.WithTimeout(ctx, defaultDataCarrierRouteOpenTimeout)
		requestID := fmt.Sprintf("edge-probe-%d-%d", time.Now().UnixNano(), index)
		stream, err := r.openExactAssignmentWithTimeout(probeContext, probeContext, rule, requestID)
		if err != nil {
			cancel()
			return err
		}
		host := rule.Hostname
		if rule.HostOverride != "" {
			host = rule.HostOverride
		}
		_, writeErr := io.WriteString(stream, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		if writeErr == nil {
			response, readErr := http.ReadResponse(bufio.NewReader(io.LimitReader(stream, maximumDataCarrierProbeHeader)), &http.Request{Method: http.MethodGet})
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			writeErr = readErr
			if writeErr == nil && response.StatusCode >= 500 {
				writeErr = fmt.Errorf("origin returned status %d", response.StatusCode)
			}
		}
		_ = stream.Close()
		cancel()
		if writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// ProbePrivateRoutes verifies only the authenticated carrier and route
// binding for access-only private TCP assignments. It intentionally does not
// write an HTTP request or inspect the host-local origin address: private TCP
// forwarding is opened later by its authenticated owner and is never exposed
// through the public HTTP matcher.
func (r *DataCarrierRouteRegistry) ProbePrivateRoutes(ctx context.Context, rules []route.RouteRule) error {
	if ctx == nil {
		return ErrDataCarrierRouteInvalid
	}
	ordered := append([]route.RouteRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for index, rule := range ordered {
		if rule.Kind != route.TunnelPrivateTCP || rule.AccessMode != "private" || rule.Protocol != "private_tcp" {
			return ErrDataCarrierRouteInvalid
		}
		probeContext, cancel := context.WithTimeout(ctx, defaultDataCarrierRouteOpenTimeout)
		requestID := fmt.Sprintf("edge-private-probe-%d-%d", time.Now().UnixNano(), index)
		stream, err := r.openExactAssignmentWithTimeout(probeContext, probeContext, rule, requestID)
		if err == nil {
			err = stream.Close()
		}
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func durableStreamKind(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "private_tcp", "tcp":
		return "tcp_private"
	case "http":
		return "http"
	case "https":
		return "https"
	case "h2c":
		return "h2c"
	case "websocket", "wss":
		return "websocket"
	case "sse":
		return "sse"
	case "grpc":
		return "grpc"
	default:
		return "https"
	}
}

func carrierRouteID(rule route.RouteRule) string {
	if strings.TrimSpace(rule.RouteID) != "" {
		return rule.RouteID
	}
	if strings.TrimSpace(rule.Target) != "" {
		return rule.Target
	}
	return rule.ID
}

// DataCarrierRouteTransport forwards an HTTP request over the selected
// authenticated carrier. The route match is read from Policy's context, so a
// request cannot choose a different connector by editing its Host header.
type DataCarrierRouteTransport struct {
	registry *DataCarrierRouteRegistry
	openWait time.Duration
	nextID   atomic.Uint64
}

type DataCarrierRouteTransportConfig struct {
	Registry          *DataCarrierRouteRegistry
	StreamOpenTimeout time.Duration
}

func NewDataCarrierRouteTransport(config DataCarrierRouteTransportConfig) (*DataCarrierRouteTransport, error) {
	if config.Registry == nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	if config.StreamOpenTimeout == 0 {
		config.StreamOpenTimeout = defaultDataCarrierRouteOpenTimeout
	}
	if config.StreamOpenTimeout <= 0 || config.StreamOpenTimeout > time.Minute {
		return nil, ErrDataCarrierRouteInvalid
	}
	return &DataCarrierRouteTransport{registry: config.Registry, openWait: config.StreamOpenTimeout}, nil
}

func (t *DataCarrierRouteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.registry == nil || request == nil || request.URL == nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	match, ok := RouteMatchFromContext(request.Context())
	if !ok || match.Rule.Kind != route.TunnelHTTPSWSS {
		return nil, ErrDataCarrierRouteInvalid
	}
	if match.Rule.AccessMode == "private" {
		// Private durable routes require the explicit private-access decision
		// contract. This transport has no proof source, so never downgrade one
		// to public forwarding.
		return nil, ErrDataCarrierRouteInvalid
	}
	requestID := fmt.Sprintf("edge-http-%d", t.nextID.Add(1))
	openContext, cancel := context.WithTimeout(request.Context(), t.openWait)
	defer cancel()
	stream, err := t.registry.openWithTimeout(openContext, request.Context(), match.Rule, requestID)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(request.Context(), func() { _ = stream.Close() })
	out := request.Clone(request.Context())
	out.RequestURI = ""
	out.URL.Scheme = ""
	out.URL.Host = ""
	if match.Rule.HostOverride != "" {
		out.Host = match.Rule.HostOverride
	}
	writeDone := make(chan error, 1)
	go func() {
		if out.Body != nil {
			defer out.Body.Close()
		}
		writeErr := out.Write(stream)
		if writeErr != nil {
			_ = stream.Close()
		}
		writeDone <- writeErr
	}()
	response, err := http.ReadResponse(bufio.NewReader(&boundedPreviewResponseHeaderReader{reader: stream, maximum: maximumDataCarrierProbeHeader}), out)
	if err != nil {
		stopCancel()
		_ = stream.Close()
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	response.Request = request
	response.Body = &dataCarrierPreviewResponseBody{body: response.Body, stream: stream, stopCancel: stopCancel, writeDone: writeDone}
	return response, nil
}

func (r *DataCarrierRouteRegistry) openWithTimeout(openCtx, lifetimeCtx context.Context, rule route.RouteRule, requestID string) (io.ReadWriteCloser, error) {
	if openCtx == nil || lifetimeCtx == nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	entry, err := r.entryFor(rule, requestID)
	if err != nil {
		return nil, err
	}
	open := connectorprotocol.StreamOpen{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion,
		AccountID: entry.identity.AccountID, TunnelID: entry.identity.TunnelID, ConnectorID: entry.identity.ConnectorID,
		SessionID: entry.identity.SessionID, ProcessGeneration: entry.identity.ProcessGeneration,
		Generation: entry.identity.Generation, RouteID: carrierRouteID(rule), RequestID: requestID,
		Kind: durableStreamKind(rule.Protocol),
	}
	started := time.Now()
	stream, err := entry.server.OpenStreamWithLifetime(openCtx, lifetimeCtx, open)
	if err != nil {
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	r.recordOpenLatency(entry, time.Since(started))
	return stream, nil
}

func (r *DataCarrierRouteRegistry) openExactAssignmentWithTimeout(openCtx, lifetimeCtx context.Context, rule route.RouteRule, requestID string) (io.ReadWriteCloser, error) {
	if openCtx == nil || lifetimeCtx == nil || requestID == "" || connectorprotocol.ValidateIdentifier(requestID) != nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	entry, err := r.entryForExactAssignment(rule)
	if err != nil {
		return nil, err
	}
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: entry.identity.AccountID, TunnelID: entry.identity.TunnelID, ConnectorID: entry.identity.ConnectorID, SessionID: entry.identity.SessionID, ProcessGeneration: entry.identity.ProcessGeneration, Generation: entry.identity.Generation, RouteID: carrierRouteID(rule), RequestID: requestID, Kind: durableStreamKind(rule.Protocol)}
	started := time.Now()
	stream, err := entry.server.OpenStreamWithLifetime(openCtx, lifetimeCtx, open)
	if err != nil {
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	r.recordOpenLatency(entry, time.Since(started))
	return stream, nil
}

var _ interface {
	ProbeRoutes(context.Context, []route.RouteRule) error
	OpenRouteStream(context.Context, route.RouteRule, string) (io.ReadWriteCloser, error)
} = (*DataCarrierRouteRegistry)(nil)
