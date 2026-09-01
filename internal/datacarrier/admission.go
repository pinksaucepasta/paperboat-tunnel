package datacarrier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

const (
	PreviewCarrierSchema        = "paperboat.preview-tunnel/v1"
	PreviewCarrierKind          = "preview_carrier_attachment"
	PreviewCarrierRoute         = "preview_public_https_wss"
	PreviewCarrierPrivateRoute  = "preview_private_https_wss"
	PreviewCarrierAccessPublic  = "public"
	PreviewCarrierAccessPrivate = "private"
	maxExpectedAdmissions       = 4096
)

var (
	ErrAdmissionNotExpected = errors.New("data carrier admission is not expected")
	ErrAdmissionExpired     = errors.New("data carrier admission is expired")
	ErrAdmissionConflict    = errors.New("data carrier admission conflicts with current state")
)

// ExpectedAdmission is the edge's generation-fenced, server-issued preview
// attachment. It is routing and identity metadata only. In particular it has
// no bearer credential or private key and cannot be used to mint one.
//
// The control-plane adapter deliberately converts its wire response into this
// type before publishing it. This keeps TLS peer binding and stream
// authorization dependent on one validated representation.
type ExpectedAdmission struct {
	Schema                    string
	Kind                      string
	EdgeNodeID                string
	PreviewID                 string
	OperationID               string
	OwnerDeviceID             string
	OwnerSessionID            string
	Identity                  Identity
	LeaseGeneration           uint64
	ConfigGeneration          uint64
	ConfigContentHash         string
	RouteID                   string
	EdgeProcessEpoch          string
	AccessMode                string
	RouteKind                 string
	Hostname                  string
	RouteRevision             uint64
	AttachmentGeneration      uint64
	Endpoint                  string
	ExpiresAt                 time.Time
	MachineIdentityPublicKey  string
	MachineIdentityThumbprint string
	// Admitted is an internal edge state. A validated pull is installed as
	// pending first; only a successful durable server ACK flips it true. TLS
	// peer binding and stream authorization reject pending entries.
	Admitted bool
}

func (a ExpectedAdmission) Validate(now time.Time, nodeID string) error {
	if a.Schema != PreviewCarrierSchema || a.Kind != PreviewCarrierKind {
		return fmt.Errorf("%w: schema or kind is invalid", ErrAdmissionNotExpected)
	}
	if nodeID == "" || a.EdgeNodeID != nodeID || connectorprotocol.ValidateIdentifier(a.EdgeNodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(a.EdgeProcessEpoch) != nil {
		return fmt.Errorf("%w: edge node binding is invalid", ErrAdmissionNotExpected)
	}
	for name, value := range map[string]string{
		"preview_id": a.PreviewID, "operation_id": a.OperationID,
		"route_id": a.RouteID, "owner_device_id": a.OwnerDeviceID,
		"owner_session_id": a.OwnerSessionID,
	} {
		if value == "" || connectorprotocol.ValidateIdentifier(value) != nil {
			return fmt.Errorf("%w: %s is invalid", ErrAdmissionNotExpected, name)
		}
	}
	if err := a.Identity.Validate(); err != nil {
		return fmt.Errorf("%w: carrier identity is invalid", ErrAdmissionNotExpected)
	}
	if a.Identity.HostID != a.OwnerDeviceID {
		return fmt.Errorf("%w: host and owner device differ", ErrAdmissionConflict)
	}
	if a.LeaseGeneration == 0 || a.ConfigGeneration == 0 || a.RouteRevision == 0 || a.AttachmentGeneration == 0 {
		return fmt.Errorf("%w: generations must be positive", ErrAdmissionNotExpected)
	}
	if a.AccessMode != PreviewCarrierAccessPublic && a.AccessMode != PreviewCarrierAccessPrivate {
		return fmt.Errorf("%w: access mode is invalid", ErrAdmissionNotExpected)
	}
	wantRoute := PreviewCarrierRoute
	if a.AccessMode == PreviewCarrierAccessPrivate {
		wantRoute = PreviewCarrierPrivateRoute
	}
	if a.RouteKind != wantRoute || !validAdmissionHost(a.Hostname) {
		return fmt.Errorf("%w: route binding is invalid", ErrAdmissionNotExpected)
	}
	if err := validateAdmissionEndpoint(a.Endpoint, a.Hostname); err != nil {
		return err
	}
	if !validAdmissionContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: config content hash is invalid", ErrAdmissionNotExpected)
	}
	if a.ExpiresAt.IsZero() || !a.ExpiresAt.After(now) {
		return ErrAdmissionExpired
	}
	if _, err := decodeMachinePublicKey(a.MachineIdentityPublicKey, a.MachineIdentityThumbprint); err != nil {
		return err
	}
	return nil
}

func (a ExpectedAdmission) key() string {
	return a.OperationID + "\x00" + a.RouteID
}

func (a ExpectedAdmission) identityEqual(other ExpectedAdmission) bool {
	return a.Identity == other.Identity && a.MachineIdentityPublicKey == other.MachineIdentityPublicKey && a.MachineIdentityThumbprint == other.MachineIdentityThumbprint
}

// exactEqual compares the durable admission binding. Admitted is deliberately
// excluded because it is edge-local state and detach messages are rebuilt
// from control-plane data without that field. Every field that can authorize
// a route, select a carrier, or fence a replacement must otherwise match.
func (a ExpectedAdmission) exactEqual(other ExpectedAdmission) bool {
	return a.Schema == other.Schema &&
		a.Kind == other.Kind &&
		a.EdgeNodeID == other.EdgeNodeID &&
		a.EdgeProcessEpoch == other.EdgeProcessEpoch &&
		a.PreviewID == other.PreviewID &&
		a.OperationID == other.OperationID &&
		a.OwnerDeviceID == other.OwnerDeviceID &&
		a.OwnerSessionID == other.OwnerSessionID &&
		a.Identity == other.Identity &&
		a.LeaseGeneration == other.LeaseGeneration &&
		a.ConfigGeneration == other.ConfigGeneration &&
		a.ConfigContentHash == other.ConfigContentHash &&
		a.RouteID == other.RouteID &&
		a.AccessMode == other.AccessMode &&
		a.RouteKind == other.RouteKind &&
		a.Hostname == other.Hostname &&
		a.RouteRevision == other.RouteRevision &&
		a.AttachmentGeneration == other.AttachmentGeneration &&
		a.Endpoint == other.Endpoint &&
		a.ExpiresAt.Equal(other.ExpiresAt) &&
		a.MachineIdentityPublicKey == other.MachineIdentityPublicKey &&
		a.MachineIdentityThumbprint == other.MachineIdentityThumbprint
}

// ExpectedAdmissionRegistry is the only source used by carrier TLS peer
// binding and data-stream authorization. Replace is atomic: a transient
// control-plane failure must leave the last known good set in place, while a
// successful pull replaces the complete node-scoped set deterministically.
type ExpectedAdmissionRegistry struct {
	nodeID       string
	maximum      int
	processEpoch string

	mu      sync.RWMutex
	closed  bool
	byKey   map[string]ExpectedAdmission
	pending map[string]ExpectedAdmission
	changed chan struct{}
}

type ExpectedAdmissionRegistryConfig struct {
	NodeID            string
	ProcessEpoch      string
	MaximumAdmissions int
}

func NewExpectedAdmissionRegistry(config ExpectedAdmissionRegistryConfig) (*ExpectedAdmissionRegistry, error) {
	if config.MaximumAdmissions == 0 {
		config.MaximumAdmissions = maxExpectedAdmissions
	}
	if connectorprotocol.ValidateIdentifier(config.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil || config.MaximumAdmissions < 1 || config.MaximumAdmissions > maxExpectedAdmissions {
		return nil, ErrInvalidConfig
	}
	return &ExpectedAdmissionRegistry{nodeID: config.NodeID, processEpoch: config.ProcessEpoch, maximum: config.MaximumAdmissions, byKey: make(map[string]ExpectedAdmission), pending: make(map[string]ExpectedAdmission), changed: make(chan struct{})}, nil
}

func (r *ExpectedAdmissionRegistry) NodeID() string {
	if r == nil {
		return ""
	}
	return r.nodeID
}

func (r *ExpectedAdmissionRegistry) ProcessEpoch() string {
	if r == nil {
		return ""
	}
	return r.processEpoch
}

// Replace applies one complete successful control-plane snapshot. Duplicate
// operation/route keys are rejected instead of being resolved by map order.
func (r *ExpectedAdmissionRegistry) Replace(admissions []ExpectedAdmission, now time.Time) error {
	if r == nil {
		return ErrInvalidConfig
	}
	if len(admissions) > r.maximum {
		return fmt.Errorf("%w: too many admissions", ErrAdmissionConflict)
	}
	next := make(map[string]ExpectedAdmission, len(admissions))
	r.mu.RLock()
	prior := make(map[string]ExpectedAdmission, len(r.byKey))
	for key, value := range r.byKey {
		prior[key] = value
	}
	r.mu.RUnlock()
	for _, admission := range admissions {
		if err := admission.Validate(now, r.nodeID); err != nil {
			return err
		}
		if admission.EdgeProcessEpoch != r.processEpoch {
			return fmt.Errorf("%w: edge process epoch is stale", ErrAdmissionConflict)
		}
		if old, exists := prior[admission.key()]; exists && old.identityEqual(admission) && old.AttachmentGeneration == admission.AttachmentGeneration && old.LeaseGeneration == admission.LeaseGeneration && old.RouteRevision == admission.RouteRevision {
			admission.Admitted = old.Admitted
		}
		key := admission.key()
		if _, exists := next[key]; exists {
			return fmt.Errorf("%w: duplicate operation and route", ErrAdmissionConflict)
		}
		next[key] = admission
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrCarrierClosed
	}
	r.byKey = next
	r.pending = make(map[string]ExpectedAdmission)
	previousChanged := r.changed
	r.changed = make(chan struct{})
	close(previousChanged)
	r.mu.Unlock()
	return nil
}

// InstallPending stages a complete pull without removing currently admitted
// entries. A new/replaced operation remains pending until the server ACK is
// durably accepted; this prevents a lost ACK from opening a carrier or from
// needlessly tearing down a last-known-good route.
func (r *ExpectedAdmissionRegistry) InstallPending(admissions []ExpectedAdmission, now time.Time) error {
	if r == nil {
		return ErrInvalidConfig
	}
	if len(admissions) > r.maximum {
		return fmt.Errorf("%w: too many admissions", ErrAdmissionConflict)
	}
	next := make(map[string]ExpectedAdmission, len(admissions))
	for _, admission := range admissions {
		admission.Admitted = false
		if err := admission.Validate(now, r.nodeID); err != nil {
			return err
		}
		if admission.EdgeProcessEpoch != r.processEpoch {
			return fmt.Errorf("%w: edge process epoch is stale", ErrAdmissionConflict)
		}
		key := admission.key()
		if _, exists := next[key]; exists {
			return fmt.Errorf("%w: duplicate operation and route", ErrAdmissionConflict)
		}
		next[key] = admission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrCarrierClosed
	}
	r.pending = next
	for key, admission := range next {
		if current, exists := r.byKey[key]; !exists || !current.Admitted {
			r.byKey[key] = admission
		}
	}
	previous := r.changed
	r.changed = make(chan struct{})
	close(previous)
	return nil
}

// MarkAdmitted commits the server acknowledgement for the exact installed
// admission set. It is deliberately separate from Replace so a lost or
// rejected acknowledgement cannot accidentally open a carrier to the host.
func (r *ExpectedAdmissionRegistry) MarkAdmitted(admissions []ExpectedAdmission) error {
	if r == nil {
		return ErrInvalidConfig
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrCarrierClosed
	}
	for _, admission := range admissions {
		current, ok := r.pending[admission.key()]
		if !ok || !current.exactEqual(admission) {
			return ErrAdmissionConflict
		}
	}
	for _, admission := range admissions {
		key := admission.key()
		value := r.pending[key]
		value.Admitted = true
		r.byKey[key] = value
		delete(r.pending, key)
	}
	previous := r.changed
	r.changed = make(chan struct{})
	close(previous)
	return nil
}

// Commit removes old admissions only after every pulled admission has been
// ACKed and marked admitted. It is atomic with respect to PeerBinding and
// AuthorizeStream.
func (r *ExpectedAdmissionRegistry) Commit(admissions []ExpectedAdmission) error {
	if r == nil {
		return ErrInvalidConfig
	}
	next := make(map[string]ExpectedAdmission, len(admissions))
	for _, admission := range admissions {
		if !admission.Admitted {
			return ErrAdmissionConflict
		}
		next[admission.key()] = admission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrCarrierClosed
	}
	for key, admission := range next {
		current, ok := r.byKey[key]
		if !ok || !current.Admitted || !current.exactEqual(admission) {
			return ErrAdmissionConflict
		}
	}
	r.byKey = next
	r.pending = make(map[string]ExpectedAdmission)
	previous := r.changed
	r.changed = make(chan struct{})
	close(previous)
	return nil
}

// Upsert is useful for an edge publisher that receives individual durable
// admissions. It applies the same generation fencing as Replace and never
// replaces a newer attachment generation with an older one.
func (r *ExpectedAdmissionRegistry) Upsert(admission ExpectedAdmission, now time.Time) error {
	if r == nil {
		return ErrInvalidConfig
	}
	if err := admission.Validate(now, r.nodeID); err != nil {
		return err
	}
	if admission.EdgeProcessEpoch != r.processEpoch {
		return fmt.Errorf("%w: edge process epoch is stale", ErrAdmissionConflict)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrCarrierClosed
	}
	key := admission.key()
	if current, exists := r.byKey[key]; exists {
		if current == admission {
			return nil
		}
		if admission.AttachmentGeneration < current.AttachmentGeneration {
			return fmt.Errorf("%w: attachment generation regressed", ErrAdmissionConflict)
		}
	}
	if _, exists := r.byKey[key]; !exists && len(r.byKey) >= r.maximum {
		return fmt.Errorf("%w: admission capacity reached", ErrAdmissionConflict)
	}
	r.byKey[key] = admission
	previous := r.changed
	r.changed = make(chan struct{})
	close(previous)
	return nil
}

// Remove removes only the exact current admission. A missing key is
// idempotent; a different generation or identity is stale and cannot remove a
// replacement.
func (r *ExpectedAdmissionRegistry) Remove(admission ExpectedAdmission) error {
	if r == nil {
		return ErrInvalidConfig
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.byKey[admission.key()]
	if !exists {
		return nil
	}
	// Admitted is local state, so a detach request reconstructed from the
	// server wire may carry its zero value even when the current route is
	// admitted. All durable identity and generation fields remain exact.
	if !current.exactEqual(admission) {
		return ErrAdmissionConflict
	}
	delete(r.byKey, admission.key())
	previous := r.changed
	r.changed = make(chan struct{})
	close(previous)
	return nil
}

func (r *ExpectedAdmissionRegistry) Snapshot() []ExpectedAdmission {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]ExpectedAdmission, 0, len(r.byKey))
	for _, admission := range r.byKey {
		result = append(result, admission)
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].OperationID != result[j].OperationID {
			return result[i].OperationID < result[j].OperationID
		}
		return result[i].RouteID < result[j].RouteID
	})
	return result
}

func (r *ExpectedAdmissionRegistry) ForIdentity(identity Identity, now time.Time) []ExpectedAdmission {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]ExpectedAdmission, 0)
	for _, admission := range r.byKey {
		if admission.Admitted && admission.Identity == identity && admission.ExpiresAt.After(now) {
			result = append(result, admission)
		}
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return result[i].key() < result[j].key()
	})
	return result
}

// WaitForIdentity waits for a successful control pull to publish at least one
// admission for this exact authenticated carrier identity.
func (r *ExpectedAdmissionRegistry) WaitForIdentity(ctx context.Context, identity Identity, now func() time.Time) ([]ExpectedAdmission, error) {
	if r == nil || ctx == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	if err := identity.Validate(); err != nil {
		return nil, ErrAdmissionNotExpected
	}
	for {
		if admissions := r.ForIdentity(identity, now().UTC()); len(admissions) != 0 {
			return admissions, nil
		}
		r.mu.RLock()
		if r.closed {
			r.mu.RUnlock()
			return nil, ErrCarrierClosed
		}
		changed := r.changed
		r.mu.RUnlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// PeerBinding maps the authenticated mTLS client certificate to an admission
// identity. The enrolled public key proves the machine identity; the canonical
// URI SAN selects the exact server-issued carrier session and generations.
// This matters during replacement overlap, when the old and new short-lived
// certificates intentionally use the same enrolled machine key.
func (r *ExpectedAdmissionRegistry) PeerBinding(state tls.ConnectionState) (Identity, error) {
	if r == nil {
		return Identity{}, ErrAdmissionNotExpected
	}
	if len(state.PeerCertificates) != 1 || state.PeerCertificates[0] == nil {
		return Identity{}, ErrAdmissionNotExpected
	}
	publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Identity{}, ErrAdmissionNotExpected
	}
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	digest := sha256.Sum256(publicKey)
	thumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Identity{}, ErrCarrierClosed
	}
	var identity Identity
	found := false
	now := time.Now().UTC()
	for _, admission := range r.byKey {
		if !admission.Admitted || !admission.ExpiresAt.After(now) || admission.MachineIdentityPublicKey != encoded || admission.MachineIdentityThumbprint != thumbprint {
			continue
		}
		binding := connectorprotocol.CarrierIdentityBinding{
			AccountID: admission.Identity.AccountID, HostID: admission.Identity.HostID,
			TunnelID: admission.Identity.TunnelID, ConnectorID: admission.Identity.ConnectorID,
			SessionID: admission.Identity.SessionID, ProcessGeneration: admission.Identity.ProcessGeneration,
			ConfigGeneration: admission.Identity.Generation, EdgeProcessEpoch: admission.EdgeProcessEpoch,
		}
		if connectorprotocol.MatchCarrierIdentityURN(state.PeerCertificates[0].URIs, binding) != nil {
			continue
		}
		if !found {
			identity = admission.Identity
			found = true
			continue
		}
		if identity != admission.Identity {
			return Identity{}, fmt.Errorf("%w: certificate matches multiple carrier identities", ErrAdmissionConflict)
		}
	}
	if !found {
		return Identity{}, ErrAdmissionNotExpected
	}
	return identity, nil
}

func (r *ExpectedAdmissionRegistry) AuthorizeStream(ctx context.Context, identity Identity, open StreamOpen) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := identity.Validate(); err != nil || !identity.matches(open) {
		return ErrIdentityMismatch
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return ErrCarrierClosed
	}
	now := time.Now().UTC()
	for _, admission := range r.byKey {
		if admission.Admitted && admission.Identity == identity && admission.RouteID == open.RouteID {
			if !admission.ExpiresAt.After(now) {
				return ErrAdmissionExpired
			}
			if admission.AccessMode == PreviewCarrierAccessPrivate {
				decision, ok := PrivateAccessDecisionFromContext(ctx)
				if !ok || !decision.Allowed || decision.ExpiresAt.IsZero() || !decision.ExpiresAt.After(now) || decision.ResourceID != admission.PreviewID || decision.RouteID != admission.RouteID || decision.OperationID != admission.OperationID || decision.CarrierSessionID != admission.Identity.SessionID || decision.RouteGeneration != admission.RouteRevision || decision.ProcessGeneration != admission.Identity.ProcessGeneration || decision.ConfigGeneration != admission.Identity.Generation || decision.Protocol != "http" && decision.Protocol != "tcp" {
					return ErrRouteDenied
				}
			}
			return nil
		}
	}
	return ErrAdmissionNotExpected
}

// PrivateAccessDecision is the bounded, server-authorized metadata required
// to open a private stream. It contains no grant or proof bytes. The edge
// transport places it in the request context only after validating the
// control-plane response; stream admission rechecks every binding field.
type PrivateAccessDecision struct {
	Allowed           bool
	ExpiresAt         time.Time
	ResourceID        string
	RouteID           string
	OperationID       string
	CarrierSessionID  string
	RouteGeneration   uint64
	ProcessGeneration uint64
	ConfigGeneration  uint64
	Protocol          string
}

type privateAccessDecisionContextKey struct{}

func WithPrivateAccessDecision(ctx context.Context, decision PrivateAccessDecision) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, privateAccessDecisionContextKey{}, decision)
}

func PrivateAccessDecisionFromContext(ctx context.Context) (PrivateAccessDecision, bool) {
	if ctx == nil {
		return PrivateAccessDecision{}, false
	}
	decision, ok := ctx.Value(privateAccessDecisionContextKey{}).(PrivateAccessDecision)
	return decision, ok
}

func (r *ExpectedAdmissionRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		previous := r.changed
		r.changed = make(chan struct{})
		close(previous)
	}
	r.mu.Unlock()
	return nil
}

func decodeMachinePublicKey(value, thumbprint string) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: machine public key is invalid", ErrAdmissionNotExpected)
	}
	digest := sha256.Sum256(key)
	want := "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	if thumbprint != want {
		return nil, fmt.Errorf("%w: machine key thumbprint does not match", ErrAdmissionConflict)
	}
	return ed25519.PublicKey(key), nil
}

func validAdmissionHost(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@[] \t\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

func validateAdmissionEndpoint(value, hostname string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), strings.TrimSuffix(hostname, ".")) {
		return fmt.Errorf("%w: endpoint does not bind the admitted hostname", ErrAdmissionNotExpected)
	}
	return nil
}

func validAdmissionContentHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

var _ Authorizer = (*ExpectedAdmissionRegistry)(nil)
