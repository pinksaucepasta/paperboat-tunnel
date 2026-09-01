package datacarrier

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

var (
	ErrDurableAdmissionInvalid  = errors.New("invalid durable carrier admission")
	ErrDurableAdmissionMissing  = errors.New("durable carrier admission is not expected")
	ErrDurableAdmissionConflict = errors.New("durable carrier admission conflicts with current state")
	ErrDurableAdmissionExpired  = errors.New("durable carrier admission is expired")
)

const (
	DurableCarrierRouteKind      = "tunnel_http_wss"
	DurableCarrierPrivateTCPKind = "tunnel_private_tcp"
	maxDurableAdmissions         = 4096
)

// DurableAdmission is the public, server-issued binding used to admit a
// connector carrier. It is deliberately separate from ExpectedAdmission:
// previews are ephemeral owner leases, while one durable connector identity
// may serve many tunnel routes. No bearer, private key, or credential secret
// is represented here.
type DurableAdmission struct {
	Identity                  Identity
	EdgeNodeID                string
	EdgeProcessEpoch          string
	AssignmentID              string
	RouteID                   string
	AssignmentGeneration      uint64
	RouteGeneration           uint64
	ConfigContentHash         string
	MachineIdentityPublicKey  string
	MachineIdentityThumbprint string
	State                     string
	ExpiresAt                 time.Time
}

func (a DurableAdmission) Validate(nodeID, processEpoch string, now time.Time) error {
	if err := a.Identity.Validate(); err != nil {
		return fmt.Errorf("%w: identity: %v", ErrDurableAdmissionInvalid, err)
	}
	if a.EdgeNodeID != nodeID || connectorprotocol.ValidateIdentifier(a.EdgeNodeID) != nil || a.EdgeProcessEpoch != processEpoch || connectorprotocol.ValidateOpaqueEpoch(a.EdgeProcessEpoch) != nil {
		return fmt.Errorf("%w: edge binding", ErrDurableAdmissionInvalid)
	}
	for _, value := range []string{a.AssignmentID, a.RouteID} {
		if connectorprotocol.ValidateIdentifier(value) != nil {
			return fmt.Errorf("%w: route binding", ErrDurableAdmissionInvalid)
		}
	}
	if a.AssignmentGeneration == 0 || a.RouteGeneration == 0 || a.ConfigContentHash == "" {
		return fmt.Errorf("%w: generations or config hash", ErrDurableAdmissionInvalid)
	}
	if a.State != "staged" && a.State != "active" && a.State != "draining" && a.State != "detached" {
		return fmt.Errorf("%w: state", ErrDurableAdmissionInvalid)
	}
	if !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(now) {
		return ErrDurableAdmissionExpired
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(a.MachineIdentityPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: machine public key", ErrDurableAdmissionInvalid)
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(publicKey))
	if err != nil || thumbprint != a.MachineIdentityThumbprint {
		return fmt.Errorf("%w: machine key thumbprint", ErrDurableAdmissionConflict)
	}
	if !validDurableContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: config hash", ErrDurableAdmissionInvalid)
	}
	return nil
}

func validDurableContentHash(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

type durableAdmissionEntry struct {
	identity                  Identity
	edgeProcessEpoch          string
	machineIdentityPublicKey  string
	machineIdentityThumbprint string
	byRoute                   map[string]DurableAdmission
}

// DurableAdmissionRegistry is the edge's authenticated durable carrier
// authority. It is keyed by the complete connector/session/config identity,
// while each identity entry contains many route assignments. Replacement is
// atomic, so a failed control pull preserves the last-known-good set.
type DurableAdmissionRegistry struct {
	nodeID       string
	processEpoch string
	maximum      int

	mu     sync.RWMutex
	closed bool
	byID   map[string]durableAdmissionEntry
}

type DurableAdmissionRegistryConfig struct {
	NodeID            string
	ProcessEpoch      string
	MaximumAdmissions int
}

func NewDurableAdmissionRegistry(config DurableAdmissionRegistryConfig) (*DurableAdmissionRegistry, error) {
	if connectorprotocol.ValidateIdentifier(config.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil {
		return nil, ErrDurableAdmissionInvalid
	}
	if config.MaximumAdmissions == 0 {
		config.MaximumAdmissions = maxDurableAdmissions
	}
	if config.MaximumAdmissions < 1 || config.MaximumAdmissions > maxDurableAdmissions {
		return nil, ErrDurableAdmissionInvalid
	}
	return &DurableAdmissionRegistry{nodeID: config.NodeID, processEpoch: config.ProcessEpoch, maximum: config.MaximumAdmissions, byID: make(map[string]durableAdmissionEntry)}, nil
}

func (r *DurableAdmissionRegistry) NodeID() string {
	if r == nil {
		return ""
	}
	return r.nodeID
}

func (r *DurableAdmissionRegistry) ProcessEpoch() string {
	if r == nil {
		return ""
	}
	return r.processEpoch
}

// Replace installs one complete canonical assignment set. Draining and
// detached rows are retained for inspection but never authorize new streams.
func (r *DurableAdmissionRegistry) Replace(admissions []DurableAdmission, now time.Time) error {
	if r == nil {
		return ErrDurableAdmissionInvalid
	}
	if len(admissions) > r.maximum {
		return ErrDurableAdmissionConflict
	}
	next := make(map[string]durableAdmissionEntry)
	r.mu.RLock()
	currentGenerations := make(map[string]uint64)
	for _, entry := range r.byID {
		for _, admission := range entry.byRoute {
			key := admission.Identity.AccountID + "\x00" + admission.Identity.HostID + "\x00" + admission.RouteID
			if admission.AssignmentGeneration > currentGenerations[key] {
				currentGenerations[key] = admission.AssignmentGeneration
			}
		}
	}
	r.mu.RUnlock()
	for _, admission := range admissions {
		if err := admission.Validate(r.nodeID, r.processEpoch, now); err != nil {
			return err
		}
		if admission.AssignmentGeneration < currentGenerations[admission.Identity.AccountID+"\x00"+admission.Identity.HostID+"\x00"+admission.RouteID] {
			return ErrDurableAdmissionConflict
		}
		key := durableIdentityKey(admission.Identity)
		entry, exists := next[key]
		if !exists {
			entry = durableAdmissionEntry{identity: admission.Identity, edgeProcessEpoch: admission.EdgeProcessEpoch, machineIdentityPublicKey: admission.MachineIdentityPublicKey, machineIdentityThumbprint: admission.MachineIdentityThumbprint, byRoute: make(map[string]DurableAdmission)}
		} else if entry.machineIdentityPublicKey != admission.MachineIdentityPublicKey || entry.machineIdentityThumbprint != admission.MachineIdentityThumbprint || entry.edgeProcessEpoch != admission.EdgeProcessEpoch {
			return fmt.Errorf("%w: identity has conflicting verifier material", ErrDurableAdmissionConflict)
		}
		if _, duplicate := entry.byRoute[admission.RouteID]; duplicate {
			return fmt.Errorf("%w: duplicate route assignment", ErrDurableAdmissionConflict)
		}
		entry.byRoute[admission.RouteID] = admission
		next[key] = entry
	}
	if len(next) > r.maximum {
		return ErrDurableAdmissionConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrCarrierClosed
	}
	r.byID = next
	return nil
}

func (r *DurableAdmissionRegistry) Snapshot() []DurableAdmission {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]DurableAdmission, 0)
	for _, entry := range r.byID {
		for _, admission := range entry.byRoute {
			result = append(result, admission)
		}
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity != result[j].Identity {
			return durableIdentityKey(result[i].Identity) < durableIdentityKey(result[j].Identity)
		}
		return result[i].RouteID < result[j].RouteID
	})
	return result
}

// HasIdentity reports whether the edge has a currently usable staged or
// active assignment for this exact connector carrier identity. A single
// identity may own many route IDs, so this is intentionally broader than a
// route lookup and is used only to select the owner of an authenticated
// server connection.
func (r *DurableAdmissionRegistry) HasIdentity(identity Identity, now time.Time) bool {
	if r == nil || identity.Validate() != nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return false
	}
	entry, ok := r.byID[durableIdentityKey(identity)]
	if !ok || entry.identity != identity {
		return false
	}
	for _, admission := range entry.byRoute {
		if (admission.State == "staged" || admission.State == "active") && (admission.ExpiresAt.IsZero() || admission.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

// ForIdentity returns the currently usable route admissions for one exact
// carrier identity. The copy is stable and sorted for deterministic callers.
func (r *DurableAdmissionRegistry) ForIdentity(identity Identity, now time.Time) []DurableAdmission {
	if r == nil || identity.Validate() != nil {
		return nil
	}
	r.mu.RLock()
	entry, ok := r.byID[durableIdentityKey(identity)]
	result := make([]DurableAdmission, 0, len(entry.byRoute))
	if !r.closed && ok && entry.identity == identity {
		for _, admission := range entry.byRoute {
			if (admission.State == "staged" || admission.State == "active") && (admission.ExpiresAt.IsZero() || admission.ExpiresAt.After(now)) {
				result = append(result, admission)
			}
		}
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].RouteID < result[j].RouteID })
	return result
}

// MachineBinding returns the verifier material captured with the exact
// connector identity. The values are public-key metadata only and are used to
// keep an attached route registry from selecting an older same-identity
// carrier during credential/key replacement.
func (r *DurableAdmissionRegistry) MachineBinding(identity Identity, now time.Time) (string, string, bool) {
	if r == nil || identity.Validate() != nil {
		return "", "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return "", "", false
	}
	entry, ok := r.byID[durableIdentityKey(identity)]
	if !ok || entry.identity != identity {
		return "", "", false
	}
	for _, admission := range entry.byRoute {
		if (admission.State == "staged" || admission.State == "active") && (admission.ExpiresAt.IsZero() || admission.ExpiresAt.After(now)) {
			return entry.machineIdentityPublicKey, entry.machineIdentityThumbprint, true
		}
	}
	return "", "", false
}

// PeerBinding verifies both the enrolled machine public key and exactly one
// canonical carrier URI SAN. The SAN carries session/process/config/edge
// generations, which prevents same-key replacement ambiguity.
func (r *DurableAdmissionRegistry) PeerBinding(state tls.ConnectionState) (Identity, error) {
	if r == nil {
		return Identity{}, ErrDurableAdmissionMissing
	}
	if len(state.PeerCertificates) != 1 || state.PeerCertificates[0] == nil {
		return Identity{}, ErrDurableAdmissionMissing
	}
	certificate := state.PeerCertificates[0]
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Identity{}, ErrDurableAdmissionMissing
	}
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	thumbprint, err := connectorprotocol.IdentityThumbprint(publicKey)
	if err != nil {
		return Identity{}, ErrDurableAdmissionMissing
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Identity{}, ErrCarrierClosed
	}
	var matched Identity
	found := false
	now := time.Now().UTC()
	for _, entry := range r.byID {
		if entry.machineIdentityPublicKey != encoded || entry.machineIdentityThumbprint != thumbprint {
			continue
		}
		for _, admission := range entry.byRoute {
			if admission.State != "staged" && admission.State != "active" || !admission.ExpiresAt.IsZero() && !admission.ExpiresAt.After(now) {
				continue
			}
			binding := connectorprotocol.CarrierIdentityBinding{AccountID: admission.Identity.AccountID, HostID: admission.Identity.HostID, TunnelID: admission.Identity.TunnelID, ConnectorID: admission.Identity.ConnectorID, SessionID: admission.Identity.SessionID, ProcessGeneration: admission.Identity.ProcessGeneration, ConfigGeneration: admission.Identity.Generation, EdgeProcessEpoch: admission.EdgeProcessEpoch}
			if connectorprotocol.MatchCarrierIdentityURN(certificate.URIs, binding) != nil {
				continue
			}
			if found && matched != admission.Identity {
				return Identity{}, ErrDurableAdmissionConflict
			}
			matched = admission.Identity
			found = true
		}
	}
	if !found {
		return Identity{}, ErrDurableAdmissionMissing
	}
	return matched, nil
}

func (r *DurableAdmissionRegistry) AuthorizeStream(ctx context.Context, identity Identity, open StreamOpen) error {
	if ctx == nil {
		return ErrDurableAdmissionInvalid
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
	entry, ok := r.byID[durableIdentityKey(identity)]
	if !ok {
		return ErrDurableAdmissionMissing
	}
	admission, ok := entry.byRoute[open.RouteID]
	if !ok {
		return ErrDurableAdmissionMissing
	}
	if admission.State != "staged" && admission.State != "active" {
		return ErrDurableAdmissionMissing
	}
	// Durable connector assignments deliberately permit zero expiry so the
	// edge can preserve last-known-good traffic during a control-plane outage.
	// Accessor admissions always carry a bounded nonzero expiry and are
	// validated before conversion into this registry.
	if !admission.ExpiresAt.IsZero() && !admission.ExpiresAt.After(time.Now().UTC()) {
		return ErrDurableAdmissionExpired
	}
	return nil
}

func (r *DurableAdmissionRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.closed = true
	r.byID = make(map[string]durableAdmissionEntry)
	r.mu.Unlock()
	return nil
}

func durableIdentityKey(identity Identity) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d", identity.AccountID, identity.HostID, identity.TunnelID, identity.ConnectorID, identity.SessionID, identity.ProcessGeneration, identity.Generation)
}

// AnyPeerBinding and AnyAuthorizer compose preview and durable authorities
// without making either registry understand the other's resource model.
func AnyPeerBinding(bindings ...PeerBinding) PeerBinding {
	return func(state tls.ConnectionState) (Identity, error) {
		var last error
		for _, binding := range bindings {
			if binding == nil {
				continue
			}
			identity, err := binding(state)
			if err == nil {
				return identity, nil
			}
			last = err
		}
		if last == nil {
			last = ErrDurableAdmissionMissing
		}
		return Identity{}, last
	}
}

func AnyAuthorizer(authorizers ...Authorizer) Authorizer {
	return AuthorizerFunc(func(ctx context.Context, identity Identity, open StreamOpen) error {
		var last error
		for _, authorizer := range authorizers {
			if authorizer == nil {
				continue
			}
			if err := authorizer.AuthorizeStream(ctx, identity, open); err == nil {
				return nil
			} else {
				last = err
			}
		}
		if last == nil {
			last = ErrDurableAdmissionMissing
		}
		return last
	})
}

var _ Authorizer = (*DurableAdmissionRegistry)(nil)
