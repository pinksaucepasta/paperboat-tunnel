// Package tlscert owns the edge-local public certificate lifecycle.
//
// A registry intentionally keeps certificate material in memory only.  The
// control plane is responsible for decrypting an authenticated distribution
// payload; this package never writes private keys, returns them in a view, or
// puts them in an error.  Every lifecycle operation carries the complete
// domain and edge binding so a delayed message from an older process cannot
// replace or remove a newer certificate.
package tlscert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

var (
	ErrInvalid             = errors.New("invalid TLS certificate binding")
	ErrCertificateInvalid  = errors.New("invalid TLS certificate bundle")
	ErrGenerationConflict  = errors.New("TLS certificate generation conflict")
	ErrHostnameConflict    = errors.New("TLS certificate hostname conflict")
	ErrNotReady            = errors.New("TLS certificate is not ready")
	ErrReplacementNotReady = errors.New("replacement TLS certificate is not ready")
	ErrCertificateExpired  = errors.New("TLS certificate is expired")
	ErrCertificateRevoked  = errors.New("TLS certificate is revoked")
	ErrCertificateMissing  = errors.New("TLS certificate is not available")
	ErrClosed              = errors.New("TLS certificate registry is closed")
)

const (
	defaultMaximumLifetime = 90 * 24 * time.Hour
	maxBundleBytes         = 16 << 20
)

type State string

const (
	StateStaged  State = "staged"
	StateReady   State = "ready"
	StateActive  State = "active"
	StateRetired State = "retired"
	StateRevoked State = "revoked"
	StateExpired State = "expired"
	StateFailed  State = "failed"
)

// TargetKind is the owner namespace for a certificate binding. A durable
// route and a foreground preview lease may use the same hostname only after
// the control plane has applied its global claim rules, so the edge keeps the
// namespace in the immutable binding and in its replay key.
type TargetKind string

const (
	TargetDurableRoute TargetKind = "durable_route"
	TargetPreviewLease TargetKind = "preview_lease"
	// TargetPlatformWildcard identifies the two Paperboat-owned wildcard
	// bundles (preview and tunnel). They are distributed to every eligible
	// edge process, rather than being owned by a tunnel route or preview
	// lease, so their binding must carry no route/lease identity.
	TargetPlatformWildcard     TargetKind = "platform_wildcard"
	TargetKindDurableRoute                = TargetDurableRoute
	TargetKindPreviewLease                = TargetPreviewLease
	TargetKindPlatformWildcard            = TargetPlatformWildcard
)

type CertificateTarget struct {
	Kind              TargetKind
	DomainID          string
	AccountID         string
	TunnelID          string
	RouteID           string
	PreviewID         string
	PreviewGeneration uint64
	PreviewState      string
	PreviewExpiresAt  time.Time
}

func (t CertificateTarget) normalizedKind() TargetKind {
	if t.Kind != "" {
		return t.Kind
	}
	if t.PreviewID != "" || t.PreviewGeneration != 0 {
		return TargetPreviewLease
	}
	return TargetDurableRoute
}

// KindValue returns the canonical target discriminator, inferring the legacy
// durable value only when no preview identity is present.
func (t CertificateTarget) KindValue() TargetKind { return t.normalizedKind() }

func (t CertificateTarget) Validate() error {
	if !validIdentifier(t.DomainID) || !validIdentifier(t.AccountID) {
		return fmt.Errorf("%w: target identity is invalid", ErrInvalid)
	}
	switch t.normalizedKind() {
	case TargetDurableRoute:
		if !validIdentifier(t.TunnelID) {
			return fmt.Errorf("%w: durable target tunnel is invalid", ErrInvalid)
		}
		if t.Kind != "" && !validIdentifier(t.RouteID) {
			return fmt.Errorf("%w: durable target route is invalid", ErrInvalid)
		}
		if t.PreviewID != "" || t.PreviewGeneration != 0 || t.PreviewState != "" || !t.PreviewExpiresAt.IsZero() {
			return fmt.Errorf("%w: durable target contains preview identity", ErrInvalid)
		}
	case TargetPreviewLease:
		if t.TunnelID != "" || t.RouteID != "" || !validIdentifier(t.PreviewID) || t.PreviewGeneration == 0 || t.PreviewState != "active" || t.PreviewExpiresAt.IsZero() {
			return fmt.Errorf("%w: preview target identity is invalid", ErrInvalid)
		}
	case TargetPlatformWildcard:
		if t.TunnelID != "" || t.RouteID != "" || t.PreviewID != "" || t.PreviewGeneration != 0 || t.PreviewState != "" || !t.PreviewExpiresAt.IsZero() {
			return fmt.Errorf("%w: platform wildcard target contains route or lease identity", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: target kind is invalid", ErrInvalid)
	}
	return nil
}

func (t CertificateTarget) Key() string {
	return strings.Join([]string{string(t.normalizedKind()), t.DomainID, t.AccountID, t.TunnelID, t.RouteID, t.PreviewID, fmt.Sprint(t.PreviewGeneration)}, "\x00")
}

// Binding is the immutable identity of one certificate distribution target.
// Generation is the edge assignment generation. DomainGeneration fences a
// domain edit, while CertificateGeneration fences replacement order.
type Binding struct {
	AccountID         string
	TunnelID          string
	DomainID          string
	Hostname          string
	TargetKind        TargetKind
	RouteID           string
	PreviewID         string
	PreviewGeneration uint64
	PreviewState      string
	PreviewExpiresAt  time.Time
	// OnDemandLeaf marks a wildcard parent whose exact one-label children are
	// issued on the first authenticated SNI miss. It is a server policy bit,
	// never inferred from public traffic.
	OnDemandLeaf          bool
	DomainGeneration      uint64
	CertificateGeneration uint64
	EdgeNodeID            string
	EdgeProcessEpoch      string
	AssignmentGeneration  uint64
}

func (b Binding) Target() CertificateTarget {
	return CertificateTarget{Kind: b.TargetKind, DomainID: b.DomainID, AccountID: b.AccountID, TunnelID: b.TunnelID, RouteID: b.RouteID, PreviewID: b.PreviewID, PreviewGeneration: b.PreviewGeneration, PreviewState: b.PreviewState, PreviewExpiresAt: b.PreviewExpiresAt}
}

func (b Binding) validate() (string, bool, error) {
	if err := b.Target().Validate(); err != nil {
		return "", false, err
	}
	for name, value := range map[string]string{"edge_node_id": b.EdgeNodeID, "edge_process_epoch": b.EdgeProcessEpoch} {
		if !validIdentifier(value) && name == "edge_node_id" || !validEpoch(value) && name == "edge_process_epoch" {
			return "", false, fmt.Errorf("%w: %s", ErrInvalid, name)
		}
	}
	if b.DomainGeneration == 0 || b.CertificateGeneration == 0 || b.AssignmentGeneration == 0 {
		return "", false, fmt.Errorf("%w: generations are required", ErrInvalid)
	}
	host, wildcard, err := normalizeHostname(b.Hostname)
	if err != nil {
		return "", false, err
	}
	if b.Hostname != host {
		return "", false, fmt.Errorf("%w: hostname must be canonical", ErrInvalid)
	}
	if b.OnDemandLeaf && !wildcard {
		return "", false, fmt.Errorf("%w: on-demand policy requires a wildcard parent", ErrInvalid)
	}
	if b.Target().normalizedKind() == TargetPlatformWildcard && (!wildcard || b.OnDemandLeaf) {
		return "", false, fmt.Errorf("%w: platform wildcard target requires a non-on-demand wildcard hostname", ErrInvalid)
	}
	return host, wildcard, nil
}

// Validate exposes the same immutable binding fence used by registry
// lifecycle operations to authenticated distribution decoders.
func (b Binding) Validate() error {
	_, _, err := b.validate()
	return err
}

// Bundle is accepted only across the authenticated server-to-edge transport.
// It must not be marshaled into an API or audit record.
type Bundle struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
}

type CertificateView struct {
	Binding     Binding
	State       State
	Fingerprint string
	Issuer      string
	NotBefore   time.Time
	ExpiresAt   time.Time
	ActivatedAt time.Time
	RetiredAt   time.Time
	RevokedAt   time.Time
}

type Config struct {
	Now                    func() time.Time
	MaximumCertificateLife time.Duration
}

type Registry struct {
	mu      sync.RWMutex
	now     func() time.Time
	maxLife time.Duration
	closed  bool
	entries map[string]*entry
	active  map[string]string
}

type entry struct {
	binding     Binding
	hostname    string
	wildcard    bool
	state       State
	fingerprint [sha256.Size]byte
	issuer      string
	notBefore   time.Time
	notAfter    time.Time
	activatedAt time.Time
	retiredAt   time.Time
	revokedAt   time.Time
	certificate tls.Certificate
}

func NewRegistry(config Config) (*Registry, error) {
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxLife := config.MaximumCertificateLife
	if maxLife <= 0 || maxLife > defaultMaximumLifetime {
		maxLife = defaultMaximumLifetime
	}
	return &Registry{now: now, maxLife: maxLife, entries: make(map[string]*entry), active: make(map[string]string)}, nil
}

func (r *Registry) Stage(ctx context.Context, binding Binding, bundle Bundle) error {
	return r.stage(ctx, binding, bundle, nil)
}

func (r *Registry) stage(ctx context.Context, binding Binding, bundle Bundle, expectedFingerprint *[sha256.Size]byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	host, wildcard, err := binding.validate()
	if err != nil {
		return err
	}
	binding.Hostname = host
	now := r.now().UTC()
	if binding.Target().normalizedKind() == TargetPreviewLease && !binding.PreviewExpiresAt.After(now) {
		return ErrCertificateExpired
	}
	parsed, fingerprint, notBefore, notAfter, err := validateBundle(bundle, host, wildcard, now, r.maxLife)
	if err != nil {
		return err
	}
	if expectedFingerprint != nil && *expectedFingerprint != [sha256.Size]byte{} && *expectedFingerprint != fingerprint {
		return fmt.Errorf("%w: certificate fingerprint does not match distribution", ErrGenerationConflict)
	}
	key := bindingKey(binding)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	r.expireLocked(now)
	for activeKey, activeEntry := range r.entries {
		if activeEntry.state != StateActive || activeEntry.hostname != host || activeKey == key {
			continue
		}
		if activeEntry.binding.DomainID != binding.DomainID {
			return fmt.Errorf("%w: %s", ErrHostnameConflict, host)
		}
	}
	if existing, ok := r.entries[key]; ok {
		if existing.binding != binding {
			return ErrGenerationConflict
		}
		switch existing.state {
		case StateActive:
			if existing.fingerprint == fingerprint && existing.notAfter.Equal(notAfter) {
				return nil
			}
			return ErrGenerationConflict
		case StateStaged, StateReady:
			if existing.fingerprint == fingerprint && existing.notAfter.Equal(notAfter) {
				return nil
			}
			return ErrGenerationConflict
		case StateRetired, StateRevoked, StateExpired, StateFailed:
			return ErrGenerationConflict
		}
	}
	if current := r.currentDomainActiveLocked(binding.DomainID, host, wildcard); current != nil {
		if binding.DomainGeneration < current.binding.DomainGeneration {
			return ErrGenerationConflict
		}
		if binding.CertificateGeneration < current.binding.CertificateGeneration {
			return ErrGenerationConflict
		}
		if binding.DomainGeneration == current.binding.DomainGeneration && binding.AssignmentGeneration < current.binding.AssignmentGeneration {
			return ErrGenerationConflict
		}
		if binding.DomainGeneration == current.binding.DomainGeneration && binding.CertificateGeneration == current.binding.CertificateGeneration && current.fingerprint != fingerprint {
			// A process restart may replay the same certificate generation, but
			// it must not turn that replay into a different certificate. A
			// changed bundle requires a new certificate generation fence.
			return ErrGenerationConflict
		}
		// The same certificate may be staged for a replacement edge process,
		// but an assignment change on the same live process is stale and must
		// not create a second mutable entry. A preview lease renewal is the one
		// intentional exception: it changes only the target generation and is
		// allowed when the exact certificate bytes are unchanged.
		if binding.CertificateGeneration == current.binding.CertificateGeneration && current.binding.EdgeNodeID == binding.EdgeNodeID && current.binding.EdgeProcessEpoch == binding.EdgeProcessEpoch {
			if binding.Target().normalizedKind() != TargetPreviewLease || current.binding.Target().Key() == binding.Target().Key() || current.fingerprint != fingerprint {
				return ErrGenerationConflict
			}
		}
	}
	// A later certificate generation may replace a staged/ready candidate for
	// the same exact target.  It is safe because it has not been activated.
	for oldKey, old := range r.entries {
		if old.binding.DomainID == binding.DomainID && old.hostname == host && old.wildcard == wildcard && old.binding.EdgeNodeID == binding.EdgeNodeID && old.binding.EdgeProcessEpoch == binding.EdgeProcessEpoch && old.state != StateActive && old.state != StateRetired && old.state != StateRevoked && old.binding.CertificateGeneration < binding.CertificateGeneration {
			old.state = StateRetired
			old.retiredAt = now
			wipeTLSCertificate(&old.certificate)
			delete(r.entries, oldKey)
		}
	}
	r.entries[key] = &entry{binding: binding, hostname: host, wildcard: wildcard, state: StateStaged, fingerprint: fingerprint, issuer: bundle.Issuer, notBefore: notBefore, notAfter: notAfter, certificate: parsed}
	return nil
}

func (r *Registry) MarkReady(ctx context.Context, binding Binding) error {
	return r.markReady(ctx, binding, nil)
}

func (r *Registry) markReady(ctx context.Context, binding Binding, expectedFingerprint *[sha256.Size]byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	host, _, err := binding.validate()
	if err != nil {
		return err
	}
	binding.Hostname = host
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	e, ok := r.entries[bindingKey(binding)]
	if !ok || e.binding != binding {
		return ErrGenerationConflict
	}
	if expectedFingerprint != nil && *expectedFingerprint != [sha256.Size]byte{} && e.fingerprint != *expectedFingerprint {
		return fmt.Errorf("%w: certificate fingerprint does not match distribution", ErrGenerationConflict)
	}
	if !e.notAfter.After(r.now().UTC()) || binding.Target().normalizedKind() == TargetPreviewLease && !binding.PreviewExpiresAt.After(r.now().UTC()) {
		e.state = StateExpired
		if r.active[hostKey(e.hostname, e.wildcard)] == bindingKey(binding) {
			delete(r.active, hostKey(e.hostname, e.wildcard))
		}
		wipeTLSCertificate(&e.certificate)
		return ErrCertificateExpired
	}
	if e.state == StateReady || e.state == StateActive {
		return nil
	}
	if e.state != StateStaged {
		return ErrNotReady
	}
	e.state = StateReady
	return nil
}

func (r *Registry) Activate(ctx context.Context, binding Binding) error {
	return r.activate(ctx, binding, nil)
}

func (r *Registry) activate(ctx context.Context, binding Binding, expectedFingerprint *[sha256.Size]byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	host, _, err := binding.validate()
	if err != nil {
		return err
	}
	binding.Hostname = host
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	e, ok := r.entries[bindingKey(binding)]
	if !ok || e.binding != binding {
		return ErrGenerationConflict
	}
	if expectedFingerprint != nil && *expectedFingerprint != [sha256.Size]byte{} && e.fingerprint != *expectedFingerprint {
		return fmt.Errorf("%w: certificate fingerprint does not match distribution", ErrGenerationConflict)
	}
	if !e.notAfter.After(now) || binding.Target().normalizedKind() == TargetPreviewLease && !binding.PreviewExpiresAt.After(now) {
		e.state = StateExpired
		if r.active[hostKey(e.hostname, e.wildcard)] == bindingKey(binding) {
			delete(r.active, hostKey(e.hostname, e.wildcard))
		}
		wipeTLSCertificate(&e.certificate)
		return ErrCertificateExpired
	}
	if e.state == StateActive {
		return nil
	}
	if e.state != StateReady {
		return ErrNotReady
	}
	activeKey := hostKey(e.hostname, e.wildcard)
	previousKey := r.active[activeKey]
	if previousKey != "" && previousKey != bindingKey(binding) {
		previous := r.entries[previousKey]
		if previous != nil {
			if previous.binding.DomainGeneration > binding.DomainGeneration || previous.binding.CertificateGeneration > binding.CertificateGeneration {
				return ErrGenerationConflict
			}
			if previous.binding.DomainGeneration == binding.DomainGeneration && binding.AssignmentGeneration < previous.binding.AssignmentGeneration {
				return ErrGenerationConflict
			}
			if previous.binding.DomainGeneration == binding.DomainGeneration && previous.binding.CertificateGeneration == binding.CertificateGeneration && previous.fingerprint != e.fingerprint {
				return ErrGenerationConflict
			}
			if previous.binding.CertificateGeneration == binding.CertificateGeneration && previous.binding.EdgeNodeID == binding.EdgeNodeID && previous.binding.EdgeProcessEpoch == binding.EdgeProcessEpoch {
				if binding.Target().normalizedKind() != TargetPreviewLease || previous.binding.Target().Key() == binding.Target().Key() || previous.fingerprint != e.fingerprint {
					return ErrGenerationConflict
				}
			}
		}
	}
	if previousKey != "" && previousKey != bindingKey(binding) {
		if previous := r.entries[previousKey]; previous != nil && previous.state == StateActive {
			previous.state = StateRetired
			previous.retiredAt = now
			if previous.binding.CertificateGeneration == binding.CertificateGeneration && previous.binding.Target().normalizedKind() == TargetPreviewLease && previous.fingerprint == e.fingerprint {
				// The replacement is already ready, so discard the old target's
				// private-key copy immediately. A later retire message is safely
				// idempotent because the entry is gone.
				wipeTLSCertificate(&previous.certificate)
				delete(r.entries, previousKey)
			}
		}
	}
	e.state = StateActive
	e.activatedAt = now
	r.active[activeKey] = bindingKey(binding)
	return nil
}

// Retire removes an old certificate only after a newer certificate is active
// for the same hostname and domain.  This is the ready-new-before-old rule.
func (r *Registry) Retire(ctx context.Context, binding Binding) error {
	return r.retire(ctx, binding, nil)
}

func (r *Registry) retire(ctx context.Context, binding Binding, expectedFingerprint *[sha256.Size]byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	host, _, err := binding.validate()
	if err != nil {
		return err
	}
	binding.Hostname = host
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[bindingKey(binding)]
	if !ok || e.binding != binding {
		return nil
	}
	if expectedFingerprint != nil && *expectedFingerprint != [sha256.Size]byte{} && e.fingerprint != *expectedFingerprint {
		return fmt.Errorf("%w: certificate fingerprint does not match distribution", ErrGenerationConflict)
	}
	if e.state == StateRetired {
		wipeTLSCertificate(&e.certificate)
		delete(r.entries, bindingKey(binding))
		return nil
	}
	if e.state == StateRevoked || e.state == StateExpired {
		return nil
	}
	if e.state == StateActive && r.active[hostKey(e.hostname, e.wildcard)] == bindingKey(binding) {
		return ErrReplacementNotReady
	}
	e.state = StateRetired
	e.retiredAt = now
	wipeTLSCertificate(&e.certificate)
	delete(r.entries, bindingKey(binding))
	return nil
}

func (r *Registry) Revoke(ctx context.Context, binding Binding) error {
	return r.revoke(ctx, binding, nil)
}

func (r *Registry) revoke(ctx context.Context, binding Binding, expectedFingerprint *[sha256.Size]byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	host, _, err := binding.validate()
	if err != nil {
		return err
	}
	binding.Hostname = host
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[bindingKey(binding)]
	if !ok || e.binding != binding {
		return nil
	}
	if expectedFingerprint != nil && *expectedFingerprint != [sha256.Size]byte{} && e.fingerprint != *expectedFingerprint {
		return fmt.Errorf("%w: certificate fingerprint does not match distribution", ErrGenerationConflict)
	}
	e.state = StateRevoked
	e.revokedAt = now
	if r.active[hostKey(e.hostname, e.wildcard)] == bindingKey(binding) {
		delete(r.active, hostKey(e.hostname, e.wildcard))
	}
	wipeTLSCertificate(&e.certificate)
	delete(r.entries, bindingKey(binding))
	return nil
}

func (r *Registry) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, ErrCertificateMissing
	}
	host, wildcard, err := normalizeHostname(hello.ServerName)
	if err != nil || wildcard {
		return nil, ErrCertificateMissing
	}
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	r.expireLocked(now)
	key := r.active[hostKey(host, false)]
	if key == "" {
		// An on-demand wildcard is an issuance policy, not an implicit
		// certificate fallback. Exact SNI requests under that policy must go
		// through the authenticated broker request path instead of receiving
		// the parent wildcard certificate.
		if r.onDemandWildcardActiveLocked(host) {
			if r.expiredForHostLocked(host) {
				return nil, ErrCertificateExpired
			}
			return nil, ErrCertificateMissing
		}
		key = r.wildcardActiveKeyLocked(host)
	}
	e := r.entries[key]
	if e == nil || e.state != StateActive {
		if r.expiredForHostLocked(host) {
			return nil, ErrCertificateExpired
		}
		return nil, ErrCertificateMissing
	}
	if !e.notAfter.After(now) {
		e.state = StateExpired
		delete(r.active, hostKey(e.hostname, e.wildcard))
		return nil, ErrCertificateExpired
	}
	certificate := cloneTLSCertificate(e.certificate)
	return &certificate, nil
}

// RequiresExactCertificate reports whether an authenticated on-demand
// wildcard policy applies to a name which does not already have an active
// exact certificate. It is used by the broker before consulting the wildcard
// fallback path, so policy-marked names can never receive the parent wildcard.
func (r *Registry) RequiresExactCertificate(hostname string) bool {
	if r == nil {
		return false
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	now := r.now().UTC()
	r.expireLocked(now)
	if key := r.active[hostKey(host, false)]; key != "" {
		if entry := r.entries[key]; entry != nil && entry.state == StateActive {
			return false
		}
	}
	return r.onDemandWildcardActiveLocked(host)
}

func (r *Registry) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: r.GetCertificate}
}

func (r *Registry) Snapshot() []CertificateView {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now().UTC())
	views := make([]CertificateView, 0, len(r.entries))
	for _, e := range r.entries {
		views = append(views, CertificateView{Binding: e.binding, State: e.state, Fingerprint: hex.EncodeToString(e.fingerprint[:]), Issuer: e.issuer, NotBefore: e.notBefore, ExpiresAt: e.notAfter, ActivatedAt: e.activatedAt, RetiredAt: e.retiredAt, RevokedAt: e.revokedAt})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Binding.Hostname != views[j].Binding.Hostname {
			return views[i].Binding.Hostname < views[j].Binding.Hostname
		}
		if views[i].Binding.EdgeNodeID != views[j].Binding.EdgeNodeID {
			return views[i].Binding.EdgeNodeID < views[j].Binding.EdgeNodeID
		}
		return views[i].Binding.CertificateGeneration < views[j].Binding.CertificateGeneration
	})
	return views
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	// Drop all private key material promptly. Metadata snapshots remain empty
	// after close rather than exposing stale handles.
	for _, e := range r.entries {
		wipeTLSCertificate(&e.certificate)
	}
	r.entries = make(map[string]*entry)
	r.active = make(map[string]string)
	return nil
}

func (r *Registry) currentDomainActiveLocked(domainID, hostname string, wildcard bool) *entry {
	key := r.active[hostKey(hostname, wildcard)]
	if key == "" {
		return nil
	}
	e := r.entries[key]
	if e == nil || e.state != StateActive || e.binding.DomainID != domainID {
		return nil
	}
	return e
}

func (r *Registry) wildcardActiveKeyLocked(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return ""
	}
	return r.active[hostKey("*."+strings.Join(labels[1:], "."), true)]
}

func (r *Registry) onDemandWildcardActiveLocked(host string) bool {
	for key, entry := range r.entries {
		if entry.state != StateActive || !entry.wildcard || !entry.binding.OnDemandLeaf {
			continue
		}
		if r.active[hostKey(entry.hostname, true)] == key && wildcardMatches(entry.hostname, host) {
			return true
		}
	}
	return false
}

func (r *Registry) expireLocked(now time.Time) {
	for _, e := range r.entries {
		if e.state != StateActive || e.notAfter.After(now) && (e.binding.Target().normalizedKind() != TargetPreviewLease || e.binding.PreviewExpiresAt.After(now)) {
			continue
		}
		e.state = StateExpired
		delete(r.active, hostKey(e.hostname, e.wildcard))
		wipeTLSCertificate(&e.certificate)
	}
}

func wipeTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for i := range certificate.Certificate {
		clear(certificate.Certificate[i])
	}
	certificate.Certificate = nil
	clear(certificate.OCSPStaple)
	certificate.OCSPStaple = nil
	for i := range certificate.SignedCertificateTimestamps {
		clear(certificate.SignedCertificateTimestamps[i])
	}
	certificate.SignedCertificateTimestamps = nil
	certificate.PrivateKey = nil
	certificate.Leaf = nil
}

func (r *Registry) expiredForHostLocked(host string) bool {
	for _, e := range r.entries {
		if e.state != StateExpired {
			continue
		}
		if e.hostname == host && !e.wildcard {
			return true
		}
		if e.wildcard && wildcardMatches(e.hostname, host) {
			return true
		}
	}
	return false
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func validateBundle(bundle Bundle, hostname string, wildcard bool, now time.Time, maxLifetime time.Duration) (tls.Certificate, [sha256.Size]byte, time.Time, time.Time, error) {
	var fingerprint [sha256.Size]byte
	if len(bundle.CertificatePEM) == 0 || len(bundle.CertificatePEM) > maxBundleBytes || len(bundle.PrivateKeyPEM) == 0 || len(bundle.PrivateKeyPEM) > maxBundleBytes || strings.TrimSpace(bundle.Issuer) == "" {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: bundle is empty or oversized", ErrCertificateInvalid)
	}
	parsed, err := tls.X509KeyPair(bundle.CertificatePEM, bundle.PrivateKeyPEM)
	if err != nil || len(parsed.Certificate) == 0 {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: certificate and private key do not match", ErrCertificateInvalid)
	}
	leaf, err := x509.ParseCertificate(parsed.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: parse certificate", ErrCertificateInvalid)
	}
	parsed.Leaf = leaf
	if !leaf.NotAfter.After(now) || leaf.NotBefore.After(now.Add(10*time.Minute)) || maxLifetime > 0 && leaf.NotAfter.Sub(now) > maxLifetime {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: certificate lifetime is outside bounds", ErrCertificateInvalid)
	}
	verifyHost := hostname
	if wildcard {
		verifyHost = "paperboat." + hostname[2:]
	}
	if err := leaf.VerifyHostname(verifyHost); err != nil {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: certificate does not cover hostname", ErrCertificateInvalid)
	}
	if !bundle.NotBefore.IsZero() && !bundle.NotBefore.Equal(leaf.NotBefore) || !bundle.NotAfter.IsZero() && !bundle.NotAfter.Equal(leaf.NotAfter) {
		return tls.Certificate{}, fingerprint, time.Time{}, time.Time{}, fmt.Errorf("%w: certificate timestamps do not match", ErrCertificateInvalid)
	}
	fingerprint = sha256.Sum256(leaf.Raw)
	return parsed, fingerprint, leaf.NotBefore, leaf.NotAfter, nil
}

func cloneTLSCertificate(certificate tls.Certificate) tls.Certificate {
	clone := certificate
	clone.Certificate = make([][]byte, len(certificate.Certificate))
	for i := range certificate.Certificate {
		clone.Certificate[i] = append([]byte(nil), certificate.Certificate[i]...)
	}
	clone.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	clone.SignedCertificateTimestamps = append([][]byte(nil), certificate.SignedCertificateTimestamps...)
	return clone
}

func bindingKey(binding Binding) string {
	return strings.Join([]string{binding.Target().Key(), binding.Hostname, fmt.Sprint(binding.OnDemandLeaf), binding.EdgeNodeID, binding.EdgeProcessEpoch, fmt.Sprint(binding.DomainGeneration), fmt.Sprint(binding.CertificateGeneration), fmt.Sprint(binding.AssignmentGeneration)}, "\x00")
}

func hostKey(host string, wildcard bool) string {
	if wildcard {
		return "w:" + host
	}
	return "e:" + host
}

func wildcardMatches(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	patternLabels := strings.Split(pattern[2:], ".")
	hostLabels := strings.Split(host, ".")
	if len(hostLabels) != len(patternLabels)+1 {
		return false
	}
	return strings.EqualFold(strings.Join(hostLabels[1:], "."), strings.Join(patternLabels, "."))
}

func normalizeHostname(raw string) (string, bool, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@?#\r\n\x00") {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	wildcard := strings.HasPrefix(host, "*.")
	base := host
	if wildcard {
		base = host[2:]
	}
	ascii, err := idna.Lookup.ToASCII(base)
	if err != nil {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	base = strings.ToLower(strings.TrimSuffix(ascii, "."))
	// Persist and compare the ASCII IDNA form. Keeping the original Unicode
	// spelling here would make a valid internationalized name fail the ASCII
	// matcher and would let equivalent spellings diverge across edge policy.
	if wildcard {
		host = "*." + base
	} else {
		host = base
	}
	if strings.Contains(base, "*") || net.ParseIP(base) != nil || !dnsNamePattern.MatchString(base) {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	if wildcard && strings.Count(base, ".") < 1 {
		return "", false, fmt.Errorf("%w: wildcard hostname is invalid", ErrInvalid)
	}
	if !wildcard && !dnsNamePattern.MatchString(host) {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	return host, wildcard, nil
}

// NormalizeHostname returns the canonical DNS wire-form hostname used by the
// edge registry and broker. The bool reports a leading-label wildcard.
func NormalizeHostname(raw string) (string, bool, error) {
	return normalizeHostname(raw)
}

var dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validIdentifier(value string) bool {
	if len(value) < 3 || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func validEpoch(value string) bool {
	if len(value) < 8 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
