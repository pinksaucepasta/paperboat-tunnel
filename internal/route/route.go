package route

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

var (
	ErrConflict = edgeerrors.New(edgeerrors.CodeRouteConflict, "route conflicts with current ownership", "reconcile authoritative route ownership")
	ErrInvalid  = edgeerrors.New(edgeerrors.CodeRouteInvalid, "route is invalid", "correct the route assignment")
	ErrStale    = edgeerrors.New(edgeerrors.CodeRouteRevisionStale, "route revision is stale", "fetch the current route revision")
)

type Kind string

const (
	HelperHTTPSWSS  Kind = "runtime_https_wss"
	PreviewHTTPSWSS Kind = "preview_public_https_wss"
	// TunnelHTTPSWSS is the durable connector-v1 route kind. Its target is an
	// opaque authenticated carrier binding, never a host-local origin address.
	TunnelHTTPSWSS Kind = "tunnel_http_wss"
	// TunnelTCP is selected by its server-reserved public port and must never
	// enter the HTTP hostname matcher.
	TunnelTCP Kind = "tunnel_tcp"
	// TunnelPrivateTCP is an access-only durable route. It is retained by the
	// carrier/admission layer but must never be inserted into the HTTP matcher.
	TunnelPrivateTCP Kind = "tunnel_private_tcp"
)

type Attachment struct {
	ID          string
	Revision    uint64
	Environment string
	Node        string
	Generation  uint64
	// ConfigGeneration is the generation of the complete route configuration.
	// Generation remains the legacy connector generation and is used as a
	// fallback when ConfigGeneration is zero.
	ConfigGeneration uint64
	Kind             Kind
	Host             string
	Target           string
	MatchType        string
	WildcardSuffix   string
	PathPrefix       string
	Priority         int
	Protocol         string
	OriginScheme     string
	PreserveHost     bool
	HostOverride     string
	DesiredState     string
	PreviewState     string
	PreviewReason    string
}

type Registry struct {
	mu                sync.Mutex
	previewBaseDomain string
	runtimeBaseDomain string
	byID              map[string]Attachment
	byHost            map[string]string
	changed           map[string]chan struct{}
	matcher           *GenerationRegistry
}

func NewRegistry(previewBaseDomain, runtimeBaseDomain string) *Registry {
	registry, _ := NewRegistryWithOptions(previewBaseDomain, runtimeBaseDomain, GenerationRegistryOptions{})
	return registry
}

func NewRegistryWithOptions(previewBaseDomain, runtimeBaseDomain string, options GenerationRegistryOptions) (*Registry, error) {
	matcher, err := NewGenerationRegistryWithOptions(0, options)
	if err != nil {
		return nil, err
	}
	return &Registry{previewBaseDomain: normalizeHost(previewBaseDomain), runtimeBaseDomain: normalizeHost(runtimeBaseDomain), byID: make(map[string]Attachment), byHost: make(map[string]string), changed: make(map[string]chan struct{}), matcher: matcher}, nil
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

var opaqueTunnelEndpointLabelPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidManagedTunnelHostname accepts only the server-owned managed endpoint
// form: one canonical lowercase UUID label directly below the configured
// tunnel base domain. Custom domains are validated by their route/domain
// ownership records and must not use this predicate.
func ValidManagedTunnelHostname(host, baseDomain string) bool {
	host = strings.TrimSpace(host)
	baseDomain = normalizeHost(baseDomain)
	if host == "" || host != normalizeHost(host) || baseDomain == "" {
		return false
	}
	prefix, matches := strings.CutSuffix(host, "."+baseDomain)
	return matches && opaqueTunnelEndpointLabelPattern.MatchString(prefix) && !strings.Contains(prefix, ".")
}

// ValidOpaqueTunnelHostname verifies the immutable endpoint shape without
// binding it to a deployment's base domain. It is used when validating a
// control assignment before the deployment domain is available at that layer.
func ValidOpaqueTunnelHostname(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host != normalizeHost(host) {
		return false
	}
	labels := strings.Split(host, ".")
	return len(labels) >= 2 && opaqueTunnelEndpointLabelPattern.MatchString(labels[0])
}

func (r *Registry) Attach(a Attachment) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.Host = normalizeHost(a.Host)
	if a.ID == "" || a.Revision == 0 || a.Environment == "" || a.Node == "" || a.Generation == 0 || a.Host == "" || a.Target == "" || (a.Kind != HelperHTTPSWSS && a.Kind != PreviewHTTPSWSS) {
		return Attachment{}, ErrInvalid
	}
	expectedDomain := r.previewBaseDomain
	if a.Kind == HelperHTTPSWSS {
		expectedDomain = r.runtimeBaseDomain
	}
	prefix, matches := strings.CutSuffix(a.Host, "."+expectedDomain)
	if expectedDomain == "" || !matches || prefix == "" || strings.Contains(prefix, ".") {
		return Attachment{}, ErrInvalid
	}
	if current, ok := r.byID[a.ID]; ok {
		if current == a {
			return current, nil
		}
		if a.Revision < current.Revision || a.Revision == current.Revision && !sameRoute(current, a) {
			return Attachment{}, ErrStale
		}
	}
	if owner, ok := r.byHost[a.Host]; ok && owner != a.ID {
		return Attachment{}, ErrConflict
	}
	if current, ok := r.byID[a.ID]; ok {
		delete(r.byHost, current.Host)
	}
	r.byID[a.ID], r.byHost[a.Host] = a, a.ID
	r.signalChangedLocked(a.Host)
	return a, nil
}

func (r *Registry) Detach(id string, revision uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return nil
	}
	if revision != a.Revision {
		return ErrStale
	}
	delete(r.byID, id)
	delete(r.byHost, a.Host)
	r.signalChangedLocked(a.Host)
	return nil
}

// Changed returns a host-scoped notification channel. The channel closes when
// authoritative ownership for the host may have changed.
func (r *Registry) Changed(host string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changedLocked(normalizeHost(host))
}

func (r *Registry) changedLocked(host string) chan struct{} {
	changed := r.changed[host]
	if changed == nil {
		changed = make(chan struct{})
		r.changed[host] = changed
	}
	return changed
}

func (r *Registry) signalChangedLocked(host string) {
	changed := r.changedLocked(host)
	close(changed)
	r.changed[host] = make(chan struct{})
}

func (r *Registry) Get(id string) (Attachment, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	return a, ok
}

func (r *Registry) Owns(a Attachment) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.byID[a.ID]
	return ok && sameRoute(current, a)
}

func (r *Registry) RouteState(host string) (string, string, string, bool) {
	if r.matcher != nil && r.matcher.HasActiveGeneration() {
		return r.matcher.RouteState(host)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byHost[normalizeHost(host)]
	if !ok {
		return "", "", "", false
	}
	a := r.byID[id]
	return string(a.Kind), a.PreviewState, a.PreviewReason, true
}

// Match resolves a request against the active complete generation. Before a
// complete generation has been promoted, it resolves the legacy attachment
// snapshot so existing FRP routes continue to work during the migration.
func (r *Registry) Match(host, requestPath string) (RouteMatch, error) {
	if r.matcher != nil && r.matcher.HasActiveGeneration() {
		return r.matcher.Match(host, requestPath)
	}
	r.mu.Lock()
	attachments := make([]Attachment, 0, len(r.byID))
	for _, attachment := range r.byID {
		attachments = append(attachments, attachment)
	}
	r.mu.Unlock()
	rules := make([]RouteRule, 0, len(attachments))
	for _, attachment := range attachments {
		rule := attachmentToRule(attachment)
		normalized, err := normalizeRule(rule.Generation, rule)
		if err != nil {
			return RouteMatch{}, err
		}
		rules = append(rules, normalized)
	}
	host, err := normalizeMatchHost(host)
	if err != nil {
		return RouteMatch{}, ErrNoMatch
	}
	requestPath, err = normalizeRequestPath(requestPath)
	if err != nil {
		return RouteMatch{}, ErrNoMatch
	}
	rule, err := chooseRule(rules, host, requestPath)
	if err != nil {
		return RouteMatch{}, err
	}
	return RouteMatch{Rule: rule, Host: host, Path: requestPath, Generation: rule.Generation}, nil
}

func (r *Registry) Acquire(ctx context.Context, host, requestPath string) (*StreamLease, RouteMatch, error) {
	if r.matcher != nil && r.matcher.HasActiveGeneration() {
		return r.matcher.Acquire(ctx, host, requestPath)
	}
	match, err := r.Match(host, requestPath)
	if err != nil {
		return nil, RouteMatch{}, err
	}
	return newNoopStreamLease(ctx, match), match, nil
}

func (r *Registry) StageGeneration(generation uint64, rules []RouteRule) error {
	return r.matcher.StageGeneration(generation, rules)
}

func (r *Registry) MarkGenerationReady(generation uint64) error {
	return r.matcher.MarkGenerationReady(generation)
}

func (r *Registry) ActivateGeneration(ctx context.Context, generation uint64, drainTimeout time.Duration) error {
	return r.matcher.ActivateGeneration(ctx, generation, drainTimeout)
}

func (r *Registry) ApplyGeneration(ctx context.Context, generation uint64, rules []RouteRule, ready func(context.Context, []RouteRule) error, drainTimeout time.Duration) error {
	return r.matcher.ApplyGeneration(ctx, generation, rules, ready, drainTimeout)
}

func (r *Registry) Generation() uint64 {
	if r.matcher == nil {
		return 0
	}
	return r.matcher.Generation()
}

func (r *Registry) HasActiveGeneration() bool {
	return r.matcher != nil && r.matcher.HasActiveGeneration()
}

func (r *Registry) TelemetryDrops() uint64 {
	if r == nil || r.matcher == nil {
		return 0
	}
	return r.matcher.TelemetryDrops()
}

// CanonicalSnapshot returns the active complete generation for access-only
// routes that deliberately have no public HTTP matcher entry.
func (r *Registry) CanonicalSnapshot() (uint64, []RouteRule, bool) {
	if r == nil || r.matcher == nil {
		return 0, nil, false
	}
	return r.matcher.Snapshot()
}

func (r *Registry) Close() error {
	if r.matcher == nil {
		return nil
	}
	return r.matcher.Close()
}

func (r *Registry) Replace(attachments []Attachment) error {
	next := NewRegistry(r.previewBaseDomain, r.runtimeBaseDomain)
	for _, attachment := range attachments {
		if _, err := next.Attach(attachment); err != nil {
			return err
		}
	}
	r.mu.Lock()
	for id, current := range r.byID {
		if replacement, ok := next.byID[id]; ok {
			if replacement.Revision < current.Revision || replacement.Revision == current.Revision && !sameRoute(current, replacement) {
				r.mu.Unlock()
				return ErrStale
			}
		}
	}
	changedHosts := make(map[string]struct{})
	for host, id := range r.byHost {
		nextID, ok := next.byHost[host]
		if !ok || nextID != id || !sameRoute(r.byID[id], next.byID[nextID]) {
			changedHosts[host] = struct{}{}
		}
	}
	for host := range next.byHost {
		if _, ok := r.byHost[host]; !ok {
			changedHosts[host] = struct{}{}
		}
	}
	r.byID, r.byHost = next.byID, next.byHost
	for host := range changedHosts {
		r.signalChangedLocked(host)
	}
	r.mu.Unlock()
	return nil
}

func sameRoute(a, b Attachment) bool {
	a.PreviewState, a.PreviewReason = "", ""
	b.PreviewState, b.PreviewReason = "", ""
	return a == b
}

func (r *Registry) Snapshot() []Attachment {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Attachment, 0, len(r.byID))
	for _, attachment := range r.byID {
		result = append(result, attachment)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
