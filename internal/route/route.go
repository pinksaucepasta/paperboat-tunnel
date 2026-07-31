package route

import (
	"sort"
	"strings"
	"sync"

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
)

type Attachment struct {
	ID            string
	Revision      uint64
	Environment   string
	Node          string
	Generation    uint64
	Kind          Kind
	Host          string
	Target        string
	PreviewState  string
	PreviewReason string
}

type Registry struct {
	mu                sync.Mutex
	previewBaseDomain string
	helperBaseDomain  string
	byID              map[string]Attachment
	byHost            map[string]string
}

func NewRegistry(previewBaseDomain, helperBaseDomain string) *Registry {
	return &Registry{previewBaseDomain: normalizeHost(previewBaseDomain), helperBaseDomain: normalizeHost(helperBaseDomain), byID: make(map[string]Attachment), byHost: make(map[string]string)}
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
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
		expectedDomain = r.helperBaseDomain
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
	return nil
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
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byHost[normalizeHost(host)]
	if !ok {
		return "", "", "", false
	}
	a := r.byID[id]
	return string(a.Kind), a.PreviewState, a.PreviewReason, true
}

func (r *Registry) Replace(attachments []Attachment) error {
	next := NewRegistry(r.previewBaseDomain, r.helperBaseDomain)
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
	r.byID, r.byHost = next.byID, next.byHost
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
