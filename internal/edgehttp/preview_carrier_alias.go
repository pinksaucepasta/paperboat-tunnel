package edgehttp

import (
	"sort"
	"strings"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

const (
	PreviewAliasExact            = "exact"
	PreviewAliasOneLabelWildcard = "one_label_wildcard"
)

// DataCarrierPreviewAlias is a certificate-ready custom hostname projected by
// the control plane onto an already authenticated preview carrier route. The
// three generations prevent a stale DNS, lease, or certificate observation
// from republishing an alias after replacement or preview termination.
type DataCarrierPreviewAlias struct {
	DomainID              string `json:"domain_id"`
	RouteID               string `json:"route_id"`
	Hostname              string `json:"hostname"`
	MatchType             string `json:"match_type"`
	PreviewGeneration     uint64 `json:"preview_generation"`
	DomainGeneration      uint64 `json:"domain_generation"`
	CertificateGeneration uint64 `json:"certificate_generation"`
}

func (a DataCarrierPreviewAlias) normalize() (DataCarrierPreviewAlias, error) {
	a.DomainID = strings.TrimSpace(a.DomainID)
	a.RouteID = strings.TrimSpace(a.RouteID)
	a.Hostname = normalizePreviewCarrierHost(a.Hostname)
	if connectorprotocol.ValidateIdentifier(a.DomainID) != nil || connectorprotocol.ValidateIdentifier(a.RouteID) != nil || a.PreviewGeneration == 0 || a.DomainGeneration == 0 || a.CertificateGeneration == 0 {
		return DataCarrierPreviewAlias{}, ErrDataCarrierPreviewRegistryInvalid
	}
	switch a.MatchType {
	case PreviewAliasExact:
		if !validPreviewCarrierHost(a.Hostname) || strings.HasPrefix(a.Hostname, "*.") {
			return DataCarrierPreviewAlias{}, ErrDataCarrierPreviewRegistryInvalid
		}
	case PreviewAliasOneLabelWildcard:
		if !strings.HasPrefix(a.Hostname, "*.") || !validPreviewCarrierHost(strings.TrimPrefix(a.Hostname, "*.")) {
			return DataCarrierPreviewAlias{}, ErrDataCarrierPreviewRegistryInvalid
		}
	default:
		return DataCarrierPreviewAlias{}, ErrDataCarrierPreviewRegistryInvalid
	}
	return a, nil
}

// AttachAlias atomically publishes one exact or one-label wildcard alias. The
// underlying preview route must already be ready and its lease generation must
// equal the alias projection. Custom aliases may live outside BaseDomain.
func (r *DataCarrierPreviewRegistry) AttachAlias(alias DataCarrierPreviewAlias) error {
	if r == nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	next, err := alias.normalize()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrDataCarrierPreviewRegistryClosed
	}
	return r.attachAliasLocked(next)
}

// ReconcilePreviewAliases installs one complete server snapshot. Aliases are
// retained as desired state while their authenticated carrier is reconnecting
// and become routable only after the exact lease generation attaches.
func (r *DataCarrierPreviewRegistry) ReconcilePreviewAliases(aliases []DataCarrierPreviewAlias) error {
	if r == nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	next := make(map[string]DataCarrierPreviewAlias, len(aliases))
	hosts := make(map[string]string, len(aliases))
	for _, candidate := range aliases {
		alias, err := candidate.normalize()
		if err != nil {
			return err
		}
		if _, duplicate := next[alias.DomainID]; duplicate {
			return ErrDataCarrierPreviewRegistryConflict
		}
		if owner, duplicate := hosts[alias.Hostname]; duplicate && owner != alias.DomainID {
			return ErrDataCarrierPreviewRegistryConflict
		}
		next[alias.DomainID] = alias
		hosts[alias.Hostname] = alias.DomainID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrDataCarrierPreviewRegistryClosed
	}
	for domainID, current := range r.desiredAliases {
		candidate, retained := next[domainID]
		if retained && (candidate.RouteID != current.RouteID || candidate.Hostname != current.Hostname || candidate.MatchType != current.MatchType || candidate.PreviewGeneration < current.PreviewGeneration || candidate.DomainGeneration < current.DomainGeneration || candidate.CertificateGeneration < current.CertificateGeneration) {
			return ErrDataCarrierPreviewRegistryStale
		}
	}
	for domainID, current := range r.aliasesByID {
		if candidate, retained := next[domainID]; !retained || candidate != current {
			r.removeAliasLocked(current)
		}
	}
	r.desiredAliases = next
	for routeID := range r.byRoute {
		r.activateDesiredAliasesForRouteLocked(routeID)
	}
	return nil
}

func (r *DataCarrierPreviewRegistry) attachAliasLocked(next DataCarrierPreviewAlias) error {
	routeEntry := r.byRoute[next.RouteID]
	if routeEntry == nil || routeEntry.route.LeaseGeneration != next.PreviewGeneration {
		return ErrDataCarrierPreviewRegistryStale
	}
	if next.Hostname == routeEntry.host {
		return ErrDataCarrierPreviewRegistryConflict
	}
	if current, ok := r.aliasesByID[next.DomainID]; ok {
		if current == next {
			return nil
		}
		if current.RouteID != next.RouteID || current.Hostname != next.Hostname || current.MatchType != next.MatchType || next.PreviewGeneration < current.PreviewGeneration || next.DomainGeneration <= current.DomainGeneration || next.CertificateGeneration < current.CertificateGeneration {
			return ErrDataCarrierPreviewRegistryStale
		}
		delete(r.byHost, current.Hostname)
	}
	if occupied := r.byHost[next.Hostname]; occupied != nil && occupied != routeEntry {
		return ErrDataCarrierPreviewRegistryConflict
	}
	r.aliasesByID[next.DomainID] = next
	ids := r.aliasIDsByRoute[next.RouteID]
	if ids == nil {
		ids = make(map[string]struct{})
		r.aliasIDsByRoute[next.RouteID] = ids
	}
	ids[next.DomainID] = struct{}{}
	r.byHost[next.Hostname] = routeEntry
	return nil
}

func (r *DataCarrierPreviewRegistry) activateDesiredAliasesForRouteLocked(routeID string) {
	for _, alias := range r.desiredAliases {
		if alias.RouteID == routeID {
			_ = r.attachAliasLocked(alias)
		}
	}
}

// DetachAlias removes only the exact current projection. Late cleanup from an
// older domain, lease, or certificate generation is harmless.
func (r *DataCarrierPreviewRegistry) DetachAlias(alias DataCarrierPreviewAlias) error {
	if r == nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	want, err := alias.normalize()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.aliasesByID[want.DomainID]
	if !ok {
		return nil
	}
	if current != want {
		return ErrDataCarrierPreviewRegistryStale
	}
	r.removeAliasLocked(current)
	return nil
}

func (r *DataCarrierPreviewRegistry) PreviewAliases() []DataCarrierPreviewAlias {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]DataCarrierPreviewAlias, 0, len(r.aliasesByID))
	for _, alias := range r.aliasesByID {
		result = append(result, alias)
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Hostname != result[j].Hostname {
			return result[i].Hostname < result[j].Hostname
		}
		return result[i].DomainID < result[j].DomainID
	})
	return result
}

func (r *DataCarrierPreviewRegistry) lookupHostLocked(host string) (*dataCarrierPreviewRouteEntry, bool) {
	if entry := r.byHost[host]; entry != nil {
		return entry, true
	}
	dot := strings.IndexByte(host, '.')
	if dot <= 0 || dot == len(host)-1 {
		return nil, false
	}
	entry := r.byHost["*."+host[dot+1:]]
	return entry, entry != nil
}

func (r *DataCarrierPreviewRegistry) removeAliasesForRouteLocked(routeID string) {
	for domainID := range r.aliasIDsByRoute[routeID] {
		if alias, ok := r.aliasesByID[domainID]; ok {
			r.removeAliasLocked(alias)
		}
	}
	delete(r.aliasIDsByRoute, routeID)
}

func (r *DataCarrierPreviewRegistry) removeAliasLocked(alias DataCarrierPreviewAlias) {
	delete(r.aliasesByID, alias.DomainID)
	delete(r.byHost, alias.Hostname)
	if ids := r.aliasIDsByRoute[alias.RouteID]; ids != nil {
		delete(ids, alias.DomainID)
		if len(ids) == 0 {
			delete(r.aliasIDsByRoute, alias.RouteID)
		}
	}
}
