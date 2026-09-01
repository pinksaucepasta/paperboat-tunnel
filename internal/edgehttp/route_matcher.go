package edgehttp

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

// CompositeRouteMatcher combines independent authoritative route owners. A
// request is accepted only when exactly one owner can acquire it; overlap is
// a fail-closed conflict rather than an order-dependent result.
type CompositeRouteMatcher struct {
	matchers []RouteMatcher
}

func NewCompositeRouteMatcher(matchers ...RouteMatcher) *CompositeRouteMatcher {
	filtered := make([]RouteMatcher, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher != nil {
			filtered = append(filtered, matcher)
		}
	}
	return &CompositeRouteMatcher{matchers: filtered}
}

func (m *CompositeRouteMatcher) Match(host, requestPath string) (route.RouteMatch, error) {
	if m == nil {
		return route.RouteMatch{}, route.ErrNoMatch
	}
	var matched route.RouteMatch
	count := 0
	for _, matcher := range m.matchers {
		candidate, err := matcher.Match(host, requestPath)
		if err != nil {
			if errors.Is(err, route.ErrNoMatch) {
				continue
			}
			return route.RouteMatch{}, err
		}
		matched = candidate
		count++
	}
	if count == 0 {
		return route.RouteMatch{}, route.ErrNoMatch
	}
	if count != 1 {
		return route.RouteMatch{}, route.ErrMatchConflict
	}
	return matched, nil
}

func (m *CompositeRouteMatcher) Acquire(ctx context.Context, host, requestPath string) (*route.StreamLease, route.RouteMatch, error) {
	if m == nil {
		return nil, route.RouteMatch{}, route.ErrNoMatch
	}
	var leases []*route.StreamLease
	var matched route.RouteMatch
	for _, matcher := range m.matchers {
		candidateLease, candidate, err := matcher.Acquire(ctx, host, requestPath)
		if err != nil {
			if errors.Is(err, route.ErrNoMatch) {
				continue
			}
			for _, lease := range leases {
				_ = lease.Close()
			}
			return nil, route.RouteMatch{}, err
		}
		leases = append(leases, candidateLease)
		matched = candidate
	}
	if len(leases) == 0 {
		return nil, route.RouteMatch{}, route.ErrNoMatch
	}
	if len(leases) != 1 {
		for _, lease := range leases {
			_ = lease.Close()
		}
		return nil, route.RouteMatch{}, route.ErrMatchConflict
	}
	return leases[0], matched, nil
}

// PreviewCarrierRouteMatcher adapts the authenticated preview registry to the
// policy's generation-fenced request boundary. It is exact-host only because
// preview route ownership and expiry are server-issued admission facts.
type PreviewCarrierRouteMatcher struct {
	registry *DataCarrierPreviewRegistry
}

func NewPreviewCarrierRouteMatcher(registry *DataCarrierPreviewRegistry) *PreviewCarrierRouteMatcher {
	return &PreviewCarrierRouteMatcher{registry: registry}
}

func (m *PreviewCarrierRouteMatcher) Match(host, requestPath string) (route.RouteMatch, error) {
	preview, _, ok := m.lookup(host, requestPath)
	if !ok {
		return route.RouteMatch{}, route.ErrNoMatch
	}
	match := previewRouteMatch(preview)
	match.Path = requestPath
	return match, nil
}

func (m *PreviewCarrierRouteMatcher) Acquire(ctx context.Context, host, requestPath string) (*route.StreamLease, route.RouteMatch, error) {
	preview, entryDone, ok := m.lookup(host, requestPath)
	if !ok {
		return nil, route.RouteMatch{}, route.ErrNoMatch
	}
	if ctx == nil {
		ctx = context.Background()
	}
	streamContext, cancel := context.WithCancel(ctx)
	match := previewRouteMatch(preview)
	match.Path = requestPath
	lease := route.NewStreamLease(streamContext, match)
	go func() {
		select {
		case <-preview.Server.Done():
			cancel()
		case <-entryDone:
			cancel()
		case <-streamContext.Done():
		case <-lease.Done():
			cancel()
		}
	}()
	return lease, match, nil
}

func (m *PreviewCarrierRouteMatcher) lookup(host, requestPath string) (DataCarrierPreviewRoute, <-chan struct{}, bool) {
	if m == nil || m.registry == nil || !validPreviewMatcherPath(requestPath) {
		return DataCarrierPreviewRoute{}, nil, false
	}
	preview, entryDone, ok := m.registry.acquire(host)
	if !ok || preview.Server == nil || preview.Kind != dataCarrierPreviewRouteKind && preview.Kind != dataCarrierPreviewPrivateRouteKind || !preview.ExpiresAt.IsZero() && !preview.ExpiresAt.After(time.Now().UTC()) {
		return DataCarrierPreviewRoute{}, nil, false
	}
	select {
	case <-preview.Server.Done():
		return DataCarrierPreviewRoute{}, nil, false
	default:
		return preview, entryDone, true
	}
}

func previewRouteMatch(preview DataCarrierPreviewRoute) route.RouteMatch {
	generation := preview.AttachmentGeneration
	if generation == 0 {
		generation = preview.Identity.Generation
	}
	kind := route.PreviewHTTPSWSS
	if preview.Kind == dataCarrierPreviewPrivateRouteKind {
		kind = route.Kind(dataCarrierPreviewPrivateRouteKind)
	}
	rule := route.RouteRule{ID: preview.RouteID, Revision: preview.Revision, Generation: generation, AssignmentGeneration: preview.LeaseGeneration, ResourceKind: "preview", SessionGeneration: preview.LeaseGeneration, Environment: preview.PreviewID, AccountID: preview.Identity.AccountID, HostID: preview.Identity.HostID, TunnelID: preview.PreviewID, ConnectorID: preview.Identity.ConnectorID, ConnectorSessionID: preview.Identity.SessionID, ConnectorProcessGeneration: preview.Identity.ProcessGeneration, ConfigGeneration: preview.Identity.Generation, Node: preview.EdgeNodeID, EdgeProcessEpoch: preview.EdgeProcessEpoch, Kind: kind, MatchType: route.MatchExact, Hostname: preview.Hostname, PathPrefix: "/", Target: preview.Endpoint, Protocol: "https", OriginScheme: "http", AccessMode: preview.AccessMode, PreserveHost: true, DesiredState: "active", ObservedState: "ready"}
	return route.RouteMatch{Rule: rule, Host: preview.Hostname, Path: "/", Generation: generation}
}

func validPreviewMatcherPath(requestPath string) bool {
	return requestPath != "" && strings.HasPrefix(requestPath, "/") && !strings.ContainsAny(requestPath, "\r\n\x00?#") && !strings.Contains(requestPath, "//")
}
