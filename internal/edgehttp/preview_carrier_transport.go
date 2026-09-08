package edgehttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

var (
	ErrDataCarrierPreviewRegistryInvalid       = errors.New("invalid data-carrier preview registry entry")
	ErrDataCarrierPreviewRegistryClosed        = errors.New("data-carrier preview registry is closed")
	ErrDataCarrierPreviewRegistryConflict      = errors.New("data-carrier preview route conflicts with an existing route")
	ErrDataCarrierPreviewRegistryStale         = errors.New("stale data-carrier preview route registration")
	ErrDataCarrierPreviewRegistryUnavailable   = errors.New("data-carrier preview carrier unavailable")
	ErrDataCarrierPreviewTransport             = errors.New("data-carrier preview transport failed")
	ErrDataCarrierPreviewResponseHeaderTimeout = errors.New("data-carrier preview response headers timed out")
)

const (
	dataCarrierPreviewRouteKind          = "preview_public_https_wss"
	dataCarrierPreviewPrivateRouteKind   = "preview_private_https_wss"
	dataCarrierPreviewDefaultOpenTimeout = 10 * time.Second
	dataCarrierPreviewMaxRoutes          = 4096
	dataCarrierPreviewMaxResponseHeader  = 64 << 10
)

// DataCarrierPreviewRoute describes one ready canonical preview route bound to
// one authenticated edge carrier. Identity is copied from Server when the
// route is attached and is never accepted as a mutable authorization token.
type DataCarrierPreviewRoute struct {
	RouteID                              string
	Hostname                             string
	Kind                                 string
	Revision                             uint64
	Identity                             datacarrier.Identity
	Server                               *datacarrier.Server
	PreviewID                            string
	OperationID                          string
	OwnerDeviceID                        string
	OwnerSessionID                       string
	AccessMode                           string
	EdgeNodeID                           string
	EdgeProcessEpoch                     string
	EdgeCarrierServerSPKISHA256          string
	EdgeCarrierServerCertificateChainPEM string
	LeaseGeneration                      uint64
	AttachmentGeneration                 uint64
	ConfigContentHash                    string
	Endpoint                             string
	ExpiresAt                            time.Time
	MachineIdentityPublicKey             string
	MachineIdentityThumbprint            string
}

type DataCarrierPreviewRegistryConfig struct {
	BaseDomain    string
	ProcessEpoch  string
	MaximumRoutes int
}

type DataCarrierPreviewRegistry struct {
	baseDomain      string
	processEpoch    string
	maximum         int
	done            chan struct{}
	closeOnce       sync.Once
	mu              sync.RWMutex
	closed          bool
	byRoute         map[string]*dataCarrierPreviewRouteEntry
	byHost          map[string]*dataCarrierPreviewRouteEntry
	aliasesByID     map[string]DataCarrierPreviewAlias
	aliasIDsByRoute map[string]map[string]struct{}
	desiredAliases  map[string]DataCarrierPreviewAlias
}

type dataCarrierPreviewRouteEntry struct {
	route DataCarrierPreviewRoute
	host  string
	done  chan struct{}
	once  sync.Once
}

func (e *dataCarrierPreviewRouteEntry) close() {
	if e == nil {
		return
	}
	e.once.Do(func() { close(e.done) })
}

func NewDataCarrierPreviewRegistry(config DataCarrierPreviewRegistryConfig) (*DataCarrierPreviewRegistry, error) {
	baseDomain := normalizePreviewCarrierHost(config.BaseDomain)
	if config.BaseDomain != "" && !validPreviewCarrierDomain(baseDomain) {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	if config.MaximumRoutes == 0 {
		config.MaximumRoutes = dataCarrierPreviewMaxRoutes
	}
	if config.MaximumRoutes < 1 || config.MaximumRoutes > dataCarrierPreviewMaxRoutes {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	if connectorprotocol.ValidateOpaqueEpoch(config.ProcessEpoch) != nil {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	return &DataCarrierPreviewRegistry{
		baseDomain: baseDomain, processEpoch: config.ProcessEpoch, maximum: config.MaximumRoutes,
		done: make(chan struct{}), byRoute: make(map[string]*dataCarrierPreviewRouteEntry),
		byHost: make(map[string]*dataCarrierPreviewRouteEntry), aliasesByID: make(map[string]DataCarrierPreviewAlias),
		aliasIDsByRoute: make(map[string]map[string]struct{}), desiredAliases: make(map[string]DataCarrierPreviewAlias),
	}, nil
}

// Attach publishes an authenticated route only after validating that the
// server identity, route identity, generation, and host are consistent. A
// newer config generation or process generation replaces an older entry; a
// stale server can never remove that replacement through its Done callback.
func (r *DataCarrierPreviewRegistry) Attach(route DataCarrierPreviewRoute) error {
	if r == nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	validated, err := r.validateRoute(route)
	if err != nil {
		return err
	}
	entry := &dataCarrierPreviewRouteEntry{route: validated, host: normalizePreviewCarrierHost(validated.Hostname), done: make(chan struct{})}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrDataCarrierPreviewRegistryClosed
	}
	old := r.byRoute[validated.RouteID]
	if old != nil {
		if sameDataCarrierPreviewRoute(old.route, validated) {
			r.mu.Unlock()
			return nil
		}
		if !newerDataCarrierPreviewRoute(old.route, validated) {
			r.mu.Unlock()
			return ErrDataCarrierPreviewRegistryStale
		}
	}
	if occupied := r.byHost[entry.host]; occupied != nil && occupied.route.RouteID != validated.RouteID {
		r.mu.Unlock()
		return ErrDataCarrierPreviewRegistryConflict
	}
	if old == nil && len(r.byRoute) >= r.maximum {
		r.mu.Unlock()
		return ErrDataCarrierPreviewRegistryConflict
	}
	if old != nil {
		old.close()
		delete(r.byHost, old.host)
		r.removeAliasesForRouteLocked(old.route.RouteID)
	}
	r.byRoute[validated.RouteID] = entry
	r.byHost[entry.host] = entry
	r.activateDesiredAliasesForRouteLocked(validated.RouteID)
	r.mu.Unlock()
	go r.watchEntry(entry)
	return nil
}

// AttachAdmission converts one fully validated server admission into a ready
// route. The authenticated Server identity is authoritative; a caller cannot
// attach a route by supplying a different Identity value.
func (r *DataCarrierPreviewRegistry) AttachAdmission(admission datacarrier.ExpectedAdmission, server *datacarrier.Server) error {
	if r == nil || server == nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	if err := admission.Validate(time.Now().UTC(), admission.EdgeNodeID); err != nil {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	if server.Identity() != admission.Identity {
		return ErrDataCarrierPreviewRegistryStale
	}
	return r.Attach(DataCarrierPreviewRoute{
		RouteID: admission.RouteID, Hostname: admission.Hostname, Kind: admission.RouteKind,
		Revision: admission.RouteRevision, Identity: admission.Identity, Server: server,
		PreviewID: admission.PreviewID, OperationID: admission.OperationID,
		OwnerDeviceID: admission.OwnerDeviceID, OwnerSessionID: admission.OwnerSessionID,
		AccessMode:                           admission.AccessMode,
		EdgeNodeID:                           admission.EdgeNodeID,
		EdgeProcessEpoch:                     admission.EdgeProcessEpoch,
		EdgeCarrierServerSPKISHA256:          admission.EdgeCarrierServerSPKISHA256,
		EdgeCarrierServerCertificateChainPEM: admission.EdgeCarrierServerCertificateChainPEM,
		LeaseGeneration:                      admission.LeaseGeneration, AttachmentGeneration: admission.AttachmentGeneration,
		ConfigContentHash: admission.ConfigContentHash, Endpoint: admission.Endpoint,
		ExpiresAt: admission.ExpiresAt, MachineIdentityPublicKey: admission.MachineIdentityPublicKey,
		MachineIdentityThumbprint: admission.MachineIdentityThumbprint,
	})
}

func (r *DataCarrierPreviewRegistry) validateRoute(route DataCarrierPreviewRoute) (DataCarrierPreviewRoute, error) {
	if route.Server == nil || connectorprotocol.ValidateIdentifier(route.RouteID) != nil || route.Revision == 0 || route.Kind != dataCarrierPreviewRouteKind && route.Kind != dataCarrierPreviewPrivateRouteKind {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	if route.Kind == dataCarrierPreviewPrivateRouteKind && route.AccessMode != "private" && route.AccessMode != "team" || route.Kind == dataCarrierPreviewRouteKind && route.AccessMode != "" && route.AccessMode != "public" {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	if route.AccessMode == "" {
		if route.Kind == dataCarrierPreviewPrivateRouteKind {
			return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
		}
		route.AccessMode = "public"
	}
	if route.AccessMode != "public" && route.AccessMode != "private" && route.AccessMode != "team" {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	if route.Kind != dataCarrierPreviewRouteKind && route.Kind != dataCarrierPreviewPrivateRouteKind {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	if connectorprotocol.ValidateOpaqueEpoch(route.EdgeProcessEpoch) != nil || route.EdgeProcessEpoch != r.processEpoch {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	host := normalizePreviewCarrierHost(route.Hostname)
	if !validPreviewCarrierHost(host) || r.baseDomain != "" && !previewHostInBaseDomain(host, r.baseDomain) {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	identity := route.Server.Identity()
	if err := identity.Validate(); err != nil {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	if route.Identity != (datacarrier.Identity{}) && route.Identity != identity {
		return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
	}
	route.Hostname = host
	route.Identity = identity
	if route.AttachmentGeneration != 0 {
		if connectorprotocol.ValidateIdentifier(route.OperationID) != nil || connectorprotocol.ValidateIdentifier(route.PreviewID) != nil || connectorprotocol.ValidateIdentifier(route.OwnerDeviceID) != nil || connectorprotocol.ValidateIdentifier(route.OwnerSessionID) != nil || route.OwnerDeviceID != identity.HostID || route.LeaseGeneration == 0 || route.ConfigContentHash == "" || route.Endpoint == "" || route.ExpiresAt.IsZero() || !route.ExpiresAt.After(time.Now().UTC()) {
			return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
		}
		if route.MachineIdentityPublicKey == "" || route.MachineIdentityThumbprint == "" {
			return DataCarrierPreviewRoute{}, ErrDataCarrierPreviewRegistryInvalid
		}
	}
	return route, nil
}

func (r *DataCarrierPreviewRegistry) watchEntry(entry *dataCarrierPreviewRouteEntry) {
	if entry == nil || entry.route.Server == nil {
		return
	}
	select {
	case <-entry.route.Server.Done():
		r.detachEntry(entry)
	case <-r.done:
	}
}

func (r *DataCarrierPreviewRegistry) detachEntry(entry *dataCarrierPreviewRouteEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.byRoute[entry.route.RouteID]; current == entry {
		delete(r.byRoute, entry.route.RouteID)
		delete(r.byHost, entry.host)
		r.removeAliasesForRouteLocked(entry.route.RouteID)
		entry.close()
	}
}

// Detach removes a route only when its exact identity and revision are still
// current. It is idempotent for an already-replaced or absent route.
func (r *DataCarrierPreviewRegistry) Detach(routeID string, identity datacarrier.Identity, revision uint64) error {
	if r == nil || connectorprotocol.ValidateIdentifier(routeID) != nil || revision == 0 {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	entry := r.byRoute[routeID]
	if entry == nil {
		return nil
	}
	if entry.route.Revision != revision || entry.route.Identity != identity {
		return ErrDataCarrierPreviewRegistryStale
	}
	delete(r.byRoute, routeID)
	delete(r.byHost, entry.host)
	r.removeAliasesForRouteLocked(routeID)
	entry.close()
	return nil
}

// DetachAdmission removes only the exact current server admission. A stale
// callback from a released or replaced attachment cannot remove the current
// route, even if it reuses the same route ID.
func (r *DataCarrierPreviewRegistry) DetachAdmission(admission datacarrier.ExpectedAdmission) error {
	if r == nil || connectorprotocol.ValidateIdentifier(admission.RouteID) != nil || connectorprotocol.ValidateIdentifier(admission.OperationID) != nil || admission.AttachmentGeneration == 0 {
		return ErrDataCarrierPreviewRegistryInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	entry := r.byRoute[admission.RouteID]
	if entry == nil {
		return nil
	}
	if entry.route.OperationID != admission.OperationID || entry.route.AttachmentGeneration != admission.AttachmentGeneration || entry.route.Identity != admission.Identity || entry.route.Revision != admission.RouteRevision || entry.route.EdgeProcessEpoch != admission.EdgeProcessEpoch {
		return ErrDataCarrierPreviewRegistryStale
	}
	delete(r.byRoute, admission.RouteID)
	delete(r.byHost, entry.host)
	r.removeAliasesForRouteLocked(admission.RouteID)
	entry.close()
	return nil
}

func (r *DataCarrierPreviewRegistry) acquire(host string) (DataCarrierPreviewRoute, <-chan struct{}, bool) {
	if r == nil {
		return DataCarrierPreviewRoute{}, nil, false
	}
	normalized := normalizePreviewCarrierHost(host)
	r.mu.RLock()
	entry, ok := r.lookupHostLocked(normalized)
	if !ok {
		r.mu.RUnlock()
		return DataCarrierPreviewRoute{}, nil, false
	}
	value, done := entry.route, entry.done
	value.Hostname = normalized
	r.mu.RUnlock()
	return value, done, true
}

func (r *DataCarrierPreviewRegistry) Lookup(host string) (DataCarrierPreviewRoute, bool) {
	if r == nil {
		return DataCarrierPreviewRoute{}, false
	}
	normalized := normalizePreviewCarrierHost(host)
	r.mu.RLock()
	entry, ok := r.lookupHostLocked(normalized)
	if !ok {
		r.mu.RUnlock()
		return DataCarrierPreviewRoute{}, false
	}
	route := entry.route
	route.Hostname = normalized
	r.mu.RUnlock()
	return route, true
}

// RouteState implements the gateway readiness projection. A route appears
// ready only while its exact authenticated carrier is still registered.
// Pending admissions are deliberately invisible, so public traffic cannot
// race ahead of the carrier handshake and route attachment.
func (r *DataCarrierPreviewRegistry) RouteState(host string) (string, string, string, bool) {
	route, ok := r.Lookup(host)
	if !ok || route.Server == nil {
		return "", "", "", false
	}
	if !route.ExpiresAt.IsZero() && !route.ExpiresAt.After(time.Now().UTC()) {
		return route.Kind, "expired", "attachment_expired", true
	}
	select {
	case <-route.Server.Done():
		return "", "", "", false
	default:
		return route.Kind, "ready", "", true
	}
}

func (r *DataCarrierPreviewRegistry) Route(routeID string) (DataCarrierPreviewRoute, bool) {
	if r == nil || connectorprotocol.ValidateIdentifier(routeID) != nil {
		return DataCarrierPreviewRoute{}, false
	}
	r.mu.RLock()
	entry, ok := r.byRoute[routeID]
	if !ok {
		r.mu.RUnlock()
		return DataCarrierPreviewRoute{}, false
	}
	route := entry.route
	r.mu.RUnlock()
	return route, true
}

func (r *DataCarrierPreviewRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byRoute)
}

// Snapshot returns a deterministic copy of current routes for reconciliation
// and shutdown. Server pointers are handles owned by the datacarrier service;
// this registry never closes them as part of a route removal.
func (r *DataCarrierPreviewRegistry) Snapshot() []DataCarrierPreviewRoute {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]DataCarrierPreviewRoute, 0, len(r.byRoute))
	for _, entry := range r.byRoute {
		result = append(result, entry.route)
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

func (r *DataCarrierPreviewRegistry) Done() <-chan struct{} {
	if r == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return r.done
}

func (r *DataCarrierPreviewRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		for _, entry := range r.byRoute {
			entry.close()
		}
		r.byRoute = make(map[string]*dataCarrierPreviewRouteEntry)
		r.byHost = make(map[string]*dataCarrierPreviewRouteEntry)
		r.aliasesByID = make(map[string]DataCarrierPreviewAlias)
		r.aliasIDsByRoute = make(map[string]map[string]struct{})
		r.desiredAliases = make(map[string]DataCarrierPreviewAlias)
		r.mu.Unlock()
		close(r.done)
	})
	return nil
}

func sameDataCarrierPreviewRoute(left, right DataCarrierPreviewRoute) bool {
	return left.RouteID == right.RouteID && left.Hostname == right.Hostname && left.Kind == right.Kind && left.Revision == right.Revision && left.Identity == right.Identity && left.Server == right.Server && left.PreviewID == right.PreviewID && left.OperationID == right.OperationID && left.OwnerDeviceID == right.OwnerDeviceID && left.OwnerSessionID == right.OwnerSessionID && left.AccessMode == right.AccessMode && left.EdgeNodeID == right.EdgeNodeID && left.EdgeProcessEpoch == right.EdgeProcessEpoch && left.LeaseGeneration == right.LeaseGeneration && left.AttachmentGeneration == right.AttachmentGeneration && left.ConfigContentHash == right.ConfigContentHash && left.Endpoint == right.Endpoint && left.ExpiresAt.Equal(right.ExpiresAt) && left.MachineIdentityPublicKey == right.MachineIdentityPublicKey && left.MachineIdentityThumbprint == right.MachineIdentityThumbprint
}

func newerDataCarrierPreviewRoute(old, next DataCarrierPreviewRoute) bool {
	if next.RouteID != old.RouteID || next.Hostname != old.Hostname || next.Kind != old.Kind ||
		next.Identity.AccountID != old.Identity.AccountID || next.Identity.HostID != old.Identity.HostID ||
		next.Identity.TunnelID != old.Identity.TunnelID || next.Identity.ConnectorID != old.Identity.ConnectorID || next.OperationID != old.OperationID || next.PreviewID != old.PreviewID || next.OwnerDeviceID != old.OwnerDeviceID || next.OwnerSessionID != old.OwnerSessionID || next.AccessMode != old.AccessMode || next.EdgeNodeID != old.EdgeNodeID {
		return false
	}
	if next.AttachmentGeneration != 0 && old.AttachmentGeneration != 0 && next.AttachmentGeneration < old.AttachmentGeneration {
		return false
	}
	if next.EdgeProcessEpoch != old.EdgeProcessEpoch || next.Identity.ProcessGeneration < old.Identity.ProcessGeneration || next.Identity.Generation < old.Identity.Generation {
		return false
	}
	if next.Identity.ProcessGeneration == old.Identity.ProcessGeneration && next.Identity.SessionID != old.Identity.SessionID {
		return false
	}
	return next.AttachmentGeneration > old.AttachmentGeneration || next.Identity.ProcessGeneration > old.Identity.ProcessGeneration || next.Identity.Generation > old.Identity.Generation || next.Revision > old.Revision
}

func normalizePreviewCarrierHost(value string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(host, ".")
}

func validPreviewCarrierDomain(value string) bool {
	return validPreviewCarrierHost(value)
}

func validPreviewCarrierHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@[] 	\r\n") || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
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

func previewHostInBaseDomain(host, base string) bool {
	suffix := "." + base
	prefix, ok := strings.CutSuffix(host, suffix)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

// DataCarrierPreviewTransport speaks HTTP directly over an authenticated
// edge Server. It is a streaming RoundTripper: request and response bodies
// stay on the carrier stream and cancellation closes the stream immediately.
type DataCarrierPreviewTransport struct {
	registry *DataCarrierPreviewRegistry
	openWait time.Duration
	nextID   atomic.Uint64
}

type DataCarrierPreviewTransportConfig struct {
	Registry          *DataCarrierPreviewRegistry
	StreamOpenTimeout time.Duration
}

func NewDataCarrierPreviewTransport(config DataCarrierPreviewTransportConfig) (*DataCarrierPreviewTransport, error) {
	if config.Registry == nil {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	if config.StreamOpenTimeout == 0 {
		config.StreamOpenTimeout = dataCarrierPreviewDefaultOpenTimeout
	}
	if config.StreamOpenTimeout <= 0 || config.StreamOpenTimeout > time.Minute {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	return &DataCarrierPreviewTransport{registry: config.Registry, openWait: config.StreamOpenTimeout}, nil
}

func (t *DataCarrierPreviewTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.registry == nil || request == nil || request.URL == nil {
		return nil, ErrDataCarrierPreviewTransport
	}
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	route, ok := t.registry.Lookup(host)
	if !ok || route.Server == nil {
		return nil, fmt.Errorf("%w: route is not ready", ErrDataCarrierPreviewRegistryUnavailable)
	}
	if !route.ExpiresAt.IsZero() && !route.ExpiresAt.After(time.Now().UTC()) {
		return nil, fmt.Errorf("%w: attachment expired", ErrDataCarrierPreviewRegistryUnavailable)
	}
	decision, browser := request.Context().Value(browserDecisionKey{}).(connectorprotocol.IngressDecision)
	restricted := route.AccessMode == "private" || route.AccessMode == "team"
	if restricted && (!browser || decision.Binding.Audience != route.AccessMode || decision.Binding.PublicationID != route.PreviewID || decision.Binding.Hostname != route.Hostname || decision.Binding.RouteGeneration != route.Revision) {
		return nil, ErrDataCarrierPreviewTransport
	}
	if !restricted && browser {
		return nil, ErrDataCarrierPreviewTransport
	}
	openContext := request.Context()
	lifetimeContext := request.Context()
	var lifetimeCancel context.CancelFunc
	var lifetimeTimer *time.Timer
	openContext, cancelOpen := context.WithTimeout(openContext, t.openWait)
	open := connectorprotocol.StreamOpen{
		Protocol:          connectorprotocol.ProtocolName,
		Version:           connectorprotocol.ProtocolVersion,
		AccountID:         route.Identity.AccountID,
		TunnelID:          route.Identity.TunnelID,
		ConnectorID:       route.Identity.ConnectorID,
		SessionID:         route.Identity.SessionID,
		ProcessGeneration: route.Identity.ProcessGeneration,
		Generation:        route.Identity.Generation,
		RouteID:           route.RouteID,
		RequestID:         fmt.Sprintf("preview-http-%d", t.nextID.Add(1)),
		Kind:              previewStreamKind(request),
	}
	if restricted {
		open.Kind = "http_browser"
		if decision.Authorize(decision, open, route.EdgeNodeID, route.EdgeProcessEpoch, time.Now().UTC()) != nil {
			cancelOpen()
			return nil, ErrDataCarrierPreviewTransport
		}
	}
	stream, err := route.Server.OpenStreamWithLifetime(openContext, lifetimeContext, open)
	cancelOpen()
	if err != nil {
		stopPreviewStreamLifetime(lifetimeCancel, lifetimeTimer)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errors.Join(ErrDataCarrierPreviewTransport, err)
	}
	if restricted {
		if err := connectorprotocol.WriteIngressDecision(stream, decision, time.Now().UTC()); err != nil {
			_ = stream.Close()
			return nil, err
		}
	}
	stopCancel := context.AfterFunc(request.Context(), func() { _ = stream.Close() })
	out := request.Clone(request.Context())
	out.RequestURI = ""
	out.URL.Scheme = ""
	out.URL.Host = ""
	out.Host = route.Hostname
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
	headerContext, cancelHeader := context.WithTimeout(request.Context(), t.openWait)
	stopHeader := context.AfterFunc(headerContext, func() { _ = stream.Close() })
	headerReader := &boundedPreviewResponseHeaderReader{reader: stream, maximum: dataCarrierPreviewMaxResponseHeader}
	response, err := http.ReadResponse(bufio.NewReader(headerReader), out)
	headerTimedOut := errors.Is(headerContext.Err(), context.DeadlineExceeded)
	stopHeader()
	cancelHeader()
	if err != nil {
		stopCancel()
		stopPreviewStreamLifetime(lifetimeCancel, lifetimeTimer)
		_ = stream.Close()
		if headerTimedOut {
			timeoutErr := &dataCarrierPreviewResponseHeaderTimeoutError{timeout: t.openWait}
			select {
			case writeErr := <-writeDone:
				return nil, errors.Join(ErrDataCarrierPreviewTransport, timeoutErr, writeErr)
			default:
				return nil, errors.Join(ErrDataCarrierPreviewTransport, timeoutErr)
			}
		}
		select {
		case writeErr := <-writeDone:
			return nil, errors.Join(ErrDataCarrierPreviewTransport, err, writeErr)
		default:
			return nil, errors.Join(ErrDataCarrierPreviewTransport, err)
		}
	}
	response.Request = request
	response.Body = &dataCarrierPreviewResponseBody{body: response.Body, stream: stream, stopCancel: stopCancel, writeDone: writeDone, lifetimeCancel: lifetimeCancel, lifetimeTimer: lifetimeTimer}
	return response, nil
}

type boundedPreviewResponseHeaderReader struct {
	reader  io.Reader
	maximum int
	read    int
	match   int
	done    bool
}

func (r *boundedPreviewResponseHeaderReader) Read(payload []byte) (int, error) {
	n, err := r.reader.Read(payload)
	if r.done || n == 0 {
		return n, err
	}
	separator := [...]byte{'\r', '\n', '\r', '\n'}
	for index := 0; index < n; index++ {
		r.read++
		if r.read > r.maximum {
			return 0, fmt.Errorf("%w: response headers exceed %d bytes", ErrDataCarrierPreviewTransport, r.maximum)
		}
		if payload[index] == separator[r.match] {
			r.match++
			if r.match == len(separator) {
				r.done = true
				break
			}
		} else if payload[index] == separator[0] {
			r.match = 1
		} else {
			r.match = 0
		}
	}
	return n, err
}

type dataCarrierPreviewResponseHeaderTimeoutError struct {
	timeout time.Duration
}

func (e *dataCarrierPreviewResponseHeaderTimeoutError) Error() string {
	if e == nil {
		return ErrDataCarrierPreviewResponseHeaderTimeout.Error()
	}
	return fmt.Sprintf("%s after %s", ErrDataCarrierPreviewResponseHeaderTimeout, e.timeout)
}

func (e *dataCarrierPreviewResponseHeaderTimeoutError) Is(target error) bool {
	return target == ErrDataCarrierPreviewResponseHeaderTimeout
}

func (*dataCarrierPreviewResponseHeaderTimeoutError) Timeout() bool   { return true }
func (*dataCarrierPreviewResponseHeaderTimeoutError) Temporary() bool { return true }

func previewStreamKind(request *http.Request) string {
	if request != nil && strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return "websocket"
	}
	if request != nil && strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/grpc") {
		return "grpc"
	}
	return "https"
}

type dataCarrierPreviewResponseBody struct {
	body           io.ReadCloser
	stream         io.Closer
	stopCancel     func() bool
	writeDone      <-chan error
	lifetimeCancel context.CancelFunc
	lifetimeTimer  *time.Timer
	once           sync.Once
	err            error
}

func (b *dataCarrierPreviewResponseBody) Read(payload []byte) (int, error) {
	if b == nil || b.body == nil {
		return 0, io.EOF
	}
	n, err := b.body.Read(payload)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}

func (b *dataCarrierPreviewResponseBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		stopPreviewStreamLifetime(b.lifetimeCancel, b.lifetimeTimer)
		if b.stopCancel != nil {
			b.stopCancel()
		}
		if b.body != nil {
			if err := b.body.Close(); !expectedPrivateStreamClose(err) {
				b.err = err
			}
		}
		if b.stream != nil {
			if err := b.stream.Close(); b.err == nil && !expectedPrivateStreamClose(err) {
				b.err = err
			}
		}
		if b.writeDone != nil {
			select {
			case err := <-b.writeDone:
				if b.err == nil && !expectedPrivateStreamClose(err) {
					b.err = err
				}
			default:
			}
		}
	})
	return b.err
}

func expectedPrivateStreamClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func stopPreviewStreamLifetime(cancel context.CancelFunc, timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
	if cancel != nil {
		cancel()
	}
}
