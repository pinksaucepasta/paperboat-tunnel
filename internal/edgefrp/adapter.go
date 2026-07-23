package edgefrp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

var ErrRunUnknown = errors.New("connector run is unknown")

// Adapter is the narrow Paperboat-owned boundary around the pinned frp server.
// frp must not be allowed to mutate proxy state until Login has succeeded here.
type Adapter struct {
	Admissions *admission.Service
	Routes     *route.Registry
	Traffic    TrafficRecorder
	Now        func() time.Time
	Capacity   uint32

	mu       sync.Mutex
	sessions map[string]session
}

type TrafficRecorder interface {
	Record(environment, route string, revision uint64, ingress, egress uint64) error
}

type session struct {
	run         admission.RunID
	environment string
	helper      string
	attached    []route.Attachment
	routes      []admission.Route
	active      map[string]uint32
	registered  map[string]bool
	operationID string
}

type Stats struct {
	Sessions      int
	Routes        int
	ActiveStreams uint32
}

func NewAdapter(admissions *admission.Service, routes *route.Registry, capacity ...uint32) *Adapter {
	limit := uint32(128)
	if len(capacity) == 1 && capacity[0] > 0 {
		limit = capacity[0]
	}
	return &Adapter{Admissions: admissions, Routes: routes, Capacity: limit, sessions: make(map[string]session)}
}

func (a *Adapter) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	stats := Stats{}
	for _, current := range a.sessions {
		for _, count := range current.active {
			stats.ActiveStreams += count
		}
		if current.run.Resume(current.run.Value, current.run.Generation, now) != nil {
			continue
		}
		stats.Sessions++
		stats.Routes += len(current.attached)
	}
	return stats
}

func (a *Adapter) Login(ctx context.Context, request admission.Request) (admission.Response, error) {
	response, err := a.Admissions.Admit(ctx, request)
	if err != nil {
		return admission.Response{}, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	a.mu.Lock()
	if existing, ok := a.sessions[response.RunID.Value]; ok {
		a.mu.Unlock()
		if err := existing.run.Resume(response.RunID.Value, response.Generation, now); err != nil {
			return admission.Response{}, err
		}
		return response, nil
	}
	replaced := make([]string, 0, 1)
	for runID, current := range a.sessions {
		if current.environment == response.Environment && current.helper == response.Helper {
			replaced = append(replaced, runID)
		}
	}
	if uint32(len(a.sessions)-len(replaced)) >= a.Capacity {
		a.mu.Unlock()
		return admission.Response{}, edgeerrors.New(edgeerrors.CodeServiceUnavailable, "connector capacity is exhausted", "retry admission on an available node")
	}

	attached, err := a.attachRoutes(response)
	if err != nil {
		a.mu.Unlock()
		return admission.Response{}, err
	}
	// Credential refresh intentionally overlaps the old and new FRP controls.
	// Unique physical proxy names share one strictly authorized HTTP group; the
	// old run remains tracked until its drain callbacks arrive.
	a.sessions[response.RunID.Value] = session{run: response.RunID, environment: response.Environment, helper: response.Helper, attached: attached, routes: append([]admission.Route(nil), response.Routes...), active: make(map[string]uint32), registered: make(map[string]bool), operationID: request.OperationID}
	a.mu.Unlock()
	return response, nil
}

// Resume authenticates the original admission again, then rotates the frp run
// ID. frps replaces controls by run ID; reusing it would let delayed close
// callbacks from the retired control tear down the replacement's routes.
func (a *Adapter) Resume(ctx context.Context, request admission.Request, priorRunID string) (admission.Response, error) {
	response, err := a.Admissions.Admit(ctx, request)
	if err != nil {
		return admission.Response{}, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.sessions[priorRunID]
	if !ok {
		return admission.Response{}, ErrRunUnknown
	}
	if current.environment != response.Environment || current.helper != response.Helper || current.run.Generation != response.Generation {
		return admission.Response{}, route.ErrInvalid
	}
	if err := current.run.Resume(priorRunID, response.Generation, now); err != nil {
		return admission.Response{}, err
	}
	replacement, err := admission.NewRunID(response.Generation, current.run.ExpiresAt)
	if err != nil {
		return admission.Response{}, err
	}
	delete(a.sessions, priorRunID)
	current.run = replacement
	current.active = make(map[string]uint32)
	current.registered = make(map[string]bool)
	a.sessions[replacement.Value] = current
	response.RunID = replacement
	return response, nil
}

func (a *Adapter) attachRoutes(response admission.Response) ([]route.Attachment, error) {
	attached := make([]route.Attachment, 0, len(response.Routes))
	for _, handedOff := range response.Routes {
		attachedRoute := route.Attachment{ID: handedOff.RouteID, Revision: handedOff.Revision, Environment: response.Environment, Node: response.EdgeNode, Generation: response.Generation, Kind: route.Kind(handedOff.Kind), Host: handedOff.PublicHost, Target: net.JoinHostPort(handedOff.TargetHost, strconv.Itoa(int(handedOff.TargetPort)))}
		if _, err := a.Routes.Attach(attachedRoute); err != nil {
			return nil, err
		}
		attached = append(attached, attachedRoute)
	}
	return attached, nil
}

func (a *Adapter) Revoke(runID string) {
	a.mu.Lock()
	deferred := a.sessions[runID]
	delete(a.sessions, runID)
	a.mu.Unlock()
	deferred.run.Revoked = true
	for _, attached := range deferred.attached {
		a.detachUnlessShared(attached)
	}
}

func (a *Adapter) Close(runID string) { a.Revoke(runID) }

func (a *Adapter) AuthorizeProxy(runID, proxyName, proxyType, publicHost, group, groupKey string) error {
	a.mu.Lock()
	current, ok := a.sessions[runID]
	a.mu.Unlock()
	if !ok || proxyType != "http" {
		return route.ErrInvalid
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if err := current.run.Resume(runID, current.run.Generation, now); err != nil {
		return err
	}
	publicHost = normalizePublicHost(publicHost)
	for _, handedOff := range current.routes {
		identity := frpProxyIdentity(current, handedOff)
		if identity.name == proxyName && identity.group == group && identity.groupKey == groupKey && normalizePublicHost(handedOff.PublicHost) == publicHost {
			a.mu.Lock()
			latest, exists := a.sessions[runID]
			if exists {
				latest.registered[proxyName] = true
				a.sessions[runID] = latest
			}
			a.mu.Unlock()
			if !exists {
				return route.ErrInvalid
			}
			return nil
		}
	}
	return route.ErrInvalid
}

func normalizePublicHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func (a *Adapter) AuthorizeProxyRun(runID string) error {
	a.mu.Lock()
	current, ok := a.sessions[runID]
	a.mu.Unlock()
	if !ok {
		return route.ErrInvalid
	}
	currentRoute := false
	for _, attached := range current.attached {
		if a.Routes.Owns(attached) {
			currentRoute = true
			break
		}
	}
	if !currentRoute {
		return route.ErrInvalid
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	return current.run.Resume(runID, current.run.Generation, now)
}

func (a *Adapter) AuthorizeStream(runID, proxyName, proxyType string) error {
	if err := a.AuthorizeProxyRun(runID); err != nil {
		return err
	}
	if proxyType != "http" {
		return route.ErrInvalid
	}
	a.mu.Lock()
	current := a.sessions[runID]
	a.mu.Unlock()
	for index, handedOff := range current.routes {
		if frpProxyIdentity(current, handedOff).name == proxyName && index < len(current.attached) {
			attached := current.attached[index]
			if !a.Routes.Owns(attached) {
				return route.ErrInvalid
			}
			a.mu.Lock()
			latest, ok := a.sessions[runID]
			if !ok || latest.active[proxyName] == ^uint32(0) {
				a.mu.Unlock()
				return route.ErrInvalid
			}
			latest.active[proxyName]++
			a.sessions[runID] = latest
			a.mu.Unlock()
			return nil
		}
	}
	return route.ErrInvalid
}

func (a *Adapter) CloseStream(runID, proxyName string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.sessions[runID]
	if !ok || current.active[proxyName] == 0 {
		return
	}
	current.active[proxyName]--
	if current.active[proxyName] == 0 {
		delete(current.active, proxyName)
	}
	a.sessions[runID] = current
}

func (a *Adapter) CloseProxy(runID, proxyName string) {
	a.mu.Lock()
	current, ok := a.sessions[runID]
	if !ok {
		a.mu.Unlock()
		return
	}
	keptRoutes := current.routes[:0]
	keptAttachments := current.attached[:0]
	var detached []route.Attachment
	for i, handedOff := range current.routes {
		if frpProxyIdentity(current, handedOff).name == proxyName && i < len(current.attached) {
			detached = append(detached, current.attached[i])
			continue
		}
		keptRoutes = append(keptRoutes, handedOff)
		if i < len(current.attached) {
			keptAttachments = append(keptAttachments, current.attached[i])
		}
	}
	current.routes, current.attached = keptRoutes, keptAttachments
	if len(current.routes) == 0 {
		// FRP sends CloseProxy when a helper drains its client. Do not retain an
		// empty generation: stale sessions otherwise consume capacity and make a
		// subsequent resume appear as route drift.
		delete(a.sessions, runID)
		current.run.Revoked = true
	} else {
		a.sessions[runID] = current
	}
	a.mu.Unlock()
	for _, attached := range detached {
		a.detachUnlessShared(attached)
	}
}

// RouteState gates public traffic on a registered proxy belonging to the live
// admitted connector. Preview target state remains control-plane authoritative.
func (a *Adapter) RouteState(host string) (string, string, string, bool) {
	kind, state, reason, found := a.Routes.RouteState(host)
	if !found {
		return "", "", "", false
	}
	normalized := normalizePublicHost(host)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, current := range a.sessions {
		if current.run.Resume(current.run.Value, current.run.Generation, a.now()) != nil {
			continue
		}
		for index, handedOff := range current.routes {
			if normalizePublicHost(handedOff.PublicHost) != normalized || !current.registered[frpProxyIdentity(current, handedOff).name] || index >= len(current.attached) || !a.Routes.Owns(current.attached[index]) {
				continue
			}
			if kind == string(route.HelperHTTPSWSS) {
				return kind, "ready", "", true
			}
			return kind, state, reason, true
		}
	}
	return kind, "offline", "connector_unavailable", true
}

func (a *Adapter) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Adapter) RecordTraffic(runID, proxyName, proxyType string, ingress, egress uint64) error {
	if a.Traffic == nil || proxyType != "http" || ingress == 0 && egress == 0 {
		return route.ErrInvalid
	}
	a.mu.Lock()
	current, ok := a.sessions[runID]
	a.mu.Unlock()
	if !ok {
		return route.ErrInvalid
	}
	for _, handedOff := range current.routes {
		if frpProxyIdentity(current, handedOff).name == proxyName {
			return a.Traffic.Record(current.routesEnvironment(), handedOff.RouteID, handedOff.Revision, ingress, egress)
		}
	}
	return route.ErrInvalid
}

type frpIdentity struct{ name, group, groupKey string }

func frpProxyIdentity(current session, handedOff admission.Route) frpIdentity {
	stable := current.environment + "\x00" + current.helper + "\x00" + handedOff.RouteID + "\x00" + handedOff.ProxyName
	physical := stable + "\x00" + current.operationID
	return frpIdentity{
		name:     "pbp_" + hashPrefix("paperboat-frp-proxy-v1\x00"+physical, 32),
		group:    "pbg_" + hashPrefix("paperboat-frp-group-v1\x00"+stable, 32),
		groupKey: hashPrefix("paperboat-frp-group-key-v1\x00"+stable, 64),
	}
}

func hashPrefix(value string, length int) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest)[:length]
}

func (a *Adapter) detachUnlessShared(attached route.Attachment) {
	a.mu.Lock()
	for _, current := range a.sessions {
		for _, candidate := range current.attached {
			if candidate == attached {
				a.mu.Unlock()
				return
			}
		}
	}
	a.mu.Unlock()
	_ = a.Routes.Detach(attached.ID, attached.Revision)
}

func (s session) routesEnvironment() string {
	if len(s.attached) == 0 {
		return ""
	}
	return s.attached[0].Environment
}
