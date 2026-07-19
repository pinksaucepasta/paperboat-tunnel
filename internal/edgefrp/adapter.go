package edgefrp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

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
	run      admission.RunID
	attached []route.Attachment
	routes   []admission.Route
	active   map[string]uint32
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
	stats := Stats{Sessions: len(a.sessions)}
	for _, current := range a.sessions {
		stats.Routes += len(current.attached)
		for _, count := range current.active {
			stats.ActiveStreams += count
		}
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
	if uint32(len(a.sessions)) >= a.Capacity {
		a.mu.Unlock()
		return admission.Response{}, edgeerrors.New(edgeerrors.CodeServiceUnavailable, "connector capacity is exhausted", "retry admission on an available node")
	}

	attached := make([]route.Attachment, 0, len(response.Routes))
	for _, handedOff := range response.Routes {
		attachedRoute := route.Attachment{ID: handedOff.RouteID, Revision: handedOff.Revision, Environment: response.Environment, Node: response.EdgeNode, Generation: response.Generation, Kind: route.Kind(handedOff.Kind), Host: handedOff.PublicHost, Target: net.JoinHostPort(handedOff.TargetHost, strconv.Itoa(int(handedOff.TargetPort)))}
		if _, err := a.Routes.Attach(attachedRoute); err != nil {
			for _, previous := range attached {
				_ = a.Routes.Detach(previous.ID, previous.Revision)
			}
			a.mu.Unlock()
			return admission.Response{}, err
		}
		attached = append(attached, attachedRoute)
	}
	a.sessions[response.RunID.Value] = session{run: response.RunID, attached: attached, routes: append([]admission.Route(nil), response.Routes...), active: make(map[string]uint32)}
	a.mu.Unlock()
	return response, nil
}

func (a *Adapter) Revoke(runID string) {
	a.mu.Lock()
	deferred := a.sessions[runID]
	delete(a.sessions, runID)
	a.mu.Unlock()
	deferred.run.Revoked = true
	for _, attached := range deferred.attached {
		_ = a.Routes.Detach(attached.ID, attached.Revision)
	}
}

func (a *Adapter) Close(runID string) { a.Revoke(runID) }

func (a *Adapter) AuthorizeProxy(runID, proxyName, proxyType, publicHost string) error {
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
		if handedOff.ProxyName == proxyName && normalizePublicHost(handedOff.PublicHost) == publicHost {
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
		if authoritative, exists := a.Routes.Get(attached.ID); exists && authoritative == attached {
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
		if handedOff.ProxyName == proxyName && index < len(current.attached) {
			attached := current.attached[index]
			authoritative, exists := a.Routes.Get(attached.ID)
			if !exists || authoritative != attached {
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
		if handedOff.ProxyName == proxyName && i < len(current.attached) {
			detached = append(detached, current.attached[i])
			continue
		}
		keptRoutes = append(keptRoutes, handedOff)
		if i < len(current.attached) {
			keptAttachments = append(keptAttachments, current.attached[i])
		}
	}
	current.routes, current.attached = keptRoutes, keptAttachments
	a.sessions[runID] = current
	a.mu.Unlock()
	for _, attached := range detached {
		_ = a.Routes.Detach(attached.ID, attached.Revision)
	}
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
		if handedOff.ProxyName == proxyName {
			return a.Traffic.Record(current.routesEnvironment(), handedOff.RouteID, handedOff.Revision, ingress, egress)
		}
	}
	return route.ErrInvalid
}

func (s session) routesEnvironment() string {
	if len(s.attached) == 0 {
		return ""
	}
	return s.attached[0].Environment
}
