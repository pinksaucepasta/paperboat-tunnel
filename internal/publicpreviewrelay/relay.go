package publicpreviewrelay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

const Path = "/v1/public-preview-relay"

var (
	ErrInvalid     = errors.New("public preview relay attachment invalid")
	ErrUnavailable = errors.New("public preview relay unavailable")
)

type Manager struct {
	Admissions *admission.Service
	Routes     *route.Registry

	mu           sync.Mutex
	sessions     map[string]*session
	changed      map[string]chan struct{}
	reconnecting map[string]route.Attachment
}

type session struct {
	run        admission.RunID
	attachment route.Attachment
	mux        *yamux.Session
	active     uint32
	retired    bool
}

func New(admissions *admission.Service, routes *route.Registry) (*Manager, error) {
	if admissions == nil || routes == nil {
		return nil, ErrInvalid
	}
	return &Manager{Admissions: admissions, Routes: routes, sessions: make(map[string]*session), changed: make(map[string]chan struct{}), reconnecting: make(map[string]route.Attachment)}, nil
}

func (m *Manager) Admit(ctx context.Context, request admission.Request) (admission.Response, error) {
	if ctx == nil || len(request.Routes) != 1 || request.Routes[0].Kind != "preview_public_https_wss" {
		return admission.Response{}, ErrInvalid
	}
	response, err := m.Admissions.Admit(ctx, request)
	if err != nil {
		return admission.Response{}, err
	}
	handoff := response.Routes[0]
	wantBinding := routeBinding(response.Routes)
	if subtle.ConstantTimeCompare([]byte(response.RouteBinding), []byte(wantBinding)) != 1 {
		return admission.Response{}, ErrInvalid
	}
	attached := route.Attachment{ID: handoff.RouteID, Revision: handoff.Revision, Environment: response.Environment, Node: response.EdgeNode, Generation: response.Generation, Kind: route.Kind(handoff.Kind), Host: normalizeHost(handoff.PublicHost), Target: net.JoinHostPort(handoff.TargetHost, strconv.Itoa(int(handoff.TargetPort)))}
	if _, err := m.Routes.Attach(attached); err != nil {
		return admission.Response{}, err
	}
	return response, nil
}

func routeBinding(routes []admission.Route) string {
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(routes)))
	_, _ = hash.Write(size[:])
	for _, item := range routes {
		for _, value := range []string{item.RouteID, item.Kind, item.PublicHost, item.ProxyName, item.TargetHost} {
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = hash.Write(size[:])
			_, _ = io.WriteString(hash, value)
		}
		binary.BigEndian.PutUint64(size[:], item.Revision)
		_, _ = hash.Write(size[:])
		binary.BigEndian.PutUint64(size[:], uint64(item.TargetPort))
		_, _ = hash.Write(size[:])
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func (m *Manager) Attach(ctx context.Context, response admission.Response, carrier io.ReadWriteCloser) error {
	if ctx == nil || carrier == nil || len(response.Routes) != 1 {
		if carrier != nil {
			_ = carrier.Close()
		}
		return ErrInvalid
	}
	handoff := response.Routes[0]
	attached := route.Attachment{ID: handoff.RouteID, Revision: handoff.Revision, Environment: response.Environment, Node: response.EdgeNode, Generation: response.Generation, Kind: route.Kind(handoff.Kind), Host: normalizeHost(handoff.PublicHost), Target: net.JoinHostPort(handoff.TargetHost, strconv.Itoa(int(handoff.TargetPort)))}
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 10 * time.Second
	config.ConnectionWriteTimeout = 10 * time.Second
	mux, err := yamux.Server(carrier, config)
	if err != nil {
		_ = carrier.Close()
		return err
	}
	current := &session{run: response.RunID, attachment: attached, mux: mux}
	host := normalizeHost(handoff.PublicHost)
	m.mu.Lock()
	old := m.sessions[host]
	m.sessions[host] = current
	delete(m.reconnecting, host)
	if old != nil {
		old.retired = true
	}
	m.signalChangedLocked(host)
	m.mu.Unlock()
	if old != nil {
		m.closeSession(old)
	}
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case <-mux.CloseChan():
		result = ErrUnavailable
	}
	m.mu.Lock()
	if m.sessions[host] == current {
		delete(m.sessions, host)
		m.reconnecting[host] = current.attachment
		m.signalChangedLocked(host)
	}
	current.retired = true
	active := current.active
	m.mu.Unlock()
	if active == 0 {
		m.closeSession(current)
	}
	return result
}

func (m *Manager) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host := normalizeHost(address)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = normalizeHost(parsed)
	}
	for {
		m.mu.Lock()
		current := m.sessions[host]
		if current != nil && !current.retired && m.Routes.Owns(current.attachment) {
			current.active++
			m.mu.Unlock()
			stream, err := current.mux.OpenStream()
			if err != nil {
				m.release(current)
				return nil, errors.Join(ErrUnavailable, err)
			}
			return &trackedConn{Conn: stream, release: func() { m.release(current) }}, nil
		}
		failed, reconnecting := m.reconnecting[host]
		if !reconnecting || !m.Routes.Owns(failed) {
			m.mu.Unlock()
			return nil, ErrUnavailable
		}
		changed := m.changedLocked(host)
		routeChanged := m.Routes.Changed(host)
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, errors.Join(ErrUnavailable, ctx.Err())
		case <-changed:
		case <-routeChanged:
		}
	}
}

func (m *Manager) changedLocked(host string) chan struct{} {
	changed := m.changed[host]
	if changed == nil {
		changed = make(chan struct{})
		m.changed[host] = changed
	}
	return changed
}

func (m *Manager) signalChangedLocked(host string) {
	changed := m.changedLocked(host)
	close(changed)
	m.changed[host] = make(chan struct{})
}

func (m *Manager) RouteState(host string) (string, string, string, bool) {
	kind, state, reason, found := m.Routes.RouteState(host)
	if !found || kind != "preview_public_https_wss" {
		return kind, state, reason, found
	}
	m.mu.Lock()
	current := m.sessions[normalizeHost(host)]
	ready := current != nil && !current.retired
	m.mu.Unlock()
	if !ready {
		return kind, "registering", "relay_unavailable", true
	}
	return kind, "ready", "", true
}

func (m *Manager) release(current *session) {
	m.mu.Lock()
	if current.active > 0 {
		current.active--
	}
	closeNow := current.retired && current.active == 0
	m.mu.Unlock()
	if closeNow {
		m.closeSession(current)
	}
}

func (m *Manager) closeSession(current *session) {
	_ = current.mux.Close()
}

func normalizeHost(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
