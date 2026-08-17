// Package peersignaling owns bounded, authenticated peer signaling sessions.
package peersignaling

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const maximumCredentialBytes = 8 << 10

var (
	ErrInvalid  = errors.New("invalid peer signaling admission")
	ErrConflict = errors.New("peer signaling attachment conflicts with active session")
	ErrCapacity = errors.New("peer signaling capacity exceeded")
	ErrClosed   = errors.New("peer signaling session closed")
)

type Role string

const (
	RoleControlling Role = "controlling"
	RoleControlled  Role = "controlled"
)

type Admission struct {
	CredentialID      string
	EnvironmentID     string
	NodeID            string
	IntentID          string
	EndpointID        string
	PeerEndpointID    string
	AttemptGeneration uint64
	NetworkGeneration uint64
	Role              Role
	ExpiresAt         time.Time
	Revoked           <-chan struct{}
	Release           func()
}

type Authenticator interface {
	Authenticate(context.Context, string) (Admission, error)
}

type Binding struct {
	IntentID          string
	AttemptGeneration uint64
	NetworkGeneration uint64
	Role              Role
}

type Validator interface {
	Accept([]byte) (bool, error)
}

type ValidatorFactory interface {
	NewValidator(Binding) (Validator, error)
}

type Config struct {
	Authenticator   Authenticator
	Validators      ValidatorFactory
	MaximumSessions int
	MaximumConsumed int
	QueueDepth      int
	MaximumMessage  int
	Now             func() time.Time
}

type sessionKey struct {
	environment string
	node        string
	intent      string
	attempt     uint64
	network     uint64
}

type endpoint struct {
	admission Admission
	validator Validator
}

type session struct {
	key       sessionKey
	endpoints map[Role]*endpoint
	completed map[Role]bool
	inbox     map[Role]chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

type Service struct {
	config   Config
	mu       sync.Mutex
	sessions map[sessionKey]*session
	consumed map[string]time.Time
	closed   bool
}

type Attachment struct {
	service *Service
	session *session
	role    Role
	done    chan struct{}
	release func()
	once    sync.Once
}

type Stats struct {
	Sessions    int
	Attachments int
	Capacity    int
	Running     bool
}

func New(config Config) (*Service, error) {
	if config.MaximumSessions == 0 {
		config.MaximumSessions = 4096
	}
	if config.QueueDepth == 0 {
		config.QueueDepth = 128
	}
	if config.MaximumConsumed == 0 {
		config.MaximumConsumed = config.MaximumSessions * 4
	}
	if config.MaximumMessage == 0 {
		config.MaximumMessage = 16 << 10
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Authenticator == nil || config.Validators == nil || config.MaximumSessions < 1 || config.MaximumConsumed < config.MaximumSessions*2 || config.QueueDepth < 1 || config.MaximumMessage < 1 || config.MaximumMessage > 1<<20 {
		return nil, ErrInvalid
	}
	return &Service{config: config, sessions: make(map[sessionKey]*session), consumed: make(map[string]time.Time)}, nil
}

func (s *Service) Attach(ctx context.Context, credential string) (*Attachment, error) {
	if s == nil || ctx == nil || credential == "" || len(credential) > maximumCredentialBytes {
		return nil, ErrInvalid
	}
	admission, err := s.config.Authenticator.Authenticate(ctx, credential)
	if err != nil {
		return nil, fmt.Errorf("authenticate peer signaling: %w", err)
	}
	release := admission.Release
	if release == nil {
		release = func() {}
	}
	var releaseOnce sync.Once
	releaseOwned := func() { releaseOnce.Do(release) }
	admission.Release = releaseOwned
	owned := false
	defer func() {
		if !owned {
			releaseOwned()
		}
	}()
	now := s.config.Now().UTC()
	if !validAdmission(admission, now) {
		return nil, ErrInvalid
	}
	validator, err := s.config.Validators.NewValidator(Binding{IntentID: admission.IntentID, AttemptGeneration: admission.AttemptGeneration, NetworkGeneration: admission.NetworkGeneration, Role: admission.Role})
	if err != nil || validator == nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	key := sessionKey{environment: admission.EnvironmentID, node: admission.NodeID, intent: admission.IntentID, attempt: admission.AttemptGeneration, network: admission.NetworkGeneration}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.removeExpiredLocked(now)
	if _, used := s.consumed[admission.CredentialID]; used {
		s.mu.Unlock()
		return nil, ErrConflict
	}
	if len(s.consumed) >= s.config.MaximumConsumed {
		s.mu.Unlock()
		return nil, ErrCapacity
	}
	current := s.sessions[key]
	if current == nil {
		if len(s.sessions) >= s.config.MaximumSessions {
			s.mu.Unlock()
			return nil, ErrCapacity
		}
		current = &session{key: key, endpoints: make(map[Role]*endpoint, 2), completed: make(map[Role]bool, 2), inbox: map[Role]chan []byte{RoleControlling: make(chan []byte, s.config.QueueDepth), RoleControlled: make(chan []byte, s.config.QueueDepth)}, done: make(chan struct{})}
		s.sessions[key] = current
	}
	if current.endpoints[admission.Role] != nil || current.completed[admission.Role] || !reciprocal(current, admission) {
		s.mu.Unlock()
		return nil, ErrConflict
	}
	current.endpoints[admission.Role] = &endpoint{admission: admission, validator: validator}
	s.consumed[admission.CredentialID] = admission.ExpiresAt
	attachment := &Attachment{service: s, session: current, role: admission.Role, done: make(chan struct{}), release: admission.Release}
	owned = true
	s.mu.Unlock()
	go attachment.watch(admission)
	return attachment, nil
}

func (a *Attachment) Send(ctx context.Context, raw []byte) error {
	if a == nil || ctx == nil || len(raw) == 0 || len(raw) > a.service.config.MaximumMessage {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.service.mu.Lock()
	defer a.service.mu.Unlock()
	if a.service.closed || a.service.sessions[a.session.key] != a.session {
		return ErrClosed
	}
	endpoint := a.session.endpoints[a.role]
	if endpoint == nil {
		return ErrClosed
	}
	inbox := a.session.inbox[opposite(a.role)]
	if len(inbox) >= cap(inbox) {
		return ErrCapacity
	}
	applied, err := endpoint.validator.Accept(raw)
	if err != nil {
		return fmt.Errorf("validate peer signaling message: %w", err)
	}
	if !applied {
		return nil
	}
	inbox <- append([]byte(nil), raw...)
	return nil
}

func (a *Attachment) Receive(ctx context.Context) ([]byte, error) {
	if a == nil || ctx == nil {
		return nil, ErrInvalid
	}
	if !a.active() {
		return nil, ErrClosed
	}
	select {
	case raw := <-a.session.inbox[a.role]:
		if !a.active() {
			return nil, ErrClosed
		}
		return append([]byte(nil), raw...), nil
	case <-a.done:
		return nil, ErrClosed
	case <-a.session.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (a *Attachment) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		close(a.done)
		a.service.terminate(a.session)
		if a.release != nil {
			a.release()
		}
	})
	return nil
}

// Complete half-closes one successfully drained signaling role. The peer may
// continue draining its bounded inbox, but this consumed role cannot reattach.
func (a *Attachment) Complete() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		close(a.done)
		a.service.complete(a.session, a.role)
		if a.release != nil {
			a.release()
		}
	})
	return nil
}

func (a *Attachment) active() bool {
	select {
	case <-a.done:
		return false
	case <-a.session.done:
		return false
	default:
	}
	a.service.mu.Lock()
	defer a.service.mu.Unlock()
	return !a.service.closed && a.service.sessions[a.session.key] == a.session && a.session.endpoints[a.role] != nil
}

func (a *Attachment) watch(admission Admission) {
	defer admission.Release()
	var delay time.Duration
	if now := a.service.config.Now(); now.Before(admission.ExpiresAt) {
		delay = admission.ExpiresAt.Sub(now)
	} else {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-a.done:
	case <-a.session.done:
	case <-admission.Revoked:
		_ = a.Close()
	case <-timer.C:
		_ = a.Close()
	}
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	current := make([]*session, 0, len(s.sessions))
	for _, active := range s.sessions {
		current = append(current, active)
	}
	s.sessions = make(map[sessionKey]*session)
	s.consumed = make(map[string]time.Time)
	s.mu.Unlock()
	for _, active := range current {
		active.closeOnce.Do(func() { close(active.done) })
	}
	return nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

func (s *Service) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	return s.Close()
}

func (s *Service) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := Stats{Sessions: len(s.sessions), Capacity: s.config.MaximumSessions, Running: !s.closed}
	for _, active := range s.sessions {
		stats.Attachments += len(active.endpoints)
	}
	return stats
}

func (s *Service) terminate(target *session) {
	s.mu.Lock()
	if s.sessions[target.key] == target {
		delete(s.sessions, target.key)
	}
	s.mu.Unlock()
	target.closeOnce.Do(func() { close(target.done) })
}

func (s *Service) complete(target *session, role Role) {
	s.mu.Lock()
	if s.sessions[target.key] != target || target.endpoints[role] == nil {
		s.mu.Unlock()
		return
	}
	delete(target.endpoints, role)
	target.completed[role] = true
	finished := len(target.endpoints) == 0
	if finished {
		delete(s.sessions, target.key)
	}
	s.mu.Unlock()
	if finished {
		target.closeOnce.Do(func() { close(target.done) })
	}
}

func (s *Service) removeExpiredLocked(now time.Time) {
	for credential, expiresAt := range s.consumed {
		if !expiresAt.After(now) {
			delete(s.consumed, credential)
		}
	}
	for key, active := range s.sessions {
		for _, endpoint := range active.endpoints {
			if !endpoint.admission.ExpiresAt.After(now) {
				delete(s.sessions, key)
				active.closeOnce.Do(func() { close(active.done) })
				break
			}
		}
	}
}

func reciprocal(active *session, admission Admission) bool {
	peer := active.endpoints[opposite(admission.Role)]
	return peer == nil || peer.admission.EndpointID == admission.PeerEndpointID && peer.admission.PeerEndpointID == admission.EndpointID
}

func validAdmission(value Admission, now time.Time) bool {
	return bounded(value.CredentialID) && bounded(value.EnvironmentID) && bounded(value.NodeID) && bounded(value.IntentID) && bounded(value.EndpointID) && bounded(value.PeerEndpointID) && value.EndpointID != value.PeerEndpointID && value.AttemptGeneration > 0 && value.NetworkGeneration > 0 && (value.Role == RoleControlling || value.Role == RoleControlled) && value.ExpiresAt.After(now) && value.ExpiresAt.Sub(now) <= 10*time.Minute
}

func bounded(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == '\n' || character == 0 {
			return false
		}
	}
	return true
}

func opposite(role Role) Role {
	if role == RoleControlling {
		return RoleControlled
	}
	return RoleControlling
}
