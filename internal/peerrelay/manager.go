// Package peerrelay owns bounded pairing and opaque byte forwarding for
// already-authorized relay QUIC and WSS endpoint legs.
package peerrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrInvalid  = errors.New("peer relay attachment is invalid")
	ErrCapacity = errors.New("peer relay capacity is exhausted")
	ErrConflict = errors.New("peer relay endpoint role is already attached")
	ErrDraining = errors.New("peer relay is draining")
	ErrRevoked  = errors.New("peer relay binding is revoked")
	ErrExpired  = errors.New("peer relay binding is expired")
	ErrLimit    = errors.New("peer relay byte limit exceeded")
	ErrClosed   = errors.New("peer relay is closed")
)

type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleHost
)

type Carrier uint8

const (
	CarrierQUIC Carrier = iota + 1
	CarrierWSS
)

type Path uint8

const (
	PathRelayQUIC Path = iota + 1
	PathRelayWSS
)

// Binding is supplied only after an outer admission layer authenticates the
// short-lived endpoint credential. It deliberately contains no wire token.
type Binding struct {
	RouteAllocation [16]byte
	StreamHandle    [16]byte
	EnvironmentID   string
	RouteID         string
	RouteRevision   uint64
	IntentID        string
	Attempt         uint64
	Network         uint64
	ExpiresAt       time.Time
	MaximumBytes    uint64
}

type Admission struct {
	Binding Binding
	Role    Role
	Carrier Carrier
}

type Config struct {
	MaximumPending  int
	MaximumActive   int
	MaximumConsumed int
	BufferBytes     int
	ReportTimeout   time.Duration
}

func DevelopmentConfig() Config {
	return Config{MaximumPending: 1024, MaximumActive: 4096, MaximumConsumed: 65536, BufferBytes: 32 << 10, ReportTimeout: 5 * time.Second}
}

func (c Config) valid() bool {
	return c.MaximumPending > 0 && c.MaximumPending <= 16384 && c.MaximumActive > 0 && c.MaximumActive <= 65536 && c.MaximumConsumed > 0 && c.MaximumConsumed <= 1<<20 && c.BufferBytes >= 4<<10 && c.BufferBytes <= 256<<10 && c.ReportTimeout > 0 && c.ReportTimeout <= time.Minute
}

type Usage struct {
	EnvironmentID    string
	RouteID          string
	RouteRevision    uint64
	IntentID         string
	Attempt          uint64
	Network          uint64
	Path             Path
	BytesToInitiator uint64
	BytesToHost      uint64
	StartedAt        time.Time
	FinishedAt       time.Time
}

type Recorder interface {
	RecordRelayUsage(context.Context, Usage) error
}

type Manager struct {
	config   Config
	recorder Recorder
	now      func() time.Time

	mu       sync.Mutex
	relays   map[relayKey]*relay
	consumed map[streamKey]time.Time
	draining bool
	closed   bool
}

type relay struct {
	key         relayKey
	binding     Binding
	initiator   *leg
	host        *leg
	done        chan struct{}
	started     bool
	baseUsage   Usage
	usage       Usage
	err         error
	finalOnce   sync.Once
	stopOnce    sync.Once
	stopMu      sync.Mutex
	stopErr     error
	expiry      *time.Timer
	expired     bool
	toInitiator atomic.Uint64
	toHost      atomic.Uint64
}

type leg struct {
	stream  io.ReadWriteCloser
	carrier Carrier
}

type Stats struct {
	Pending int
	Active  int
}

func NewManager(config Config, recorder Recorder, now func() time.Time) (*Manager, error) {
	if config.MaximumConsumed == 0 {
		config.MaximumConsumed = DevelopmentConfig().MaximumConsumed
	}
	if !config.valid() || recorder == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{config: config, recorder: recorder, now: now, relays: make(map[relayKey]*relay), consumed: make(map[streamKey]time.Time)}, nil
}

// Attach transfers stream ownership to the manager and blocks until the paired
// relay finishes. Every exit path closes the supplied stream.
func (m *Manager) Attach(ctx context.Context, admission Admission, stream io.ReadWriteCloser) (Usage, error) {
	if m == nil || m.now == nil || ctx == nil || nilStream(stream) || !validAdmission(admission, m.now()) {
		if !nilStream(stream) {
			_ = stream.Close()
		}
		return Usage{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		_ = stream.Close()
		return Usage{}, err
	}
	admission.Binding = canonicalBinding(admission.Binding)
	key := relayKey{Binding: admission.Binding, Carrier: admission.Carrier}
	m.mu.Lock()
	m.pruneConsumedLocked(m.now())
	if m.closed {
		m.mu.Unlock()
		_ = stream.Close()
		return Usage{}, ErrClosed
	}
	if m.draining {
		m.mu.Unlock()
		_ = stream.Close()
		return Usage{}, ErrDraining
	}
	if _, replayed := m.consumed[keyFor(key)]; replayed {
		m.mu.Unlock()
		_ = stream.Close()
		return Usage{}, ErrConflict
	}
	current := m.relays[key]
	created := false
	if current == nil {
		if len(m.consumed)+len(m.relays) >= m.config.MaximumConsumed {
			m.mu.Unlock()
			_ = stream.Close()
			return Usage{}, ErrCapacity
		}
		pending, _ := m.countLocked()
		if pending >= m.config.MaximumPending {
			m.mu.Unlock()
			_ = stream.Close()
			return Usage{}, ErrCapacity
		}
		current = &relay{key: key, binding: admission.Binding, done: make(chan struct{})}
		m.relays[key] = current
		created = true
	}
	if current.expired {
		m.mu.Unlock()
		_ = stream.Close()
		return Usage{}, ErrExpired
	}
	selected := &current.initiator
	if admission.Role == RoleHost {
		selected = &current.host
	}
	if *selected != nil {
		m.mu.Unlock()
		_ = stream.Close()
		return Usage{}, ErrConflict
	}
	if !created && !current.started && (current.initiator != nil || current.host != nil) {
		_, active := m.countLocked()
		if active >= m.config.MaximumActive {
			m.mu.Unlock()
			_ = stream.Close()
			return Usage{}, ErrCapacity
		}
	}
	*selected = &leg{stream: stream, carrier: admission.Carrier}
	if created {
		current.expiry = time.AfterFunc(admission.Binding.ExpiresAt.Sub(m.now()), func() { m.expirePending(current) })
	}
	if current.initiator != nil && current.host != nil && !current.started {
		current.started = true
		if current.expiry != nil {
			current.expiry.Stop()
		}
		current.baseUsage = Usage{EnvironmentID: current.binding.EnvironmentID, RouteID: current.binding.RouteID, RouteRevision: current.binding.RouteRevision, IntentID: current.binding.IntentID, Attempt: current.binding.Attempt, Network: current.binding.Network, Path: relayPath(current.initiator.carrier, current.host.carrier), StartedAt: m.now().UTC()}
		go m.run(current, current.baseUsage)
	}
	m.mu.Unlock()

	stop := context.AfterFunc(ctx, func() { m.fail(key, current, ctx.Err()) })
	<-current.done
	stop()
	return current.usage, current.err
}

func (m *Manager) BeginDrain() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.draining = true
	m.mu.Unlock()
}

func (m *Manager) Revoke(binding Binding) {
	if m == nil {
		return
	}
	binding = canonicalBinding(binding)
	m.mu.Lock()
	var current []*relay
	for key, item := range m.relays {
		if key.Binding == binding {
			current = append(current, item)
		}
	}
	m.mu.Unlock()
	for _, item := range current {
		m.terminate(item, ErrRevoked)
	}
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.closed, m.draining = true, true
	current := make([]*relay, 0, len(m.relays))
	for _, item := range m.relays {
		current = append(current, item)
	}
	m.mu.Unlock()
	for _, item := range current {
		m.terminate(item, ErrClosed)
	}
	for _, item := range current {
		<-item.done
	}
	return nil
}

func (m *Manager) Stats() Stats {
	if m == nil {
		return Stats{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, active := m.countLocked()
	return Stats{Pending: pending, Active: active}
}

func (m *Manager) countLocked() (pending, active int) {
	for _, current := range m.relays {
		if current.started {
			active++
		} else {
			pending++
		}
	}
	return pending, active
}

func (m *Manager) run(current *relay, usage Usage) {
	type result struct {
		toInitiator bool
		bytes       uint64
		err         error
	}
	results := make(chan result, 2)
	copyLeg := func(destination, source io.ReadWriteCloser, toInitiator bool, counter *atomic.Uint64) {
		written, err := copyLimited(destination, source, current.binding.MaximumBytes, m.config.BufferBytes, counter)
		results <- result{toInitiator: toInitiator, bytes: written, err: err}
	}
	go copyLeg(current.initiator.stream, current.host.stream, true, &current.toInitiator)
	go copyLeg(current.host.stream, current.initiator.stream, false, &current.toHost)
	first := <-results
	second := <-results
	_ = current.initiator.stream.Close()
	_ = current.host.stream.Close()
	if first.toInitiator {
		usage.BytesToInitiator = first.bytes
	} else {
		usage.BytesToHost = first.bytes
	}
	if second.toInitiator {
		usage.BytesToInitiator = second.bytes
	} else {
		usage.BytesToHost = second.bytes
	}
	err := first.err
	if err == nil {
		err = normalizeCopyError(second.err)
	} else {
		err = normalizeCopyError(err)
	}
	if stopped := current.stopped(); stopped != nil {
		err = stopped
	}
	m.finalize(current, err, &usage)
}

func (m *Manager) fail(key relayKey, current *relay, cause error) {
	m.mu.Lock()
	owned := m.relays[key] == current
	m.mu.Unlock()
	if owned {
		m.terminate(current, cause)
	}
}

// Credential expiry bounds how long an unmatched endpoint may occupy pending
// capacity. Once both authenticated legs are paired, revocation, byte limits,
// endpoint lifetime, draining, or shutdown own the established relay lifetime.
func (m *Manager) expirePending(current *relay) {
	m.mu.Lock()
	if m.relays[current.key] != current || current.started {
		m.mu.Unlock()
		return
	}
	current.expired = true
	m.mu.Unlock()
	m.terminate(current, ErrExpired)
}

func (m *Manager) terminate(current *relay, cause error) {
	current.stopOnce.Do(func() {
		m.mu.Lock()
		initiator, host, started := current.initiator, current.host, current.started
		m.mu.Unlock()
		current.stopMu.Lock()
		current.stopErr = cause
		current.stopMu.Unlock()
		if initiator != nil {
			_ = initiator.stream.Close()
		}
		if host != nil {
			_ = host.stream.Close()
		}
		if !started {
			m.finalize(current, cause, nil)
		}
	})
}

func (r *relay) stopped() error {
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	return r.stopErr
}

func (m *Manager) finalize(current *relay, cause error, completed *Usage) {
	current.finalOnce.Do(func() {
		m.mu.Lock()
		if current.expiry != nil {
			current.expiry.Stop()
		}
		started := current.started
		if m.relays[current.key] == current {
			delete(m.relays, current.key)
		}
		m.consumed[keyFor(current.key)] = current.binding.ExpiresAt
		m.mu.Unlock()
		usage := current.baseUsage
		if completed != nil {
			usage = *completed
		}
		usage.BytesToInitiator = current.toInitiator.Load()
		usage.BytesToHost = current.toHost.Load()
		usage.FinishedAt = m.now().UTC()
		current.usage = usage
		current.err = cause
		if started {
			reportCtx, cancel := context.WithTimeout(context.Background(), m.config.ReportTimeout)
			current.err = errors.Join(current.err, m.recorder.RecordRelayUsage(reportCtx, usage))
			cancel()
		}
		close(current.done)
	})
}

type relayKey struct {
	Binding Binding
	Carrier Carrier
}

type streamKey [33]byte

func keyFor(value relayKey) streamKey {
	var key streamKey
	copy(key[:16], value.Binding.RouteAllocation[:])
	copy(key[16:32], value.Binding.StreamHandle[:])
	key[32] = byte(value.Carrier)
	return key
}

func (m *Manager) pruneConsumedLocked(now time.Time) {
	for key, expiresAt := range m.consumed {
		if !expiresAt.After(now) {
			delete(m.consumed, key)
		}
	}
}

type limitedWriter struct {
	destination io.Writer
	remaining   uint64
	counter     *atomic.Uint64
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	if uint64(len(value)) > w.remaining {
		value = value[:w.remaining]
		n, err := w.destination.Write(value)
		w.remaining -= uint64(n)
		w.counter.Add(uint64(n))
		if err != nil {
			return n, err
		}
		return n, ErrLimit
	}
	n, err := w.destination.Write(value)
	w.remaining -= uint64(n)
	w.counter.Add(uint64(n))
	return n, err
}

func copyLimited(destination io.Writer, source io.Reader, maximum uint64, bufferBytes int, counter *atomic.Uint64) (uint64, error) {
	writer := &limitedWriter{destination: destination, remaining: maximum, counter: counter}
	written, err := io.CopyBuffer(writer, source, make([]byte, bufferBytes))
	return uint64(written), err
}

func normalizeCopyError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func relayPath(first, second Carrier) Path {
	if first == CarrierQUIC && second == CarrierQUIC {
		return PathRelayQUIC
	}
	return PathRelayWSS
}

func validAdmission(admission Admission, now time.Time) bool {
	binding := canonicalBinding(admission.Binding)
	return (admission.Role == RoleInitiator || admission.Role == RoleHost) &&
		(admission.Carrier == CarrierQUIC || admission.Carrier == CarrierWSS) &&
		binding.RouteAllocation != [16]byte{} && binding.StreamHandle != [16]byte{} &&
		binding.EnvironmentID != "" && len(binding.EnvironmentID) <= 128 && binding.RouteID != "" && len(binding.RouteID) <= 128 && binding.RouteRevision > 0 &&
		binding.IntentID != "" && len(binding.IntentID) <= 128 && binding.Attempt > 0 && binding.Network > 0 &&
		binding.ExpiresAt.After(now) && binding.MaximumBytes > 0 && binding.MaximumBytes <= 1<<40
}

func canonicalBinding(binding Binding) Binding {
	binding.ExpiresAt = binding.ExpiresAt.UTC().Round(0)
	return binding
}

func nilStream(stream io.ReadWriteCloser) bool {
	if stream == nil {
		return true
	}
	value := reflect.ValueOf(stream)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
