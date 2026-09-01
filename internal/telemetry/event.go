package telemetry

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

const (
	EventSchemaV1       = "paperboat.edge_event.v1"
	maximumEventLogSize = 4096
)

type EventSeverity string

const (
	SeverityDebug EventSeverity = "debug"
	SeverityInfo  EventSeverity = "info"
	SeverityWarn  EventSeverity = "warn"
	SeverityError EventSeverity = "error"
)

type EventOutcome string

const (
	OutcomeSuccess     EventOutcome = "success"
	OutcomeFailed      EventOutcome = "failed"
	OutcomeRejected    EventOutcome = "rejected"
	OutcomeCanceled    EventOutcome = "canceled"
	OutcomeStateChange EventOutcome = "state_change"
)

// SafeIDs is deliberately limited to opaque identifiers. It is not a place
// for hostnames, URLs, email addresses, credentials or user-provided labels.
type SafeIDs struct {
	AccountID     string `json:"account_id,omitempty"`
	ActorID       string `json:"actor_id,omitempty"`
	TunnelID      string `json:"tunnel_id,omitempty"`
	RouteID       string `json:"route_id,omitempty"`
	ConnectorID   string `json:"connector_id,omitempty"`
	DomainID      string `json:"domain_id,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	AssignmentID  string `json:"assignment_id,omitempty"`
	HostID        string `json:"host_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	OperationID   string `json:"operation_id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	EdgeNodeID    string `json:"edge_node_id,omitempty"`
}

type Generations struct {
	Config       uint64 `json:"config,omitempty"`
	Route        uint64 `json:"route,omitempty"`
	Assignment   uint64 `json:"assignment,omitempty"`
	Connector    uint64 `json:"connector,omitempty"`
	Process      uint64 `json:"process,omitempty"`
	Session      uint64 `json:"session,omitempty"`
	Installation uint64 `json:"installation,omitempty"`
	Credential   uint64 `json:"credential,omitempty"`
	Certificate  uint64 `json:"certificate,omitempty"`
}

type EventInput struct {
	At            time.Time
	Severity      EventSeverity
	Component     Dimension
	Name          string
	Code          string
	Outcome       EventOutcome
	Message       string
	CorrelationID string
	IDs           SafeIDs
	Generations   Generations
	Retry         RetryDecision
	NextRetryAt   time.Time
}

type Event struct {
	Schema        string        `json:"schema"`
	At            time.Time     `json:"at"`
	Severity      EventSeverity `json:"severity"`
	Component     Dimension     `json:"component"`
	Name          string        `json:"name"`
	Code          string        `json:"code"`
	Outcome       EventOutcome  `json:"outcome"`
	Message       string        `json:"message"`
	CorrelationID string        `json:"correlation_id"`
	IDs           SafeIDs       `json:"ids"`
	Generations   Generations   `json:"generations"`
	Retry         RetryDecision `json:"retry"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`
}

var safeIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,127}$`)

func NewEvent(input EventInput) (Event, error) {
	if normalizeTime(input.At).IsZero() {
		return Event{}, newError(ErrorInvalidTime, "construct edge event")
	}
	if !validEventSeverity(input.Severity) || !validDimension(input.Component) ||
		!stableCodePattern.MatchString(input.Name) || !stableCodePattern.MatchString(input.Code) ||
		!validEventOutcome(input.Outcome) {
		return Event{}, newError(ErrorInvalidEvent, "construct edge event")
	}
	if !validCorrelationID(input.CorrelationID) {
		return Event{}, newError(ErrorInvalidID, "construct edge event")
	}
	if !validSafeIDs(input.IDs) {
		return Event{}, newError(ErrorInvalidID, "construct edge event")
	}
	if !validRetry(input.Retry, input.NextRetryAt) {
		return Event{}, newError(ErrorInvalidRetry, "construct edge event")
	}
	message, err := safeBoundedString(input.Message, maximumMessageBytes, true)
	if err != nil {
		return Event{}, err
	}
	event := Event{
		Schema:        EventSchemaV1,
		At:            normalizeTime(input.At),
		Severity:      input.Severity,
		Component:     input.Component,
		Name:          input.Name,
		Code:          input.Code,
		Outcome:       input.Outcome,
		Message:       message,
		CorrelationID: input.CorrelationID,
		IDs:           input.IDs,
		Generations:   input.Generations,
		Retry:         input.Retry,
	}
	if !input.NextRetryAt.IsZero() {
		nextRetry := normalizeTime(input.NextRetryAt)
		event.NextRetryAt = &nextRetry
	}
	return event, nil
}

func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

func validEventSeverity(value EventSeverity) bool {
	return value == SeverityDebug || value == SeverityInfo || value == SeverityWarn || value == SeverityError
}

func validEventOutcome(value EventOutcome) bool {
	return value == OutcomeSuccess || value == OutcomeFailed || value == OutcomeRejected || value == OutcomeCanceled || value == OutcomeStateChange
}

func validCorrelationID(value string) bool {
	return hasSafePrefix(value, "corr_", "cor_", "correlation_", "request_", "pb-")
}

func validSafeIDs(ids SafeIDs) bool {
	return optionalSafeID(ids.AccountID, "account_") &&
		optionalSafeID(ids.ActorID, "actor_") &&
		optionalSafeID(ids.TunnelID, "tunnel_") &&
		optionalSafeID(ids.RouteID, "route_") &&
		optionalSafeID(ids.ConnectorID, "connector_") &&
		optionalSafeID(ids.DomainID, "domain_") &&
		optionalSafeID(ids.CertificateID, "certificate_") &&
		optionalSafeID(ids.AssignmentID, "assignment_") &&
		optionalSafeID(ids.HostID, "host_") &&
		optionalSafeID(ids.DeviceID, "device_") &&
		optionalSafeID(ids.SessionID, "session_", "carrier_") &&
		optionalSafeID(ids.OperationID, "operation_", "op_") &&
		optionalSafeID(ids.RequestID, "request_", "req_") &&
		optionalSafeID(ids.EdgeNodeID, "edge_")
}

func optionalSafeID(value string, prefixes ...string) bool {
	return value == "" || hasSafePrefix(value, prefixes...)
}

func hasSafePrefix(value string, prefixes ...string) bool {
	if !safeIDPattern.MatchString(value) {
		return false
	}
	for _, prefix := range prefixes {
		if len(value) > len(prefix) && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// EventLog is a bounded, nonblocking producer path backed by an owned worker.
// Record never waits for a sink or a slow reader. A full queue increments the
// typed drop counter and discards the event safely.
type EventLog struct {
	mu       sync.RWMutex
	gate     sync.RWMutex
	capacity int
	events   []Event
	queue    chan eventItem
	commands chan flushCommand
	stop     chan struct{}
	done     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Uint64
	accepted atomic.Uint64
	closeMu  sync.Mutex
}

type eventItem struct {
	event   Event
	barrier chan struct{}
}

type flushCommand struct{ done chan struct{} }

func NewEventLog(capacity int) (*EventLog, error) {
	queueCapacity := capacity * 2
	if queueCapacity < capacity || queueCapacity > maximumEventLogSize {
		queueCapacity = maximumEventLogSize
	}
	return NewEventLogWithQueue(capacity, queueCapacity)
}

// NewEventLogWithQueue is useful when callers want a small producer queue but
// a larger retained ring. Both bounds are explicit and finite.
func NewEventLogWithQueue(capacity, queueCapacity int) (*EventLog, error) {
	if capacity <= 0 || capacity > maximumEventLogSize || queueCapacity <= 0 || queueCapacity > maximumEventLogSize {
		return nil, newError(ErrorInvalidCapacity, "construct edge event log")
	}
	log := &EventLog{
		capacity: capacity,
		events:   make([]Event, 0, capacity),
		queue:    make(chan eventItem, queueCapacity),
		commands: make(chan flushCommand),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go log.run()
	return log, nil
}

func (l *EventLog) run() {
	defer close(l.done)
	for {
		select {
		case item := <-l.queue:
			if item.barrier != nil {
				close(item.barrier)
				continue
			}
			l.append(item.event)
		case command := <-l.commands:
			l.drain()
			close(command.done)
		case <-l.stop:
			l.drain()
			return
		}
	}
}

func (l *EventLog) drain() {
	for {
		select {
		case item := <-l.queue:
			if item.barrier != nil {
				close(item.barrier)
			} else {
				l.append(item.event)
			}
		default:
			return
		}
	}
}

func (l *EventLog) append(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == l.capacity {
		copy(l.events, l.events[1:])
		l.events[len(l.events)-1] = cloneEvent(event)
		return
	}
	l.events = append(l.events, cloneEvent(event))
}

func (l *EventLog) Record(input EventInput) (Event, error) {
	event, err := NewEvent(input)
	if err != nil {
		return Event{}, err
	}
	if l == nil {
		return event, nil
	}
	if !l.gate.TryRLock() {
		l.dropped.Add(1)
		return event, nil
	}
	defer l.gate.RUnlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, nil
	}
	select {
	case l.queue <- eventItem{event: event}:
		if accepted := l.accepted.Add(1); accepted > uint64(l.capacity) {
			// Retention is accounted for at acceptance time so callers can
			// observe drops without waiting for the worker to run.
			l.dropped.Add(1)
		}
	default:
		l.dropped.Add(1)
	}
	return event, nil
}

// TryRecord never waits for another producer. It retains the historical
// boolean result while using the same bounded queue as Record.
func (l *EventLog) TryRecord(input EventInput) (Event, bool, error) {
	event, err := NewEvent(input)
	if err != nil {
		return Event{}, false, err
	}
	if l == nil {
		return event, false, nil
	}
	// Keep this quick lock probe for callers that use TryRecord as an explicit
	// contention boundary. No producer can wait for the ring mutex.
	if !l.mu.TryLock() {
		l.dropped.Add(1)
		return event, false, nil
	}
	l.mu.Unlock()
	if !l.gate.TryRLock() {
		l.dropped.Add(1)
		return event, false, nil
	}
	defer l.gate.RUnlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, false, nil
	}
	select {
	case l.queue <- eventItem{event: event}:
		if accepted := l.accepted.Add(1); accepted > uint64(l.capacity) {
			l.dropped.Add(1)
		}
		return event, true, nil
	default:
		l.dropped.Add(1)
		return event, false, nil
	}
}

// Flush waits until events accepted before the call are retained. Unlike
// Record, it may wait for the owned worker and honors cancellation.
func (l *EventLog) Flush(ctx context.Context) error {
	if l == nil || l.closed.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	command := flushCommand{done: make(chan struct{})}
	select {
	case l.commands <- command:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return nil
	}
	select {
	case <-command.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *EventLog) Snapshot() []Event {
	if l == nil {
		return nil
	}
	_ = l.Flush(context.Background())
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Event, len(l.events))
	for index, event := range l.events {
		result[index] = cloneEvent(event)
	}
	return result
}

func (l *EventLog) DroppedEvents() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

// DropCount is a concise alias for integrations exposing generic counters.
func (l *EventLog) DropCount() uint64 { return l.DroppedEvents() }

// Dropped preserves the original edge package name while integrations migrate
// to the typed DroppedEvents counter.
func (l *EventLog) Dropped() uint64 { return l.DroppedEvents() }

func (l *EventLog) Close() error {
	if l == nil {
		return nil
	}
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed.Load() {
		<-l.done
		return nil
	}
	l.gate.Lock()
	l.closed.Store(true)
	close(l.stop)
	l.gate.Unlock()
	<-l.done
	return nil
}

func cloneEvent(event Event) Event {
	event.NextRetryAt = cloneTime(event.NextRetryAt)
	return event
}
