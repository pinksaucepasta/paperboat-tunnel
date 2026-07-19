package usage

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrQueueFull = errors.New("usage report queue is full")

func NewCounterEpoch() (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

type Key struct {
	Node        string `json:"edge_node_id"`
	Epoch       string `json:"counter_epoch"`
	Environment string `json:"environment_id"`
	Route       string `json:"route_id"`
	Direction   string `json:"direction"`
	Revision    uint64 `json:"route_revision"`
}

type Counters struct {
	mu     sync.Mutex
	values map[Key]uint64
}

type CounterRecord struct {
	Key   Key    `json:"key"`
	Bytes uint64 `json:"bytes"`
}

func NewCounters() *Counters { return &Counters{values: make(map[Key]uint64)} }

// Add records bytes observed at the edge. Counters never decrease.
func (c *Counters) Add(k Key, bytes uint64) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[k] += bytes
	return c.values[k]
}

func (c *Counters) Observe(k Key, absolute uint64) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if absolute > c.values[k] {
		c.values[k] = absolute
	}
	return c.values[k]
}

func (c *Counters) Get(k Key) uint64 { c.mu.Lock(); defer c.mu.Unlock(); return c.values[k] }

func (c *Counters) Snapshot() []CounterRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CounterRecord, 0, len(c.values))
	for key, bytes := range c.values {
		result = append(result, CounterRecord{Key: key, Bytes: bytes})
	}
	return result
}

func RestoreCounters(records []CounterRecord) *Counters {
	counters := NewCounters()
	for _, record := range records {
		if record.Key.Node == "" || record.Key.Epoch == "" || record.Key.Environment == "" || record.Key.Route == "" || (record.Key.Direction != "ingress" && record.Key.Direction != "egress") {
			continue
		}
		if record.Bytes > counters.values[record.Key] {
			counters.values[record.Key] = record.Bytes
		}
	}
	return counters
}

// Reconcile applies an absolute observation and returns the newly observed delta.
func (c *Counters) Reconcile(k Key, absolute uint64) (delta uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if absolute <= c.values[k] {
		return 0
	}
	delta = absolute - c.values[k]
	c.values[k] = absolute
	return delta
}

type Report struct {
	OperationID string
	Key         Key
	Bytes       uint64
	Interval    [2]time.Time
	Payload     []byte
}

type Queue struct {
	mu         sync.Mutex
	maxReports int
	maxBytes   int
	bytes      int
	pending    map[string]Report
	order      []string
}

type QueueState struct {
	Reports []Report `json:"reports"`
}

type QueueStats struct {
	Reports    int
	Bytes      int
	MaxReports int
	MaxBytes   int
	OldestAt   time.Time
}

func NewQueue(maxReports, maxBytes int) (*Queue, error) {
	if maxReports < 1 || maxBytes < 1 {
		return nil, ErrQueueFull
	}
	return &Queue{maxReports: maxReports, maxBytes: maxBytes, pending: make(map[string]Report)}, nil
}

func (q *Queue) Enqueue(report Report) error {
	if report.OperationID == "" || len(report.Payload) == 0 {
		return ErrQueueFull
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if existing, ok := q.pending[report.OperationID]; ok {
		if existing.Key == report.Key && existing.Bytes == report.Bytes && string(existing.Payload) == string(report.Payload) {
			return nil
		}
		return ErrQueueFull
	}
	if len(q.pending) >= q.maxReports || q.bytes+len(report.Payload) > q.maxBytes {
		return ErrQueueFull
	}
	report.Payload = append([]byte(nil), report.Payload...)
	q.pending[report.OperationID] = report
	q.order = append(q.order, report.OperationID)
	q.bytes += len(report.Payload)
	return nil
}

func (q *Queue) Next() (Report, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range q.order {
		if report, ok := q.pending[id]; ok {
			report.Payload = append([]byte(nil), report.Payload...)
			return report, true
		}
	}
	return Report{}, false
}

func (q *Queue) Ack(operationID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	report, ok := q.pending[operationID]
	if !ok {
		return false
	}
	delete(q.pending, operationID)
	q.bytes -= len(report.Payload)
	return true
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

func (q *Queue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := QueueStats{Reports: len(q.pending), Bytes: q.bytes, MaxReports: q.maxReports, MaxBytes: q.maxBytes}
	for _, id := range q.order {
		report, ok := q.pending[id]
		if !ok {
			continue
		}
		at := report.Interval[0]
		if at.IsZero() {
			at = report.Interval[1]
		}
		if stats.OldestAt.IsZero() || !at.IsZero() && at.Before(stats.OldestAt) {
			stats.OldestAt = at
		}
	}
	return stats
}

func (q *Queue) HasKey(key Key) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, report := range q.pending {
		if report.Key == key {
			return true
		}
	}
	return false
}

func (q *Queue) Snapshot() QueueState {
	q.mu.Lock()
	defer q.mu.Unlock()
	state := QueueState{Reports: make([]Report, 0, len(q.pending))}
	for _, id := range q.order {
		if report, ok := q.pending[id]; ok {
			report.Payload = append([]byte(nil), report.Payload...)
			state.Reports = append(state.Reports, report)
		}
	}
	return state
}

func RestoreQueue(state QueueState, maxReports, maxBytes int) (*Queue, error) {
	queue, err := NewQueue(maxReports, maxBytes)
	if err != nil {
		return nil, err
	}
	for _, report := range state.Reports {
		if err := queue.Enqueue(report); err != nil {
			return nil, err
		}
	}
	return queue, nil
}
