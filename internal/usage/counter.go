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

// Revision is report metadata, not part of the server's absolute counter identity.
func (k Key) counterIdentity() Key { k.Revision = 0; return k }

type Counters struct {
	mu               sync.Mutex
	values           map[Key]CounterRecord
	restoredBaseline map[Key]uint64
}

type CounterRecord struct {
	Key   Key    `json:"key"`
	Bytes uint64 `json:"bytes"`
}

func NewCounters() *Counters { return &Counters{} }

func (c *Counters) update(k Key, bytes uint64, add bool) (uint64, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = make(map[Key]CounterRecord)
	}
	identity := k.counterIdentity()
	record := c.values[identity]
	previous := record.Bytes
	if record.Key.Revision <= k.Revision {
		record.Key = k
	}
	if add {
		if bytes > ^uint64(0)-record.Bytes {
			record.Bytes = ^uint64(0)
		} else {
			record.Bytes += bytes
		}
	} else if bytes > record.Bytes {
		record.Bytes = bytes
	}
	c.values[identity] = record
	return record.Bytes, record.Bytes - previous
}

// Add records bytes across all revisions, including late bytes from old streams.
func (c *Counters) Add(k Key, bytes uint64) uint64 {
	total, _ := c.update(k, bytes, true)
	return total
}
func (c *Counters) Observe(k Key, absolute uint64) uint64 {
	total, _ := c.update(k, absolute, false)
	return total
}
func (c *Counters) Reconcile(k Key, absolute uint64) uint64 {
	_, delta := c.update(k, absolute, false)
	return delta
}
func (c *Counters) Get(k Key) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[k.counterIdentity()].Bytes
}
func (c *Counters) Snapshot() []CounterRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CounterRecord, 0, len(c.values))
	for _, record := range c.values {
		result = append(result, record)
	}
	return result
}

// Restore accepts durable revision partitions, deduplicates identical records by
// their maximum absolute value, and sums distinct partitions once. The next
// snapshot writes exactly one cumulative record per server counter identity.
func RestoreCounters(records []CounterRecord) *Counters {
	counters := NewCounters()
	partitions := make(map[Key]uint64)
	for _, record := range records {
		k := record.Key
		if k.Node == "" || k.Epoch == "" || k.Environment == "" || k.Route == "" || (k.Direction != "ingress" && k.Direction != "egress") {
			continue
		}
		if record.Bytes > partitions[k] {
			partitions[k] = record.Bytes
		}
	}
	counters.restoredBaseline = make(map[Key]uint64)
	for key, bytes := range partitions {
		counters.Add(key, bytes)
		identity := key.counterIdentity()
		// The server could only acknowledge the maximum partition. Any excess
		// must be reported even when the old durable queue has already emptied.
		if bytes > counters.restoredBaseline[identity] {
			counters.restoredBaseline[identity] = bytes
		}
	}
	return counters
}

func (c *Counters) baseline(record CounterRecord) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if value, ok := c.restoredBaseline[record.Key.counterIdentity()]; ok {
		return value
	}
	return record.Bytes
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
	if report.OperationID == "" || len(report.Payload) == 0 || len(report.Payload) > q.maxBytes {
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
	if len(q.pending) >= q.maxReports || q.bytes > q.maxBytes-len(report.Payload) {
		return ErrQueueFull
	}
	report.Payload = append([]byte(nil), report.Payload...)
	q.pending[report.OperationID] = report
	q.order = append(q.order, report.OperationID)
	q.bytes += len(report.Payload)
	return nil
}

// EnqueueLatest coalesces one absolute snapshot per usage key. A newer
// absolute replaces the pending report without growing the bounded queue.
func (q *Queue) EnqueueLatest(report Report) error {
	if report.OperationID == "" || len(report.Payload) == 0 || len(report.Payload) > q.maxBytes {
		return ErrQueueFull
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for id, current := range q.pending {
		if current.Key.counterIdentity() != report.Key.counterIdentity() {
			continue
		}
		if report.Bytes <= current.Bytes {
			return nil
		}
		baseBytes := q.bytes - len(current.Payload)
		if baseBytes < 0 || baseBytes > q.maxBytes-len(report.Payload) {
			return ErrQueueFull
		}
		newBytes := baseBytes + len(report.Payload)
		delete(q.pending, id)
		report.Payload = append([]byte(nil), report.Payload...)
		q.pending[report.OperationID] = report
		q.bytes = newBytes
		for index, ordered := range q.order {
			if ordered == id {
				q.order[index] = report.OperationID
				break
			}
		}
		return nil
	}
	if len(q.pending) >= q.maxReports || q.bytes > q.maxBytes-len(report.Payload) {
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
		if report.Key.counterIdentity() == key.counterIdentity() {
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
