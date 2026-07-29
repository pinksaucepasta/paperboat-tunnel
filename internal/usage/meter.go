package usage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var ErrMeterInvalid = errors.New("usage meter is invalid")

type Meter struct {
	Node       string
	Epoch      string
	Counters   *Counters
	Queue      *Queue
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Persist    func() error
	Now        func() time.Time

	mu    sync.Mutex
	start map[Key]time.Time
	last  map[Key]uint64
}

// RestoreBaseline marks durable counters as already represented by the
// restored pending queue or by an earlier acknowledged report.
func (m *Meter) RestoreBaseline() error {
	if m == nil || m.Counters == nil || m.Queue == nil {
		return ErrMeterInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		m.last = make(map[Key]uint64)
	}
	for _, record := range m.Counters.Snapshot() {
		m.last[record.Key] = record.Bytes
	}
	return nil
}

func (m *Meter) Record(environment, route string, revision uint64, ingress, egress uint64) error {
	if m == nil || m.Node == "" || m.Epoch == "" || environment == "" || route == "" || revision == 0 || m.Counters == nil || m.Queue == nil || m.KeyID == "" || len(m.PrivateKey) != ed25519.PrivateKeySize || m.Persist == nil {
		return ErrMeterInvalid
	}
	if ingress != 0 {
		m.Counters.Add(Key{Node: m.Node, Epoch: m.Epoch, Environment: environment, Route: route, Revision: revision, Direction: "ingress"}, ingress)
	}
	if egress != 0 {
		m.Counters.Add(Key{Node: m.Node, Epoch: m.Epoch, Environment: environment, Route: route, Revision: revision, Direction: "egress"}, egress)
	}
	return nil
}

func (m *Meter) Flush() error {
	if m == nil || m.Counters == nil || m.Queue == nil || m.Persist == nil {
		return ErrMeterInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		m.last = make(map[Key]uint64)
	}
	if m.start == nil {
		m.start = make(map[Key]time.Time)
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	for _, record := range m.Counters.Snapshot() {
		if record.Bytes == 0 || record.Bytes <= m.last[record.Key] {
			continue
		}
		start := m.start[record.Key]
		if start.IsZero() {
			start = now
		}
		operationID := meterOperationID(record.Key, record.Bytes)
		report, err := NewSignedReport(m.KeyID, m.PrivateKey, SignedDocument{OperationID: operationID, Key: record.Key, Bytes: record.Bytes, Start: start, End: now})
		if err != nil {
			return err
		}
		if err := m.Queue.EnqueueLatest(report); err != nil {
			return err
		}
		m.last[record.Key] = record.Bytes
		m.start[record.Key] = now
	}
	return m.Persist()
}

func meterOperationID(key Key, absolute uint64) string {
	canonical, _ := json.Marshal(struct {
		Key   Key    `json:"key"`
		Bytes uint64 `json:"bytes"`
	}{key, absolute})
	digest := sha256.Sum256(canonical)
	return "usage_" + hex.EncodeToString(digest[:16])
}
