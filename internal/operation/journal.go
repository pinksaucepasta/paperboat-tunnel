package operation

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

const maxDocumentBytes = 1 << 20

var (
	ErrInvalid = edgeerrors.New(edgeerrors.CodeOperationConflict, "operation is invalid", "create a new valid operation")
	ErrReplay  = edgeerrors.New(edgeerrors.CodeCredentialReplayed, "credential was already consumed", "request a fresh credential")
	ErrFull    = edgeerrors.New(edgeerrors.CodeStoreCapacity, "operation journal is at capacity", "restore journal capacity before retrying")
)

type Request struct {
	OperationID string
	JTI         string
	Canonical   []byte
	Decision    []byte
	RetainUntil time.Time
}

type Outcome struct {
	Decision  []byte
	Duplicate bool
}

type Record struct {
	OperationID string    `json:"operation_id"`
	JTI         string    `json:"jti"`
	RequestHash string    `json:"request_hash"`
	Decision    []byte    `json:"decision"`
	RetainUntil time.Time `json:"retain_until"`
}

type entry struct {
	operationID string
	jti         string
	requestHash [sha256.Size]byte
	decision    []byte
	retainUntil time.Time
}

// Journal atomically binds single-use JTIs and operation IDs to canonical decisions.
type Journal struct {
	mu          sync.Mutex
	maxEntries  int
	byOperation map[string]*entry
	byJTI       map[string]*entry
}

func NewJournal(maxEntries int) (*Journal, error) {
	if maxEntries < 1 {
		return nil, ErrInvalid
	}
	return &Journal{maxEntries: maxEntries, byOperation: make(map[string]*entry), byJTI: make(map[string]*entry)}, nil
}

func (j *Journal) Consume(now time.Time, request Request) (Outcome, error) {
	if request.OperationID == "" || request.JTI == "" || len(request.Canonical) == 0 || len(request.Canonical) > maxDocumentBytes || len(request.Decision) > maxDocumentBytes || !request.RetainUntil.After(now) {
		return Outcome{}, ErrInvalid
	}
	hash := sha256.Sum256(request.Canonical)
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing := j.byOperation[request.OperationID]; existing != nil {
		return duplicate(existing, request, hash)
	}
	if existing := j.byJTI[request.JTI]; existing != nil {
		return duplicate(existing, request, hash)
	}
	if len(j.byOperation) >= j.maxEntries {
		return Outcome{}, ErrFull
	}
	created := &entry{operationID: request.OperationID, jti: request.JTI, requestHash: hash, decision: clone(request.Decision), retainUntil: request.RetainUntil}
	j.byOperation[created.operationID], j.byJTI[created.jti] = created, created
	return Outcome{Decision: clone(created.decision)}, nil
}

func duplicate(existing *entry, request Request, hash [sha256.Size]byte) (Outcome, error) {
	if existing.operationID != request.OperationID || existing.jti != request.JTI || existing.requestHash != hash {
		return Outcome{}, ErrReplay
	}
	return Outcome{Decision: clone(existing.decision), Duplicate: true}, nil
}

func (j *Journal) RemoveExpired(now time.Time) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	removed := 0
	for id, existing := range j.byOperation {
		if now.Before(existing.retainUntil) {
			continue
		}
		delete(j.byOperation, id)
		delete(j.byJTI, existing.jti)
		removed++
	}
	return removed
}

func (j *Journal) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.byOperation)
}

func (j *Journal) Snapshot() []Record {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make([]Record, 0, len(j.byOperation))
	for _, value := range j.byOperation {
		result = append(result, Record{OperationID: value.operationID, JTI: value.jti, RequestHash: hex.EncodeToString(value.requestHash[:]), Decision: clone(value.decision), RetainUntil: value.retainUntil})
	}
	sort.Slice(result, func(i, k int) bool { return result[i].OperationID < result[k].OperationID })
	return result
}

func Restore(records []Record, maxEntries int) (*Journal, error) {
	journal, err := NewJournal(maxEntries)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.OperationID == "" || record.JTI == "" || len(record.Decision) > maxDocumentBytes || !record.RetainUntil.After(time.Unix(0, 0)) {
			return nil, ErrInvalid
		}
		raw, err := hex.DecodeString(record.RequestHash)
		if err != nil || len(raw) != sha256.Size {
			return nil, ErrInvalid
		}
		var hash [sha256.Size]byte
		copy(hash[:], raw)
		if journal.byOperation[record.OperationID] != nil || journal.byJTI[record.JTI] != nil || len(journal.byOperation) >= journal.maxEntries {
			return nil, ErrInvalid
		}
		value := &entry{operationID: record.OperationID, jti: record.JTI, requestHash: hash, decision: clone(record.Decision), retainUntil: record.RetainUntil}
		journal.byOperation[value.operationID], journal.byJTI[value.jti] = value, value
	}
	return journal, nil
}

func clone(value []byte) []byte { return append([]byte(nil), value...) }
