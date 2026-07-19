package operation

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func validRequest(now time.Time) Request {
	return Request{OperationID: "op_admit_0001", JTI: "jti_admit_0001", Canonical: []byte(`{"generation":3}`), Decision: []byte(`{"accepted":true}`), RetainUntil: now.Add(time.Minute)}
}

func TestConsumeDuplicateAndChangedReplay(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	journal, _ := NewJournal(2)
	request := validRequest(now)
	first, err := journal.Consume(now, request)
	if err != nil || first.Duplicate {
		t.Fatalf("first = %+v, %v", first, err)
	}
	request.Canonical[0], request.Decision[0] = 'x', 'x'
	duplicate := validRequest(now)
	duplicate.Decision = []byte(`{"accepted":false}`)
	result, err := journal.Consume(now, duplicate)
	if err != nil || !result.Duplicate || string(result.Decision) != `{"accepted":true}` {
		t.Fatalf("duplicate = %+v, %v", result, err)
	}
	changed := duplicate
	changed.Canonical = []byte(`{"generation":4}`)
	if _, err := journal.Consume(now, changed); !errors.Is(err, ErrReplay) {
		t.Fatalf("changed replay error = %v", err)
	}
	changed = duplicate
	changed.OperationID = "op_admit_0002"
	if _, err := journal.Consume(now, changed); !errors.Is(err, ErrReplay) {
		t.Fatalf("JTI replay error = %v", err)
	}
}

func TestConsumeIsAtomicUnderConcurrency(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	journal, _ := NewJournal(1)
	request := validRequest(now)
	var fresh, duplicates, failed atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			outcome, err := journal.Consume(now, request)
			switch {
			case err != nil:
				failed.Add(1)
			case outcome.Duplicate:
				duplicates.Add(1)
			default:
				fresh.Add(1)
			}
		}()
	}
	group.Wait()
	if fresh.Load() != 1 || duplicates.Load() != 31 || failed.Load() != 0 {
		t.Fatalf("fresh=%d duplicates=%d failed=%d", fresh.Load(), duplicates.Load(), failed.Load())
	}
}

func TestRetentionAndCapacity(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	journal, _ := NewJournal(1)
	if _, err := journal.Consume(now, validRequest(now)); err != nil {
		t.Fatal(err)
	}
	second := validRequest(now)
	second.OperationID, second.JTI = "op_admit_0002", "jti_admit_0002"
	if _, err := journal.Consume(now, second); !errors.Is(err, ErrFull) {
		t.Fatalf("capacity error = %v", err)
	}
	if removed := journal.RemoveExpired(now.Add(time.Minute - time.Nanosecond)); removed != 0 {
		t.Fatalf("removed early: %d", removed)
	}
	if removed := journal.RemoveExpired(now.Add(time.Minute)); removed != 1 {
		t.Fatalf("removed: %d", removed)
	}
	if _, err := journal.Consume(now, second); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotRestorePreservesReplayDecision(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	original, _ := NewJournal(2)
	request := validRequest(now)
	if _, err := original.Consume(now, request); err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(original.Snapshot(), 2)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.Consume(now, request)
	if err != nil || !result.Duplicate || string(result.Decision) != `{"accepted":true}` {
		t.Fatalf("restored = %+v, %v", result, err)
	}
}
