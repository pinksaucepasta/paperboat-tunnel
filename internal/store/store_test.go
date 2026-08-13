package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func testState() State {
	return State{Version: CurrentVersion, CounterEpoch: "epoch_test_01", Operations: []operation.Record{{OperationID: "op_1", JTI: "jti_1", RequestHash: "0000000000000000000000000000000000000000000000000000000000000000", Decision: []byte("decision"), RetainUntil: time.Unix(100, 0)}}, Counters: []usage.CounterRecord{{Key: usage.Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Direction: "egress"}, Bytes: 12}}, PendingUsage: usage.QueueState{Reports: []usage.Report{{OperationID: "usage_1", Payload: []byte("signed")}}}}
}

func TestSaveLoadAndPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := Save(path, testState()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CounterEpoch != "epoch_test_01" || len(loaded.Operations) != 1 || len(loaded.PendingUsage.Reports) != 1 {
		t.Fatalf("loaded = %+v", loaded)
	}
}

func TestCorruptionAndUnsafePermissionsFailClosed(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := Save(path, testState()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unsafe error = %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"sha256":"bad","state":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption error = %v", err)
	}
}

func TestLoadRejectsDuplicateCanonicalFieldsEvenWithValidChecksum(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := Save(path, testState()); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicateEnvelope := bytes.Replace(payload, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if bytes.Equal(duplicateEnvelope, payload) {
		t.Fatal("envelope fixture did not mutate")
	}
	if err := os.WriteFile(path, duplicateEnvelope, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate envelope error=%v", err)
	}

	var wrapped envelope
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		t.Fatal(err)
	}
	duplicateState := bytes.Replace(wrapped.State, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if bytes.Equal(duplicateState, wrapped.State) {
		t.Fatal("state fixture did not mutate")
	}
	digest := sha256.Sum256(duplicateState)
	wrapped.State = duplicateState
	wrapped.Checksum = hex.EncodeToString(digest[:])
	duplicatePayload, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, duplicatePayload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate checksummed state error=%v", err)
	}
}
