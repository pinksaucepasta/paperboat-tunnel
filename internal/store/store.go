package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

const (
	CurrentVersion uint32 = 1
	maxFileBytes          = 16 << 20
	maxStateBytes         = maxFileBytes - 1024
)

var (
	ErrCorrupt = errors.New("edge store is corrupt")
	ErrUnsafe  = errors.New("edge store permissions are unsafe")
	ErrVersion = errors.New("edge store version is unsupported")
)

type State struct {
	Version      uint32                `json:"version"`
	CounterEpoch string                `json:"counter_epoch"`
	Operations   []operation.Record    `json:"operations"`
	Counters     []usage.CounterRecord `json:"counters"`
	PendingUsage usage.QueueState      `json:"pending_usage"`
}

type envelope struct {
	Version  uint32          `json:"version"`
	Checksum string          `json:"sha256"`
	State    json.RawMessage `json:"state"`
}

func Save(path string, state State) error {
	if path == "" || state.Version != CurrentVersion || state.CounterEpoch == "" || len(state.Operations) > 100000 || len(state.Counters) > 100000 || len(state.PendingUsage.Reports) > 100000 {
		return ErrCorrupt
	}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode edge store: %w", err)
	}
	if len(stateBytes) > maxStateBytes {
		return ErrCorrupt
	}
	digest := sha256.Sum256(stateBytes)
	payload, err := json.Marshal(envelope{Version: CurrentVersion, Checksum: hex.EncodeToString(digest[:]), State: stateBytes})
	if err != nil {
		return fmt.Errorf("encode edge store envelope: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create edge store directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".edge-state-*")
	if err != nil {
		return fmt.Errorf("create edge store temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set edge store permissions: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write edge store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync edge store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close edge store: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace edge store: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open edge store directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync edge store directory: %w", err)
	}
	return nil
}

func Load(path string) (State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return State{}, ErrUnsafe
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	limited := io.LimitReader(file, maxFileBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return State{}, fmt.Errorf("read edge store: %w", err)
	}
	if len(payload) > maxFileBytes {
		return State{}, ErrCorrupt
	}
	var wrapped envelope
	if err := strictJSON(payload, &wrapped); err != nil {
		return State{}, ErrCorrupt
	}
	if wrapped.Version != CurrentVersion {
		return State{}, ErrVersion
	}
	digest := sha256.Sum256(wrapped.State)
	if wrapped.Checksum != hex.EncodeToString(digest[:]) {
		return State{}, ErrCorrupt
	}
	var state State
	if err := strictJSON(wrapped.State, &state); err != nil || state.Version != CurrentVersion || state.CounterEpoch == "" || len(state.Operations) > 100000 || len(state.Counters) > 100000 || len(state.PendingUsage.Reports) > 100000 {
		return State{}, ErrCorrupt
	}
	return state, nil
}

func strictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	return nil
}
