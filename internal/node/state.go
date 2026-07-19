package node

import (
	"sync"
	"time"
)

type Phase string

const (
	Starting Phase = "starting"
	Ready    Phase = "ready"
	Draining Phase = "draining"
	Stopped  Phase = "stopped"
)

type Snapshot struct {
	NodeID        string    `json:"node_id"`
	Phase         Phase     `json:"phase"`
	Live          bool      `json:"live"`
	Ready         bool      `json:"ready"`
	DrainDeadline time.Time `json:"drain_deadline,omitempty"`
}

type State struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

func New(nodeID string) *State {
	return &State{snapshot: Snapshot{NodeID: nodeID, Phase: Starting, Live: true}}
}

func (s *State) MarkReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Phase != Starting {
		return false
	}
	s.snapshot.Phase, s.snapshot.Ready = Ready, true
	return true
}

func (s *State) BeginDrain(deadline time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Phase == Draining || s.snapshot.Phase == Stopped {
		return false
	}
	s.snapshot.Phase = Draining
	s.snapshot.Ready = false
	s.snapshot.DrainDeadline = deadline
	return true
}

func (s *State) SetControlAvailable(available bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Phase != Ready {
		return false
	}
	s.snapshot.Ready = available
	return true
}

func (s *State) MarkStopped() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.Phase, s.snapshot.Live, s.snapshot.Ready = Stopped, false, false
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}
