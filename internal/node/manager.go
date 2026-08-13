package node

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

var (
	ErrNotReady = errors.New("node is not ready for new assignments")
	ErrCapacity = errors.New("node connector capacity is exhausted")
	ErrUnknown  = errors.New("connector is not owned by this node")
	ErrDraining = errors.New("node is draining")
)

type ConnectorSnapshot struct {
	ID         string
	Generation uint64
	Streams    uint32
}

type ManagerSnapshot struct {
	Connectors []ConnectorSnapshot
	Streams    uint32
	Capacity   uint32
	Draining   bool
}

type Manager struct {
	state    *State
	capacity uint32

	mu         sync.Mutex
	connectors map[string]*connector
	wake       chan struct{}
}

type connector struct {
	generation uint64
	streams    uint32
	retired    map[uint64]uint32
}

func NewManager(state *State, capacity uint32) (*Manager, error) {
	if state == nil || capacity == 0 {
		return nil, ErrCapacity
	}
	return &Manager{state: state, capacity: capacity, connectors: make(map[string]*connector), wake: make(chan struct{})}, nil
}

func (m *Manager) AdmitConnector(id string, generation uint64) error {
	if id == "" || generation == 0 {
		return ErrUnknown
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Snapshot().Phase != Ready {
		return ErrNotReady
	}
	if _, exists := m.connectors[id]; exists {
		return nil
	}
	if uint32(len(m.connectors)) >= m.capacity {
		return ErrCapacity
	}
	m.connectors[id] = &connector{generation: generation, retired: make(map[uint64]uint32)}
	return nil
}

func (m *Manager) ReplaceConnector(id string, generation uint64) error {
	if id == "" || generation == 0 {
		return ErrUnknown
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Snapshot().Phase != Ready {
		return ErrNotReady
	}
	current, exists := m.connectors[id]
	if !exists {
		return ErrUnknown
	}
	if generation <= current.generation {
		return ErrUnknown
	}
	if current.streams != 0 {
		current.retired[current.generation] += current.streams
	}
	current.generation, current.streams = generation, 0
	return nil
}

func (m *Manager) RemoveConnector(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.connectors[id]
	if !exists {
		return ErrUnknown
	}
	if current.streams != 0 || len(current.retired) != 0 {
		return ErrDraining
	}
	delete(m.connectors, id)
	m.signalLocked()
	return nil
}

func (m *Manager) OpenStream(id string, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Snapshot().Phase != Ready {
		return ErrDraining
	}
	current, exists := m.connectors[id]
	if !exists {
		return ErrUnknown
	}
	if current.generation != generation {
		return ErrUnknown
	}
	if current.streams == ^uint32(0) {
		return ErrCapacity
	}
	current.streams++
	return nil
}

func (m *Manager) CloseStream(id string, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.connectors[id]
	if !exists {
		return ErrUnknown
	}
	if current.generation == generation && current.streams > 0 {
		current.streams--
	} else if current.retired[generation] > 0 {
		current.retired[generation]--
		if current.retired[generation] == 0 {
			delete(current.retired, generation)
		}
	} else {
		return ErrUnknown
	}
	m.signalLocked()
	return nil
}

// Drain fences new assignments, waits for existing streams, and returns true if
// the deadline forced ownership cleanup. It deliberately leaves liveness to the
// process lifecycle owner; callers may still report the draining observation.
func (m *Manager) Drain(ctx context.Context, deadline time.Time) (forced bool) {
	m.state.BeginDrain(deadline)
	for {
		m.mu.Lock()
		if m.totalStreamsLocked() == 0 {
			m.mu.Unlock()
			return false
		}
		wake := m.wake
		m.mu.Unlock()
		wait := time.NewTimer(time.Until(deadline))
		select {
		case <-wake:
			stopTimer(wait)
		case <-wait.C:
			m.mu.Lock()
			m.connectors = make(map[string]*connector)
			m.signalLocked()
			m.mu.Unlock()
			return true
		case <-ctx.Done():
			stopTimer(wait)
			m.mu.Lock()
			m.connectors = make(map[string]*connector)
			m.signalLocked()
			m.mu.Unlock()
			return true
		}
	}
}

func (m *Manager) Snapshot() ManagerSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := ManagerSnapshot{Capacity: m.capacity, Connectors: make([]ConnectorSnapshot, 0, len(m.connectors))}
	for id, current := range m.connectors {
		snapshot.Connectors = append(snapshot.Connectors, ConnectorSnapshot{ID: id, Generation: current.generation, Streams: current.streams})
		snapshot.Streams = saturatingAddUint32(snapshot.Streams, current.streams)
		for generation, streams := range current.retired {
			snapshot.Connectors = append(snapshot.Connectors, ConnectorSnapshot{ID: id, Generation: generation, Streams: streams})
			snapshot.Streams = saturatingAddUint32(snapshot.Streams, streams)
		}
	}
	snapshot.Draining = m.state.Snapshot().Phase == Draining
	return snapshot
}

func (m *Manager) Observation(nodeID, processEpoch string, at time.Time) control.NodeObservation {
	snapshot := m.Snapshot()
	phase := m.state.Snapshot().Phase
	return control.NodeObservation{NodeID: nodeID, ProcessEpoch: processEpoch, Ready: phase == Ready, Draining: phase == Draining, ActiveStreams: snapshot.Streams, At: at}
}

func (m *Manager) RegisterAndHeartbeat(ctx context.Context, sink control.NodeSink, registration control.NodeRegistration, at time.Time) error {
	if sink == nil {
		return ErrUnknown
	}
	if err := sink.RegisterNode(ctx, registration); err != nil {
		return err
	}
	return sink.Heartbeat(ctx, m.Observation(registration.NodeID, registration.ProcessEpoch, at))
}

func (m *Manager) totalStreamsLocked() uint32 {
	var total uint32
	for _, current := range m.connectors {
		total = saturatingAddUint32(total, current.streams)
		for _, streams := range current.retired {
			total = saturatingAddUint32(total, streams)
		}
	}
	return total
}
func saturatingAddUint32(current, value uint32) uint32 {
	if value > ^uint32(0)-current {
		return ^uint32(0)
	}
	return current + value
}
func (m *Manager) signalLocked() { close(m.wake); m.wake = make(chan struct{}) }
func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
