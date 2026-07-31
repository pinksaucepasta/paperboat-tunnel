package testedge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

var (
	ErrUnknownCredential = errors.New("unknown fake credential")
	ErrUnknownAssignment = errors.New("unknown fake assignment")
	ErrOperationConflict = errors.New("fake control operation conflict")
	ErrAckLost           = errors.New("fake control acknowledgment lost")
	ErrInvalid           = errors.New("fake control request invalid")
)

type Fake struct {
	mu            sync.Mutex
	credentials   map[string]admission.Claims
	assignments   map[string]admission.Current
	operations    map[string]fakeOperation
	maximum       map[usage.Key]uint64
	nodes         map[string]control.NodeObservation
	registrations map[string]control.NodeRegistration
	routes        map[string]control.RouteAssignment
	usageKeys     map[string]ed25519.PublicKey
	loseNextAck   bool
}

type fakeOperation struct {
	hash  [sha256.Size]byte
	delta uint64
}

func New() *Fake {
	return &Fake{credentials: map[string]admission.Claims{}, assignments: map[string]admission.Current{}, operations: map[string]fakeOperation{}, maximum: map[usage.Key]uint64{}, nodes: map[string]control.NodeObservation{}, registrations: map[string]control.NodeRegistration{}, routes: map[string]control.RouteAssignment{}, usageKeys: map[string]ed25519.PublicKey{}}
}

func (f *Fake) SetCredential(token string, claims admission.Claims) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credentials[token] = claims
}
func (f *Fake) SetAssignment(environment, machine, connector string, current admission.Current) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assignments[environment+"\x00"+machine+"\x00"+connector] = current
}

func (f *Fake) Verify(_ context.Context, token string) (admission.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	claims, ok := f.credentials[token]
	if !ok {
		return admission.Claims{}, ErrUnknownCredential
	}
	return claims, nil
}

func (f *Fake) Current(_ context.Context, environment, machine, connector string) (admission.Current, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, ok := f.assignments[environment+"\x00"+machine+"\x00"+connector]
	if !ok {
		return admission.Current{}, ErrUnknownAssignment
	}
	return current, nil
}

func (f *Fake) ReportUsage(_ context.Context, report control.UsageReport) (control.UsageResult, error) {
	if report.OperationID == "" || report.Key.Node == "" || report.Key.Epoch == "" || report.Key.Environment == "" || report.Key.Route == "" || report.Key.Revision == 0 || (report.Key.Direction != "ingress" && report.Key.Direction != "egress") || report.Interval[0].IsZero() || report.Interval[1].Before(report.Interval[0]) {
		return control.UsageResult{}, ErrInvalid
	}
	if len(report.Payload) > 0 {
		f.mu.Lock()
		keys := make(map[string]ed25519.PublicKey, len(f.usageKeys))
		for keyID, public := range f.usageKeys {
			keys[keyID] = append(ed25519.PublicKey(nil), public...)
		}
		f.mu.Unlock()
		document, err := usage.VerifySignedReportWithKeys(keys, report.Payload)
		if err != nil || document.OperationID != report.OperationID || document.Key != report.Key || document.Bytes != report.Bytes || !document.Start.Equal(report.Interval[0]) || !document.End.Equal(report.Interval[1]) {
			return control.UsageResult{}, ErrInvalid
		}
	}
	canonical, _ := json.Marshal(report)
	hash := sha256.Sum256(canonical)
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.operations[report.OperationID]; ok {
		if previous.hash != hash {
			return control.UsageResult{}, ErrOperationConflict
		}
		if f.loseNextAck {
			f.loseNextAck = false
			return control.UsageResult{}, ErrAckLost
		}
		return control.UsageResult{Delta: previous.delta}, nil
	}
	previous := f.maximum[report.Key]
	delta := uint64(0)
	if report.Bytes > previous {
		delta = report.Bytes - previous
		f.maximum[report.Key] = report.Bytes
	}
	f.operations[report.OperationID] = fakeOperation{hash: hash, delta: delta}
	if f.loseNextAck {
		f.loseNextAck = false
		return control.UsageResult{}, ErrAckLost
	}
	return control.UsageResult{Delta: delta}, nil
}

func (f *Fake) SetUsageKey(keyID string, public ed25519.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageKeys[keyID] = append(ed25519.PublicKey(nil), public...)
}

func (f *Fake) LoseNextAcknowledgment() { f.mu.Lock(); defer f.mu.Unlock(); f.loseNextAck = true }

func (f *Fake) RegisterNode(_ context.Context, registration control.NodeRegistration) error {
	if registration.NodeID == "" || registration.ProcessEpoch == "" || registration.Capacity == 0 {
		return errors.New("invalid node registration")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[registration.NodeID] = control.NodeObservation{NodeID: registration.NodeID, ProcessEpoch: registration.ProcessEpoch}
	f.registrations[registration.NodeID] = registration
	return nil
}

func (f *Fake) Heartbeat(_ context.Context, observation control.NodeObservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	registration, ok := f.registrations[observation.NodeID]
	if !ok || observation.ProcessEpoch == "" || observation.ProcessEpoch != registration.ProcessEpoch {
		return errors.New("node is not registered")
	}
	if observation.At.IsZero() {
		observation.At = time.Now()
	}
	f.nodes[observation.NodeID] = observation
	return nil
}

func (f *Fake) Node(nodeID string) (control.NodeObservation, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	node, ok := f.nodes[nodeID]
	return node, ok
}

func (f *Fake) Registration(nodeID string) (control.NodeRegistration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.registrations[nodeID]
	return value, ok
}

func (f *Fake) SetRoute(assignment control.RouteAssignment) error {
	if assignment.RouteID == "" || assignment.Revision == 0 || assignment.Environment == "" || assignment.Generation == 0 || assignment.NodeID == "" {
		return ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if current, ok := f.routes[assignment.RouteID]; ok && assignment.Revision < current.Revision {
		return ErrOperationConflict
	}
	f.routes[assignment.RouteID] = assignment
	return nil
}

func (f *Fake) Route(routeID string) (control.RouteAssignment, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.routes[routeID]
	return value, ok
}

func (f *Fake) DesiredRoutes(_ context.Context, nodeID string) ([]control.RouteAssignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]control.RouteAssignment, 0, len(f.routes))
	for _, route := range f.routes {
		if route.NodeID == nodeID {
			result = append(result, route)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RouteID < result[j].RouteID })
	return result, nil
}
