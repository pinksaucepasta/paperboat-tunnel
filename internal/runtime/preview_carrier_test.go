package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
)

type previewCarrierSourceFake struct {
	mu           sync.Mutex
	snapshots    [][]control.PreviewCarrierAdmission
	index        int
	ackError     error
	ackCalls     int
	detachCalls  int
	detachments  []control.PreviewCarrierDetachment
	observations []control.PreviewCarrierObservation
}

type previewCarrierSnapshotSourceFake struct {
	base        *previewCarrierSourceFake
	detachments []control.PreviewCarrierDetachment
}

func (f *previewCarrierSnapshotSourceFake) PreviewCarrierSnapshot(ctx context.Context, nodeID, processEpoch string) (control.PreviewCarrierSnapshot, error) {
	admissions, err := f.base.PreviewCarrierAdmissions(ctx, nodeID, processEpoch)
	if err != nil {
		return control.PreviewCarrierSnapshot{}, err
	}
	if f.base.index < 2 {
		return control.PreviewCarrierSnapshot{Admissions: admissions, Detachments: []control.PreviewCarrierDetachment{}}, nil
	}
	return control.PreviewCarrierSnapshot{Admissions: admissions, Detachments: append([]control.PreviewCarrierDetachment(nil), f.detachments...)}, nil
}

func (f *previewCarrierSnapshotSourceFake) PreviewCarrierAdmissions(ctx context.Context, nodeID, processEpoch string) ([]control.PreviewCarrierAdmission, error) {
	return f.base.PreviewCarrierAdmissions(ctx, nodeID, processEpoch)
}

func (f *previewCarrierSnapshotSourceFake) AcknowledgePreviewCarrierAdmissions(ctx context.Context, nodeID, processEpoch string, admissions []control.PreviewCarrierAdmission) error {
	return f.base.AcknowledgePreviewCarrierAdmissions(ctx, nodeID, processEpoch, admissions)
}

func (f *previewCarrierSnapshotSourceFake) ObservePreviewCarriers(ctx context.Context, nodeID, processEpoch string, observations []control.PreviewCarrierObservation) error {
	return f.base.ObservePreviewCarriers(ctx, nodeID, processEpoch, observations)
}

func (f *previewCarrierSnapshotSourceFake) DetachPreviewCarriers(ctx context.Context, nodeID, processEpoch string, detachments []control.PreviewCarrierDetachment) error {
	return f.base.DetachPreviewCarriers(ctx, nodeID, processEpoch, detachments)
}

func (f *previewCarrierSourceFake) PreviewCarrierAdmissions(context.Context, string, string) ([]control.PreviewCarrierAdmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.snapshots) == 0 {
		return []control.PreviewCarrierAdmission{}, nil
	}
	index := f.index
	if index >= len(f.snapshots) {
		index = len(f.snapshots) - 1
	}
	f.index++
	return append([]control.PreviewCarrierAdmission(nil), f.snapshots[index]...), nil
}

func (f *previewCarrierSourceFake) AcknowledgePreviewCarrierAdmissions(_ context.Context, _, _ string, admissions []control.PreviewCarrierAdmission) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ackCalls++
	if f.ackError != nil {
		return f.ackError
	}
	// The real server ACK is idempotent and the edge must acknowledge every
	// member of a complete snapshot, including an empty successful snapshot.
	_ = admissions
	return nil
}

func (f *previewCarrierSourceFake) ObservePreviewCarriers(_ context.Context, _, _ string, observations []control.PreviewCarrierObservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observations = append(f.observations, observations...)
	return nil
}

func (f *previewCarrierSourceFake) DetachPreviewCarriers(_ context.Context, _, _ string, detachments []control.PreviewCarrierDetachment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachCalls++
	f.detachments = append(f.detachments, detachments...)
	return nil
}

func TestPreviewCarrierWorkerCommitsOnlyCompleteSnapshots(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	a := testPreviewCarrierAdmission("preview_a", "operation_a", "route_a", "a.preview.example.test", now.Add(time.Hour))
	b := testPreviewCarrierAdmission("preview_b", "operation_b", "route_b", "b.preview.example.test", now.Add(time.Hour))
	source := &previewCarrierSourceFake{snapshots: [][]control.PreviewCarrierAdmission{{a}, {a, b}, {}}}
	expected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := edgehttp.NewDataCarrierPreviewRegistry(edgehttp.DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPreviewCarrierWorker(PreviewCarrierWorkerConfig{Source: source, Expected: expected, Registry: routes, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	worker.reconcile(context.Background())
	assertPreviewAdmissionState(t, expected.Snapshot(), map[string]bool{"operation_a\x00route_a": true})
	worker.reconcile(context.Background())
	assertPreviewAdmissionState(t, expected.Snapshot(), map[string]bool{"operation_a\x00route_a": true, "operation_b\x00route_b": true})
	worker.reconcile(context.Background())
	if got := expected.Snapshot(); len(got) != 0 {
		t.Fatalf("empty complete snapshot left admissions: %+v", got)
	}
	if source.ackCalls != 3 {
		t.Fatalf("ack calls = %d, want one idempotent ACK per snapshot", source.ackCalls)
	}
}

func TestPreviewCarrierWorkerLostAckThenRestartReplaysSnapshot(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	a := testPreviewCarrierAdmission("preview_a", "operation_a", "route_a", "a.preview.example.test", now.Add(time.Hour))
	source := &previewCarrierSourceFake{snapshots: [][]control.PreviewCarrierAdmission{{a}, {a}}, ackError: errors.New("lost ACK response")}
	expected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := edgehttp.NewDataCarrierPreviewRegistry(edgehttp.DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewPreviewCarrierWorker(PreviewCarrierWorkerConfig{Source: source, Expected: expected, Registry: routes, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first.reconcile(context.Background())
	if admissions := expected.Snapshot(); len(admissions) != 1 || admissions[0].Admitted {
		t.Fatalf("lost ACK should leave one pending admission, got %+v", admissions)
	}

	// A process restart loses only local pending state. The server's complete
	// desired snapshot is replayed and a new worker can safely acknowledge it.
	source.ackError = nil
	restartedExpected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPreviewCarrierWorker(PreviewCarrierWorkerConfig{Source: source, Expected: restartedExpected, Registry: routes, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	restarted.reconcile(context.Background())
	assertPreviewAdmissionState(t, restartedExpected.Snapshot(), map[string]bool{"operation_a\x00route_a": true})
}

func TestPreviewCarrierWorkerRejectsOverLimitSnapshotAndPreservesLKG(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	base := testPreviewCarrierAdmission("preview_a", "operation_a", "route_a", "a.preview.example.test", now.Add(time.Hour))
	tooMany := make([]control.PreviewCarrierAdmission, 4097)
	for index := range tooMany {
		tooMany[index] = base
		tooMany[index].Binding.PreviewID = fmt.Sprintf("preview_%04d", index)
		tooMany[index].Binding.OperationID = fmt.Sprintf("operation_%04d", index)
		tooMany[index].Binding.RouteID = fmt.Sprintf("route_%04d", index)
		tooMany[index].Hostname = fmt.Sprintf("p%04d.preview.example.test", index)
		tooMany[index].Endpoint = "https://" + tooMany[index].Hostname
	}
	source := &previewCarrierSourceFake{snapshots: [][]control.PreviewCarrierAdmission{{base}, tooMany}}
	expected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := edgehttp.NewDataCarrierPreviewRegistry(edgehttp.DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPreviewCarrierWorker(PreviewCarrierWorkerConfig{Source: source, Expected: expected, Registry: routes, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	worker.reconcile(context.Background())
	worker.reconcile(context.Background())
	assertPreviewAdmissionState(t, expected.Snapshot(), map[string]bool{"operation_a\x00route_a": true})
	if source.ackCalls != 1 {
		t.Fatalf("over-limit snapshot ACK calls = %d, want 1", source.ackCalls)
	}
}

func TestPreviewCarrierPrivateAdmissionPreservesPrivateRouteBeforeRegistryInstall(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	private := testPreviewCarrierAdmission("preview_private", "operation_private", "route_private", "private.preview.example.test", now.Add(time.Hour))
	private.AccessMode = "private"
	private.RouteKind = "preview_private_https_wss"
	expected, err := private.Expected("edge_1", now)
	if err != nil {
		t.Fatalf("private admission error = %v", err)
	}
	if expected.AccessMode != "private" || expected.RouteKind != "preview_private_https_wss" {
		t.Fatalf("private admission was normalized as public: %+v", expected)
	}
}

func TestPreviewCarrierWorkerAppliesAndAcknowledgesServerDetachGeneration(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	a := testPreviewCarrierAdmission("preview_detach", "operation_detach", "route_detach", "detach.preview.example.test", now.Add(time.Hour))
	detachment := control.PreviewCarrierDetachment{
		Schema: a.Schema, Kind: a.Kind, Binding: a.Binding, AttachmentGeneration: 2,
		Reason: "server_detach", ObservedAt: now,
	}
	base := &previewCarrierSourceFake{snapshots: [][]control.PreviewCarrierAdmission{{a}, {}}}
	source := &previewCarrierSnapshotSourceFake{base: base, detachments: []control.PreviewCarrierDetachment{detachment}}
	expected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := edgehttp.NewDataCarrierPreviewRegistry(edgehttp.DataCarrierPreviewRegistryConfig{BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPreviewCarrierWorker(PreviewCarrierWorkerConfig{Source: source, Expected: expected, Registry: routes, NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	worker.reconcile(context.Background())
	worker.reconcile(context.Background())
	if got := expected.Snapshot(); len(got) != 0 {
		t.Fatalf("server detach did not remove expected admission: %+v", got)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.detachments) != 1 || base.detachments[0].AttachmentGeneration != 2 || base.detachments[0].Reason != "server_detach" {
		t.Fatalf("detachment ACK = %+v", base.detachments)
	}
}

func TestPreviewCarrierDetachmentPreservesPreviewOwnerSession(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	route := edgehttp.DataCarrierPreviewRoute{
		PreviewID: "preview_owner", OperationID: "operation_owner",
		OwnerDeviceID: "host_1", OwnerSessionID: "owner_session_preview_1",
		Identity: datacarrier.Identity{
			AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1",
			SessionID: "stable_carrier_session_1", ProcessGeneration: 1, Generation: 1,
		},
		LeaseGeneration: 1, RouteID: "route_owner", Revision: 1,
	}
	observation := observationFromRoute(route, now, "expired", "lease_expired")
	if observation.Binding.OwnerDeviceID != route.OwnerDeviceID || observation.Binding.OwnerSessionID != route.OwnerSessionID {
		t.Fatalf("observation owner = %s/%s, want %s/%s", observation.Binding.OwnerDeviceID, observation.Binding.OwnerSessionID, route.OwnerDeviceID, route.OwnerSessionID)
	}
	if observation.Binding.OwnerSessionID == route.Identity.SessionID {
		t.Fatal("preview owner session was replaced by the stable carrier session")
	}
}

func assertPreviewAdmissionState(t *testing.T, admissions []datacarrier.ExpectedAdmission, want map[string]bool) {
	t.Helper()
	if len(admissions) != len(want) {
		t.Fatalf("admission count = %d, want %d: %+v", len(admissions), len(want), admissions)
	}
	for _, admission := range admissions {
		key := admission.OperationID + "\x00" + admission.RouteID
		admitted, ok := want[key]
		if !ok || admission.Admitted != admitted {
			t.Fatalf("admission %+v not in expected state %v", admission, want)
		}
	}
}

func testPreviewCarrierAdmission(previewID, operationID, routeID, hostname string, expiresAt time.Time) control.PreviewCarrierAdmission {
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	digest := sha256.Sum256(publicKey)
	trust, err := control.NewProcessCarrierServerTrust("edge_1", "edge_epoch_1", "edge.example.test", expiresAt.Add(-time.Hour), 2*time.Hour)
	if err != nil {
		panic(err)
	}
	return control.PreviewCarrierAdmission{
		Schema: "paperboat.preview-tunnel/v1", Kind: "preview_carrier_attachment",
		Binding: control.PreviewCarrierBinding{
			AccountID: "account_1", PreviewID: previewID, OperationID: operationID,
			OwnerDeviceID: "host_1", OwnerSessionID: "owner_session_1", HostID: "host_1",
			LeaseGeneration: 1, TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1",
			ProcessGeneration: 1, ConfigGeneration: 1, RouteID: routeID, RouteGeneration: 1,
			EdgeNodeID: "edge_1", EdgeProcessEpoch: "edge_epoch_1", EdgeCarrierServerSPKISHA256: trust.SPKISHA256, EdgeCarrierServerCertificateChainPEM: trust.CertificateChainPEM, MachineIdentityPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
			MachineIdentityThumbprint: "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:]),
		},
		AttachmentGeneration: 1, ConfigContentHash: "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EdgeEndpoints: []string{"tls://edge.example.test:27443", "quic://edge.example.test:27444"}, Endpoint: "https://" + hostname,
		ExpiresAt: expiresAt, AccessMode: "public", RouteKind: "preview_public_https_wss", RouteRevision: 1,
	}
}

var _ control.PreviewCarrierSource = (*previewCarrierSourceFake)(nil)
