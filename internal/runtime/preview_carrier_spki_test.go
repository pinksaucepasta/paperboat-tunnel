package runtime

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
)

func TestPreviewCarrierObservationsRetainEdgeServerBinding(t *testing.T) {
	now := time.Now().UTC()
	trust, err := control.NewProcessCarrierServerTrust("edge_1", "edge_epoch_1", "edge.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admission := datacarrier.ExpectedAdmission{
		Schema: controlPreviewCarrierSchema, Kind: controlPreviewCarrierKind,
		EdgeNodeID: "edge_1", PreviewID: "preview_spki", OperationID: "operation_spki",
		OwnerDeviceID: "host_1", OwnerSessionID: "owner_session_1",
		Identity: datacarrier.Identity{
			AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1",
			ProcessGeneration: 1, Generation: 1,
		},
		LeaseGeneration: 1, ConfigGeneration: 1,
		ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RouteID:           "route_spki", EdgeProcessEpoch: "edge_epoch_1",
		EdgeCarrierServerSPKISHA256: trust.SPKISHA256, EdgeCarrierServerCertificateChainPEM: trust.CertificateChainPEM,
		AccessMode: datacarrier.PreviewCarrierAccessPublic, RouteKind: datacarrier.PreviewCarrierRoute,
		Hostname: "preview-spki.preview.example.test", RouteRevision: 1, AttachmentGeneration: 1,
		Endpoint: "https://preview-spki.preview.example.test", ExpiresAt: now.Add(time.Hour),
		MachineIdentityPublicKey: "", MachineIdentityThumbprint: "",
	}

	fromAdmission := observationFromAdmission(admission, "edge_ready", "", now)
	assertPreviewCarrierServerBinding(t, fromAdmission.Binding, trust.SPKISHA256, trust.CertificateChainPEM)

	fromRoute := observationFromRoute(edgehttp.DataCarrierPreviewRoute{
		RouteID: admission.RouteID, Hostname: admission.Hostname, Kind: admission.RouteKind, Revision: admission.RouteRevision,
		Identity: admission.Identity, PreviewID: admission.PreviewID, OperationID: admission.OperationID,
		OwnerDeviceID: admission.OwnerDeviceID, OwnerSessionID: admission.OwnerSessionID, AccessMode: admission.AccessMode,
		EdgeNodeID: admission.EdgeNodeID, EdgeProcessEpoch: admission.EdgeProcessEpoch,
		EdgeCarrierServerSPKISHA256: trust.SPKISHA256, EdgeCarrierServerCertificateChainPEM: trust.CertificateChainPEM,
		LeaseGeneration: admission.LeaseGeneration, AttachmentGeneration: admission.AttachmentGeneration,
	}, now, "edge_ready", "")
	assertPreviewCarrierServerBinding(t, fromRoute.Binding, trust.SPKISHA256, trust.CertificateChainPEM)
}

func assertPreviewCarrierServerBinding(t *testing.T, binding control.PreviewCarrierBinding, wantPin, wantChain string) {
	t.Helper()
	if binding.EdgeCarrierServerSPKISHA256 != wantPin {
		t.Fatalf("SPKI pin = %q, want %q", binding.EdgeCarrierServerSPKISHA256, wantPin)
	}
	if binding.EdgeCarrierServerCertificateChainPEM != wantChain {
		t.Fatal("certificate chain was not retained")
	}
}
