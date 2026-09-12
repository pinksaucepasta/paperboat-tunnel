package datacarrier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func TestExpectedAdmissionRegistryPeerBindingUsesCarrierURNSessionFence(t *testing.T) {
	public := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	for index := range public {
		public[index] = byte(index + 1)
	}
	digest := sha256.Sum256(public)
	encoded := base64.RawURLEncoding.EncodeToString(public)
	thumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	oldIdentity := Identity{
		AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1",
		ConnectorID: "connector_1", SessionID: "session_1",
		ProcessGeneration: 1, Generation: 1,
	}
	newIdentity := oldIdentity
	newIdentity.SessionID = "session_2"
	newIdentity.ProcessGeneration = 2

	registry, err := NewExpectedAdmissionRegistry(ExpectedAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "_epoch12", MaximumAdmissions: 2})
	if err != nil {
		t.Fatal(err)
	}
	registry.byKey["old"] = ExpectedAdmission{Identity: oldIdentity, EdgeProcessEpoch: "_epoch12", EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("a", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain", MachineIdentityPublicKey: encoded, MachineIdentityThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Admitted: true}
	registry.byKey["new"] = ExpectedAdmission{Identity: newIdentity, EdgeProcessEpoch: "_epoch12", EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("a", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain", MachineIdentityPublicKey: encoded, MachineIdentityThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Admitted: true}

	sharedIdentity := newIdentity
	sharedIdentity.AccountID = "teammate_account"
	sharedIdentity.TunnelID = "teammate_tunnel"
	sharedIdentity.ConnectorID = "teammate_connector"
	registry.byKey["shared"] = ExpectedAdmission{Identity: sharedIdentity, EdgeProcessEpoch: "_epoch12", MachineIdentityPublicKey: encoded, MachineIdentityThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Admitted: true}
	for name, identity := range map[string]Identity{"old": oldIdentity, "new": newIdentity, "shared account": sharedIdentity} {
		uri, err := connectorprotocol.CarrierIdentityURN(connectorprotocol.CarrierIdentityBinding{
			AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID,
			ConnectorID: identity.ConnectorID, SessionID: identity.SessionID,
			ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation,
			EdgeProcessEpoch: "_epoch12",
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := registry.PeerBinding(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: public, URIs: []*url.URL{uri}}}})
		if err != nil {
			t.Fatalf("%s identity: %v", name, err)
		}
		if got != identity {
			t.Fatalf("%s identity = %#v, want %#v", name, got, identity)
		}
	}
	replacementEdgeURI, err := connectorprotocol.CarrierIdentityURN(connectorprotocol.CarrierIdentityBinding{
		AccountID: newIdentity.AccountID, HostID: newIdentity.HostID, TunnelID: newIdentity.TunnelID,
		ConnectorID: newIdentity.ConnectorID, SessionID: newIdentity.SessionID,
		ProcessGeneration: newIdentity.ProcessGeneration, ConfigGeneration: newIdentity.Generation,
		EdgeProcessEpoch: "_epoch13",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.PeerBinding(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: public, URIs: []*url.URL{replacementEdgeURI}}}}); !errors.Is(err, ErrAdmissionNotExpected) {
		t.Fatalf("replacement edge URI matched stale process: %v", err)
	}

	if _, err := registry.PeerBinding(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: public}}}); !errors.Is(err, ErrAdmissionNotExpected) {
		t.Fatalf("missing URI error = %v", err)
	}
}

func TestExpectedAdmissionRegistryRejectsStaleCraftedRemoval(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	admission := testExpectedAdmissionForRegistry(now.Add(time.Hour))
	registry, err := NewExpectedAdmissionRegistry(ExpectedAdmissionRegistryConfig{NodeID: admission.EdgeNodeID, ProcessEpoch: admission.EdgeProcessEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Upsert(admission, now); err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*ExpectedAdmission){
		"schema":                     func(value *ExpectedAdmission) { value.Schema = "paperboat.preview-tunnel/v2" },
		"kind":                       func(value *ExpectedAdmission) { value.Kind = "other" },
		"edge node":                  func(value *ExpectedAdmission) { value.EdgeNodeID = "edge_2" },
		"edge process epoch":         func(value *ExpectedAdmission) { value.EdgeProcessEpoch = "_epoch13" },
		"preview":                    func(value *ExpectedAdmission) { value.PreviewID = "preview_2" },
		"owner device":               func(value *ExpectedAdmission) { value.OwnerDeviceID = "host_2" },
		"owner session":              func(value *ExpectedAdmission) { value.OwnerSessionID = "owner_session_2" },
		"carrier session":            func(value *ExpectedAdmission) { value.Identity.SessionID = "session_2" },
		"carrier process generation": func(value *ExpectedAdmission) { value.Identity.ProcessGeneration++ },
		"lease generation":           func(value *ExpectedAdmission) { value.LeaseGeneration++ },
		"config generation":          func(value *ExpectedAdmission) { value.ConfigGeneration++ },
		"config hash": func(value *ExpectedAdmission) {
			value.ConfigContentHash = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
		},
		"route kind":            func(value *ExpectedAdmission) { value.RouteKind = PreviewCarrierPrivateRoute },
		"hostname":              func(value *ExpectedAdmission) { value.Hostname = "other.preview.example.test" },
		"route revision":        func(value *ExpectedAdmission) { value.RouteRevision++ },
		"attachment generation": func(value *ExpectedAdmission) { value.AttachmentGeneration++ },
		"endpoint":              func(value *ExpectedAdmission) { value.Endpoint = "https://other.preview.example.test" },
		"expiry":                func(value *ExpectedAdmission) { value.ExpiresAt = value.ExpiresAt.Add(time.Minute) },
		"machine public key":    func(value *ExpectedAdmission) { value.MachineIdentityPublicKey = "stale-key" },
		"machine thumbprint":    func(value *ExpectedAdmission) { value.MachineIdentityThumbprint = "sha256:stale" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := admission
			mutate(&candidate)
			if err := registry.Remove(candidate); !errors.Is(err, ErrAdmissionConflict) {
				t.Fatalf("Remove error = %v, want ErrAdmissionConflict", err)
			}
			if got := registry.Snapshot(); len(got) != 1 || got[0].AttachmentGeneration != admission.AttachmentGeneration {
				t.Fatalf("stale removal changed registry: %+v", got)
			}
		})
	}

	for name, mutate := range map[string]func(*ExpectedAdmission){
		"operation key": func(value *ExpectedAdmission) { value.OperationID = "operation_2" },
		"route key":     func(value *ExpectedAdmission) { value.RouteID = "route_2" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := admission
			mutate(&candidate)
			if err := registry.Remove(candidate); err != nil {
				t.Fatalf("idempotent missing-key removal error = %v", err)
			}
			if got := registry.Snapshot(); len(got) != 1 {
				t.Fatalf("missing-key removal changed registry: %+v", got)
			}
		})
	}
}

func testExpectedAdmissionForRegistry(expiresAt time.Time) ExpectedAdmission {
	public := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	for index := range public {
		public[index] = byte(index + 1)
	}
	digest := sha256.Sum256(public)
	return ExpectedAdmission{
		Schema: PreviewCarrierSchema, Kind: PreviewCarrierKind,
		EdgeNodeID: "edge_1", PreviewID: "preview_1", OperationID: "operation_1",
		OwnerDeviceID: "host_1", OwnerSessionID: "owner_session_1",
		Identity:        Identity{AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 1, Generation: 1},
		LeaseGeneration: 1, ConfigGeneration: 1,
		ConfigContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RouteID:           "route_1", EdgeProcessEpoch: "_epoch12", AccessMode: PreviewCarrierAccessPublic,
		RouteKind: PreviewCarrierRoute, Hostname: "preview-1.preview.example.test", RouteRevision: 1,
		AttachmentGeneration: 1, Endpoint: "https://preview-1.preview.example.test", ExpiresAt: expiresAt,
		EdgeCarrierServerSPKISHA256:          "sha256:" + strings.Repeat("a", 64),
		EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain",
		MachineIdentityPublicKey:             base64.RawURLEncoding.EncodeToString(public),
		MachineIdentityThumbprint:            "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:]), Admitted: true,
	}
}
