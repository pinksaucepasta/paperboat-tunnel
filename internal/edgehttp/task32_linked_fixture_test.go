package edgehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

type task32LinkedDescriptor struct {
	BaseURL           string `json:"base_url"`
	EdgeNodeID        string
	EdgeProcessEpoch  string
	EdgeCredential    string
	TLSCertificatePEM string
	TLSPrivateKeyPEM  string
	PreviewID         string `json:"preview_id"`
	TunnelID          string `json:"tunnel_id"`
	RouteID           string `json:"route_id"`
	PreviewEndpoint   string
	TunnelEndpoint    string
	MachinePublicKey  string
	MachineThumbprint string
	PreviewCarrier    control.InspectorCarrier
	TunnelCarrier     control.InspectorCarrier
}

type task32EdgeReady struct {
	HTTPSAddress          string `json:"https_address"`
	PreviewCarrierAddress string `json:"preview_carrier_address"`
	TunnelCarrierAddress  string `json:"tunnel_carrier_address"`
}

// TestTask32LinkedEdgeFixture is an opt-in process fixture. It uses the real
// node authority client, exact live registries and production inspector edge
// handler; the paired owner process supplies authenticated carrier clients.
func TestTask32LinkedEdgeFixture(t *testing.T) {
	descriptorPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK32_DESCRIPTOR"))
	readyPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK32_EDGE_READY"))
	stopPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK32_STOP"))
	httpsAddress := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK32_EDGE_LISTEN"))
	if httpsAddress == "" {
		httpsAddress = "127.0.0.1:0"
	}
	if descriptorPath == "" || readyPath == "" || stopPath == "" {
		t.Skip("set task32 descriptor, edge ready and stop paths")
	}
	var descriptor task32LinkedDescriptor
	readTask32PrivateJSON(t, descriptorPath, &descriptor)
	controlURL := descriptor.BaseURL
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(descriptor.TLSCertificatePEM)) {
		t.Fatal("invalid task32 authority CA")
	}
	httpControl, err := control.NewHTTPClient(control.HTTPConfig{BaseURL: controlURL, Credential: descriptor.EdgeCredential, Timeout: 10 * time.Second, TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}})
	if err != nil {
		t.Fatal(err)
	}
	durable, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	preview, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{ProcessEpoch: descriptor.EdgeProcessEpoch, MaximumRoutes: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer preview.Close()

	previewListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer previewListener.Close()
	tunnelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelListener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attachErr := make(chan error, 2)
	go acceptTask32Carrier(ctx, previewListener, descriptor.PreviewCarrier, descriptor.PreviewID, descriptor.PreviewEndpoint, descriptor.MachinePublicKey, descriptor.MachineThumbprint, durable, preview, true, attachErr)
	go acceptTask32Carrier(ctx, tunnelListener, descriptor.TunnelCarrier, descriptor.TunnelID, "", descriptor.MachinePublicKey, descriptor.MachineThumbprint, durable, preview, false, attachErr)

	certificate, err := tls.X509KeyPair([]byte(descriptor.TLSCertificatePEM), []byte(descriptor.TLSPrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	httpsListener, err := tls.Listen("tcp", httpsAddress, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer httpsListener.Close()
	authority := &control.InspectorAccessClient{HTTP: httpControl, NodeID: descriptor.EdgeNodeID, ProcessEpoch: descriptor.EdgeProcessEpoch}
	server := &http.Server{Handler: &InspectorEdgeAccess{Authority: authority, Carriers: durable, PreviewCarriers: preview}, ReadHeaderTimeout: 10 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(httpsListener) }()
	writeTask32PrivateJSON(t, readyPath, task32EdgeReady{HTTPSAddress: httpsListener.Addr().String(), PreviewCarrierAddress: previewListener.Addr().String(), TunnelCarrierAddress: tunnelListener.Addr().String()})
	defer os.Remove(readyPath)
	for {
		if _, err := os.Stat(stopPath); err == nil {
			break
		}
		select {
		case err := <-attachErr:
			if err != nil {
				t.Fatal(err)
			}
		case err := <-serverDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Fatal(err)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
}

func acceptTask32Carrier(ctx context.Context, listener net.Listener, carrier control.InspectorCarrier, resourceID, endpoint, machineKey, machineThumb string, durable *DataCarrierRouteRegistry, preview *DataCarrierPreviewRegistry, ephemeral bool, result chan<- error) {
	for {
		err := attachTask32Carrier(ctx, listener, carrier, resourceID, endpoint, machineKey, machineThumb, durable, preview, ephemeral)
		result <- err
		if err != nil || ctx.Err() != nil {
			return
		}
	}
}

func attachTask32Carrier(ctx context.Context, listener net.Listener, carrier control.InspectorCarrier, resourceID, endpoint, machineKey, machineThumb string, durable *DataCarrierRouteRegistry, preview *DataCarrierPreviewRegistry, ephemeral bool) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	identity := datacarrier.Identity{AccountID: carrier.AccountID, HostID: carrier.MachineID, TunnelID: carrier.TunnelID, ConnectorID: carrier.ConnectorID, SessionID: carrier.SessionID, ProcessGeneration: carrier.ProcessGeneration, Generation: carrier.Generation}
	config := datacarrier.DefaultConfig()
	config.Identity = identity
	config.Authorize = datacarrier.AuthorizerFunc(func(_ context.Context, _ datacarrier.Identity, open datacarrier.StreamOpen) error {
		if open.Kind != connectorprotocol.InspectorHTTP || open.RouteID != carrier.RouteID {
			return errors.New("fixture stream denied")
		}
		return nil
	})
	server, err := datacarrier.NewServer(ctx, connection, config)
	if err != nil {
		return err
	}
	if ephemeral {
		host := "preview.fixture.invalid"
		if parsed, parseErr := url.Parse(endpoint); parseErr == nil && parsed.Hostname() != "" {
			host = parsed.Hostname()
		}
		err = preview.Attach(DataCarrierPreviewRoute{RouteID: carrier.RouteID, Hostname: host, Kind: dataCarrierPreviewPrivateRouteKind, AccessMode: "private", Revision: carrier.RouteGeneration, Server: server, PreviewID: resourceID, OperationID: carrier.AssignmentID, OwnerDeviceID: carrier.OwnerDeviceID, OwnerSessionID: carrier.SessionID, EdgeNodeID: carrier.EdgeNodeID, EdgeProcessEpoch: carrier.EdgeProcessEpoch, LeaseGeneration: carrier.LeaseGeneration, AttachmentGeneration: carrier.AttachmentGeneration, ConfigContentHash: carrier.ConfigContentHash, Endpoint: endpoint, ExpiresAt: time.Now().Add(time.Hour), MachineIdentityPublicKey: machineKey, MachineIdentityThumbprint: machineThumb})
	} else {
		err = durable.AttachReplica(server, "fixture-public-key", "fixture-thumbprint", ReplicaState{Ready: true, Generation: carrier.Generation, RouteIDs: []string{carrier.RouteID}, HealthyRoutes: []string{carrier.RouteID}, RouteBindings: []ReplicaRouteBinding{{RouteID: carrier.RouteID, AssignmentID: carrier.AssignmentID, AssignmentGeneration: carrier.AssignmentGeneration, RouteGeneration: carrier.RouteGeneration, ConfigContentHash: carrier.ConfigContentHash}}, FailureDomain: "task32", Capacity: 4})
	}
	return err
}

func readTask32PrivateJSON(t *testing.T, path string, out any) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("task32 descriptor must be a regular 0600 file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, out) != nil {
		t.Fatal("invalid task32 descriptor")
	}
}

func writeTask32PrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}
