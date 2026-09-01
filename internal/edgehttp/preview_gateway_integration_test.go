package edgehttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

// TestGatewayRoutesAttachedPreviewToCarrierTransport proves the complete live
// public-preview path. A route published in the canonical preview registry is
// selected by the strict gateway matcher and forwarded over its authenticated
// carrier, rather than falling through to the legacy upstream (which would
// return a plain 404).
func TestGatewayRoutesAttachedPreviewToCarrierTransport(t *testing.T) {
	identity := testEdgePreviewIdentity(1, 1)
	server, client := testEdgePreviewCarrierPair(t, identity)
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{
		BaseDomain:   "preview.example.test",
		ProcessEpoch: "edge_epoch_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Attach(DataCarrierPreviewRoute{
		RouteID:          "preview_live",
		Hostname:         "app.preview.example.test",
		Kind:             dataCarrierPreviewRouteKind,
		EdgeProcessEpoch: "edge_epoch_1",
		Revision:         1,
		Server:           server,
	}); err != nil {
		t.Fatal(err)
	}

	serveDone := make(chan error, 1)
	go func() {
		stream, open, acceptErr := client.AcceptStream(context.Background())
		if acceptErr != nil {
			serveDone <- acceptErr
			return
		}
		if open.RouteID != "preview_live" || open.Kind != "https" || open.AccountID != identity.AccountID || open.TunnelID != identity.TunnelID || open.ConnectorID != identity.ConnectorID || open.SessionID != identity.SessionID || open.Generation != identity.Generation {
			_ = stream.Close()
			serveDone <- errors.New("unexpected preview carrier stream metadata")
			return
		}
		serveDone <- datacarrier.ServeHTTPStream(context.Background(), stream, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Host != "app.preview.example.test" || request.URL.Path != "/" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(writer, "preview reached over carrier\n")
		}), 4096, time.Second)
	}()

	transport, err := NewDataCarrierPreviewTransport(DataCarrierPreviewTransportConfig{
		Registry:          registry,
		StreamOpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGatewayWithTransports(Config{
		PreviewBaseDomain: "preview.example.test",
		TunnelBaseDomain:  "tunnels.example.test",
		RuntimeBaseDomain: "runtime.example.test",
		MaxHeaderBytes:    4096,
		MaxBodyBytes:      4096,
		Routes:            NewCompositeRouteMatcher(NewPreviewCarrierRouteMatcher(registry)),
		RequestID:         func() string { return "preview-live-request" },
	}, "127.0.0.1:1", transport, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://app.preview.example.test/", nil)
	request.Host = "app.preview.example.test"
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "preview reached over carrier\n" {
		t.Fatalf("gateway response = %d %q, want carrier response", response.Code, response.Body.String())
	}
	select {
	case serveErr := <-serveDone:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("carrier HTTP handler did not stop")
	}
}
