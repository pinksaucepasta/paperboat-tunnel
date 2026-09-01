package edgehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

func TestDataCarrierPreviewAliasesShareAuthenticatedCarrierEndToEnd(t *testing.T) {
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{
		BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1", MaximumRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	identity := testEdgePreviewIdentity(7, 3)
	server, client := testEdgePreviewCarrierPair(t, identity)
	defer server.Close()
	defer client.Close()

	primary := DataCarrierPreviewRoute{
		RouteID: "preview_alias_01", Hostname: "managed.preview.example.test", Kind: dataCarrierPreviewRouteKind,
		EdgeProcessEpoch: "edge_epoch_1", Revision: 1, Server: server, PreviewID: "preview_alias_01",
		OperationID: "operation_alias_01", OwnerDeviceID: identity.HostID, OwnerSessionID: "owner_session_01",
		AccessMode: "public", LeaseGeneration: identity.Generation,
	}
	if err := registry.Attach(primary); err != nil {
		t.Fatal(err)
	}
	private := DataCarrierPreviewRoute{
		RouteID: "preview_private_01", Hostname: "private.preview.example.test", Kind: dataCarrierPreviewPrivateRouteKind,
		EdgeProcessEpoch: "edge_epoch_1", Revision: 1, Server: server, PreviewID: "preview_private_01",
		OperationID: "operation_private_01", OwnerDeviceID: identity.HostID, OwnerSessionID: "owner_session_02",
		AccessMode: "private", LeaseGeneration: identity.Generation,
	}
	if err := registry.Attach(private); err != nil {
		t.Fatal(err)
	}

	exact := DataCarrierPreviewAlias{
		DomainID: "domain_alias_exact_01", RouteID: primary.RouteID, Hostname: "demo.customer.test",
		MatchType: PreviewAliasExact, PreviewGeneration: identity.Generation, DomainGeneration: 2, CertificateGeneration: 3,
	}
	wildcard := DataCarrierPreviewAlias{
		DomainID: "domain_alias_wildcard_01", RouteID: primary.RouteID, Hostname: "*.apps.customer.test",
		MatchType: PreviewAliasOneLabelWildcard, PreviewGeneration: identity.Generation, DomainGeneration: 2, CertificateGeneration: 3,
	}
	privateAlias := DataCarrierPreviewAlias{
		DomainID: "domain_alias_private_01", RouteID: private.RouteID, Hostname: "private.customer.test",
		MatchType: PreviewAliasExact, PreviewGeneration: identity.Generation, DomainGeneration: 2, CertificateGeneration: 3,
	}
	if err := registry.ReconcilePreviewAliases([]DataCarrierPreviewAlias{exact, wildcard, privateAlias}); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{exact.Hostname, "one.apps.customer.test"} {
		route, ok := registry.Lookup(host)
		if !ok || route.Server != server || route.Identity != identity || route.AccessMode != "public" || route.Kind != dataCarrierPreviewRouteKind {
			t.Fatalf("public alias lookup(%q) = %+v, %v", host, route, ok)
		}
	}
	if _, ok := registry.Lookup("two.deep.apps.customer.test"); ok {
		t.Fatal("one-label wildcard matched a recursive hostname")
	}
	if route, ok := registry.Lookup(privateAlias.Hostname); !ok || route.Server != server || route.AccessMode != "private" || route.Kind != dataCarrierPreviewPrivateRouteKind {
		t.Fatalf("private alias lookup = %+v, %v", route, ok)
	}
	if route, ok := registry.Lookup(primary.Hostname); !ok || route.Server != server || route.AccessMode != "public" {
		t.Fatalf("managed endpoint lookup = %+v, %v", route, ok)
	}

	stale := exact
	stale.DomainGeneration--
	if err := registry.AttachAlias(stale); !errors.Is(err, ErrDataCarrierPreviewRegistryStale) {
		t.Fatalf("stale alias attach = %v", err)
	}
	if err := registry.DetachAlias(stale); !errors.Is(err, ErrDataCarrierPreviewRegistryStale) {
		t.Fatalf("stale alias detach = %v", err)
	}
	if _, ok := registry.Lookup(exact.Hostname); !ok {
		t.Fatal("stale alias operation removed the active alias")
	}

	transport, err := NewDataCarrierPreviewTransport(DataCarrierPreviewTransportConfig{Registry: registry, StreamOpenTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{exact.Hostname, "one.apps.customer.test"}
	serveDone := make(chan error, 1)
	go func() {
		for _, wantHost := range hosts {
			stream, open, acceptErr := client.AcceptStream(context.Background())
			if acceptErr != nil {
				serveDone <- acceptErr
				return
			}
			if open.RouteID != primary.RouteID || open.AccountID != identity.AccountID || open.TunnelID != identity.TunnelID || open.ConnectorID != identity.ConnectorID || open.SessionID != identity.SessionID || open.ProcessGeneration != identity.ProcessGeneration || open.Generation != identity.Generation {
				_ = stream.Close()
				serveDone <- fmt.Errorf("unexpected authenticated stream-open: %+v", open)
				return
			}
			err := datacarrier.ServeHTTPStream(context.Background(), stream, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Host != wantHost {
					return
				}
				_, _ = io.WriteString(writer, request.Host)
			}), 4096, time.Second)
			if err != nil {
				serveDone <- err
				return
			}
		}
		serveDone <- nil
	}()
	for _, host := range hosts {
		request := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		request.Host = host
		response, roundTripErr := transport.RoundTrip(request)
		if roundTripErr != nil {
			t.Fatal(roundTripErr)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != host {
			t.Fatalf("alias response host=%q status=%d body=%q read=%v close=%v", host, response.StatusCode, body, readErr, closeErr)
		}
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated alias streams did not finish")
	}

	if err := registry.ReconcilePreviewAliases(nil); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{exact.Hostname, "one.apps.customer.test", privateAlias.Hostname} {
		if _, ok := registry.Lookup(host); ok {
			t.Fatalf("complete empty snapshot retained alias %q", host)
		}
	}
	if route, ok := registry.Lookup(primary.Hostname); !ok || route.Server != server || route.AccessMode != "public" || route.Kind != dataCarrierPreviewRouteKind {
		t.Fatalf("complete empty snapshot removed managed endpoint: %+v, %v", route, ok)
	}
}

func TestDataCarrierPreviewRegistryCustomAliasesAreGenerationFenced(t *testing.T) {
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{
		BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1", MaximumRoutes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server, client := testEdgePreviewCarrierPair(t, testEdgePreviewIdentity(4, 2))
	defer server.Close()
	defer client.Close()
	primary := DataCarrierPreviewRoute{
		RouteID: "preview_01", Hostname: "managed.preview.example.test", Kind: dataCarrierPreviewRouteKind,
		EdgeProcessEpoch: "edge_epoch_1", Revision: 4, LeaseGeneration: 7, Server: server,
	}
	if err := registry.Attach(primary); err != nil {
		t.Fatal(err)
	}
	exact := DataCarrierPreviewAlias{
		DomainID: "domain_exact_01", RouteID: primary.RouteID, Hostname: "demo.customer.test", MatchType: PreviewAliasExact,
		PreviewGeneration: 7, DomainGeneration: 2, CertificateGeneration: 3,
	}
	wildcard := DataCarrierPreviewAlias{
		DomainID: "domain_wildcard_01", RouteID: primary.RouteID, Hostname: "*.apps.customer.test", MatchType: PreviewAliasOneLabelWildcard,
		PreviewGeneration: 7, DomainGeneration: 5, CertificateGeneration: 6,
	}
	if err := registry.AttachAlias(exact); err != nil {
		t.Fatal(err)
	}
	if err := registry.AttachAlias(wildcard); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"demo.customer.test", "one.apps.customer.test"} {
		got, ok := registry.Lookup(host)
		if !ok || got.RouteID != primary.RouteID || got.Hostname != host || got.Server != server {
			t.Fatalf("lookup(%q) = %+v, %v", host, got, ok)
		}
	}
	if _, ok := registry.Lookup("two.deep.apps.customer.test"); ok {
		t.Fatal("one-label wildcard matched a recursive hostname")
	}
	if err := registry.DetachAlias(DataCarrierPreviewAlias{
		DomainID: exact.DomainID, RouteID: exact.RouteID, Hostname: exact.Hostname, MatchType: exact.MatchType,
		PreviewGeneration: exact.PreviewGeneration, DomainGeneration: 1, CertificateGeneration: exact.CertificateGeneration,
	}); !errors.Is(err, ErrDataCarrierPreviewRegistryStale) {
		t.Fatalf("stale detach = %v", err)
	}
	if _, ok := registry.Lookup(exact.Hostname); !ok {
		t.Fatal("stale detach removed current alias")
	}
	if err := registry.DetachAlias(exact); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Lookup(exact.Hostname); ok {
		t.Fatal("exact alias remained after exact detach")
	}
	if aliases := registry.PreviewAliases(); len(aliases) != 1 || aliases[0] != wildcard {
		t.Fatalf("aliases = %+v", aliases)
	}
}

func TestDataCarrierPreviewRegistryRouteReplacementWithdrawsAliases(t *testing.T) {
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{
		BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1", MaximumRoutes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server, client := testEdgePreviewCarrierPair(t, testEdgePreviewIdentity(4, 2))
	defer server.Close()
	defer client.Close()
	route := DataCarrierPreviewRoute{
		RouteID: "preview_01", Hostname: "managed.preview.example.test", Kind: dataCarrierPreviewRouteKind,
		EdgeProcessEpoch: "edge_epoch_1", Revision: 4, LeaseGeneration: 7, Server: server,
	}
	if err := registry.Attach(route); err != nil {
		t.Fatal(err)
	}
	alias := DataCarrierPreviewAlias{
		DomainID: "domain_01", RouteID: route.RouteID, Hostname: "demo.customer.test", MatchType: PreviewAliasExact,
		PreviewGeneration: 7, DomainGeneration: 1, CertificateGeneration: 1,
	}
	if err := registry.AttachAlias(alias); err != nil {
		t.Fatal(err)
	}
	route.Revision++
	if err := registry.Attach(route); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Lookup(alias.Hostname); ok {
		t.Fatal("route replacement retained an unconfirmed alias")
	}
	if aliases := registry.PreviewAliases(); len(aliases) != 0 {
		t.Fatalf("aliases after replacement = %+v", aliases)
	}
	alias.PreviewGeneration = 8
	alias.DomainGeneration++
	if err := registry.AttachAlias(alias); !errors.Is(err, ErrDataCarrierPreviewRegistryStale) {
		t.Fatalf("future lease alias = %v", err)
	}
}

func TestDataCarrierPreviewRegistryReconcilesCompleteAliasSnapshot(t *testing.T) {
	registry, err := NewDataCarrierPreviewRegistry(DataCarrierPreviewRegistryConfig{
		BaseDomain: "preview.example.test", ProcessEpoch: "edge_epoch_1", MaximumRoutes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	alias := DataCarrierPreviewAlias{
		DomainID: "domain_01", RouteID: "preview_01", Hostname: "demo.customer.test", MatchType: PreviewAliasExact,
		PreviewGeneration: 7, DomainGeneration: 2, CertificateGeneration: 3,
	}
	if err := registry.ReconcilePreviewAliases([]DataCarrierPreviewAlias{alias}); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Lookup(alias.Hostname); ok {
		t.Fatal("alias became ready before its carrier")
	}
	server, client := testEdgePreviewCarrierPair(t, testEdgePreviewIdentity(4, 2))
	defer server.Close()
	defer client.Close()
	if err := registry.Attach(DataCarrierPreviewRoute{
		RouteID: alias.RouteID, Hostname: "managed.preview.example.test", Kind: dataCarrierPreviewRouteKind,
		EdgeProcessEpoch: "edge_epoch_1", Revision: 4, LeaseGeneration: alias.PreviewGeneration, Server: server,
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.Lookup(alias.Hostname); !ok || got.RouteID != alias.RouteID || got.Hostname != alias.Hostname {
		t.Fatalf("activated alias = %+v, %v", got, ok)
	}
	stale := alias
	stale.DomainGeneration--
	if err := registry.ReconcilePreviewAliases([]DataCarrierPreviewAlias{stale}); !errors.Is(err, ErrDataCarrierPreviewRegistryStale) {
		t.Fatalf("stale complete snapshot = %v", err)
	}
	if _, ok := registry.Lookup(alias.Hostname); !ok {
		t.Fatal("stale complete snapshot removed current alias")
	}
	if err := registry.ReconcilePreviewAliases([]DataCarrierPreviewAlias{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Lookup(alias.Hostname); ok {
		t.Fatal("complete empty snapshot retained alias")
	}
}
