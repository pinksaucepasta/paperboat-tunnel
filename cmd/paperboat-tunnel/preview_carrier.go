package main

import (
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	edgeruntime "github.com/pinksaucepasta/paperboat-tunnel/internal/runtime"
)

// previewCarrierState constructs the two node-scoped registries and the
// control worker. It does not bind a listener: the worker must install and
// durably acknowledge a complete server snapshot before the carrier accepts
// a host connection.
func previewCarrierState(nodeID, processEpoch string, deployment config.Deployment, source *control.HTTPClient) (*edgeruntime.PreviewCarrierWorker, *edgeruntime.PreviewCarrierHandler, *datacarrier.ExpectedAdmissionRegistry, *edgehttp.DataCarrierPreviewRegistry, error) {
	if source == nil {
		return nil, nil, nil, nil, errors.New("preview carrier control source is required")
	}
	expected, err := datacarrier.NewExpectedAdmissionRegistry(datacarrier.ExpectedAdmissionRegistryConfig{NodeID: nodeID, ProcessEpoch: processEpoch, MaximumAdmissions: 4096})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create preview carrier admission registry: %w", err)
	}
	routes, err := edgehttp.NewDataCarrierPreviewRegistry(edgehttp.DataCarrierPreviewRegistryConfig{BaseDomain: deployment.PreviewBaseDomain, ProcessEpoch: processEpoch, MaximumRoutes: 4096})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create preview carrier route registry: %w", err)
	}
	worker, err := edgeruntime.NewPreviewCarrierWorker(edgeruntime.PreviewCarrierWorkerConfig{
		Source: source, Expected: expected, Registry: routes, NodeID: nodeID,
		ProcessEpoch: processEpoch,
		Interval:     deployment.ControlInterval, Timeout: deployment.ControlTimeout,
	})
	if err != nil {
		_ = routes.Close()
		return nil, nil, nil, nil, fmt.Errorf("create preview carrier worker: %w", err)
	}
	handler, err := edgeruntime.NewPreviewCarrierHandler(edgeruntime.PreviewCarrierHandlerConfig{
		Source: source, Expected: expected, Registry: routes, NodeID: nodeID,
		ProcessEpoch: processEpoch,
		WaitTimeout:  deployment.ControlTimeout,
	})
	if err != nil {
		_ = routes.Close()
		return nil, nil, nil, nil, fmt.Errorf("create preview carrier handler: %w", err)
	}
	return worker, handler, expected, routes, nil
}

// newPreviewCarrierComponent is retained for focused preview-only tests and
// delegates to the same authenticated listener assembly used by the default
// combined preview/durable path.
type previewReadiness struct {
	Canonical interface {
		RouteState(string) (string, string, string, bool)
		Lookup(string) (edgehttp.DataCarrierPreviewRoute, bool)
	}
	Fallback interface {
		RouteState(string) (string, string, string, bool)
	}
}

func (r previewReadiness) RouteState(host string) (string, string, string, bool) {
	if r.Canonical != nil {
		if _, ok := r.Canonical.Lookup(host); ok {
			return r.Canonical.RouteState(host)
		}
	}
	if r.Fallback != nil {
		return r.Fallback.RouteState(host)
	}
	return "", "", "", false
}
