package edgehttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const (
	inspectorEdgePrefix       = "/.paperboat/inspector/v1"
	inspectorGrantHeader      = "X-Paperboat-Inspector-Grant"
	inspectorEdgeRequestLimit = 64 << 10
	inspectorEdgeReplyLimit   = 2 << 20
	inspectorEdgeTimeout      = 45 * time.Second
)

type InspectorAuthority interface {
	Authorize(context.Context, string, string, string, string, string) (control.InspectorAccess, error)
}

type InspectorEdgeAccess struct {
	Authority       InspectorAuthority
	Carriers        *DataCarrierRouteRegistry
	PreviewCarriers *DataCarrierPreviewRegistry
	RequestID       func() string
}

type inspectorSelectors struct {
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	RouteID      string `json:"route_id"`
}

func inspectorOperation(method, path string) (string, bool) {
	suffix := strings.TrimPrefix(path, inspectorEdgePrefix)
	switch {
	case method == http.MethodGet && suffix == "/records":
		return "inspect", true
	case method == http.MethodGet && strings.HasPrefix(suffix, "/records/") && !strings.Contains(strings.TrimPrefix(suffix, "/records/"), "/"):
		return "inspect", true
	case method == http.MethodGet && suffix == "/audit":
		return "inspect", true
	case method == http.MethodDelete && suffix == "/records":
		return "replay", true
	case method == http.MethodPut && suffix == "/policy":
		return "replay", true
	case method == http.MethodPost && suffix == "/replay":
		return "replay", true
	default:
		return "", false
	}
}

func (a *InspectorEdgeAccess) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if a == nil || a.Authority == nil || a.Carriers == nil || a.PreviewCarriers == nil || r == nil {
		http.Error(w, "Inspector unavailable", http.StatusServiceUnavailable)
		return
	}
	action, ok := inspectorOperation(r.Method, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	grants := r.Header.Values(inspectorGrantHeader)
	if len(grants) != 1 || grants[0] == "" || len(grants[0]) > 512 || strings.TrimSpace(grants[0]) != grants[0] || strings.ContainsAny(grants[0], "\x00\r\n\t ") {
		http.Error(w, "Inspector authorization required", http.StatusUnauthorized)
		return
	}
	selectors, body, err := inspectorRequestSelectors(w, r)
	if err != nil {
		http.Error(w, "Invalid inspector request", http.StatusBadRequest)
		return
	}
	if selectors.ResourceKind != "preview" && selectors.ResourceKind != "tunnel" || connectorprotocol.ValidateIdentifier(selectors.ResourceID) != nil || connectorprotocol.ValidateIdentifier(selectors.RouteID) != nil || selectors.ResourceKind == "preview" && selectors.ResourceID != selectors.RouteID {
		http.Error(w, "Invalid inspector request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inspectorEdgeTimeout)
	defer cancel()
	access, err := a.Authority.Authorize(ctx, grants[0], selectors.ResourceKind, selectors.ResourceID, selectors.RouteID, action)
	if err != nil {
		http.Error(w, "Inspector authorization unavailable", http.StatusForbidden)
		return
	}
	requestID := fmt.Sprintf("inspector-%d", time.Now().UnixNano())
	if a.RequestID != nil {
		requestID = a.RequestID()
	}
	stream, err := a.openInspectorStream(ctx, access, requestID)
	if err != nil {
		http.Error(w, "Inspector owner is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()
	out := r.Clone(ctx)
	out.URL.Path = "/v1/inspector" + strings.TrimPrefix(r.URL.Path, inspectorEdgePrefix)
	out.URL.RawPath = ""
	out.RequestURI = ""
	out.Host = "paperboatd.local"
	out.Header = make(http.Header)
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set("Accept", "application/json")
	out.Header.Set(inspectorGrantHeader, grants[0])
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	if len(body) == 0 {
		out.Body = http.NoBody
	}
	if err := out.Write(stream); err != nil {
		http.Error(w, "Inspector owner is unavailable", http.StatusServiceUnavailable)
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(stream, inspectorEdgeReplyLimit+64<<10)), out)
	if err != nil {
		http.Error(w, "Inspector owner is unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, inspectorEdgeReplyLimit+1))
	if err != nil || len(payload) > inspectorEdgeReplyLimit {
		http.Error(w, "Inspector response is too large", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(payload)
}

func inspectorRequestSelectors(w http.ResponseWriter, r *http.Request) (inspectorSelectors, []byte, error) {
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		query := r.URL.Query()
		if len(query["kind"]) != 1 || len(query["resource"]) != 1 || len(query["route"]) != 1 {
			return inspectorSelectors{}, nil, errors.New("invalid inspector selectors")
		}
		return inspectorSelectors{ResourceKind: query["kind"][0], ResourceID: query["resource"][0], RouteID: query["route"][0]}, nil, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, inspectorEdgeRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || len(body) > inspectorEdgeRequestLimit {
		return inspectorSelectors{}, nil, errors.New("invalid inspector body")
	}
	var selectors inspectorSelectors
	if err := strictjson.Validate(body, 16); err != nil {
		return inspectorSelectors{}, nil, err
	}
	if err := json.Unmarshal(body, &selectors); err != nil {
		return inspectorSelectors{}, nil, err
	}
	return selectors, body, nil
}

func (a *InspectorEdgeAccess) openInspectorStream(ctx context.Context, access control.InspectorAccess, requestID string) (io.ReadWriteCloser, error) {
	if access.ResourceKind == "preview" {
		return a.PreviewCarriers.openInspectorStream(ctx, access, requestID)
	}
	return a.Carriers.openInspectorStream(ctx, access.Carrier, requestID)
}

func (r *DataCarrierRouteRegistry) openInspectorStream(ctx context.Context, carrier control.InspectorCarrier, requestID string) (io.ReadWriteCloser, error) {
	if r == nil || ctx == nil || connectorprotocol.ValidateIdentifier(requestID) != nil {
		return nil, ErrDataCarrierRouteInvalid
	}
	identity := datacarrier.Identity{AccountID: carrier.AccountID, HostID: carrier.MachineID, TunnelID: carrier.TunnelID, ConnectorID: carrier.ConnectorID, SessionID: carrier.SessionID, ProcessGeneration: carrier.ProcessGeneration, Generation: carrier.Generation}
	r.mu.RLock()
	entry := r.byKey[carrierRouteIdentityKey(identity)]
	if entry == nil || entry.server == nil || entry.identity != identity || !entry.state.Ready || entry.state.Generation != carrier.Generation || uint32(entry.server.ActiveStreams()) >= entry.state.Capacity {
		r.mu.RUnlock()
		return nil, ErrDataCarrierRouteUnavailable
	}
	binding, bound := replicaRouteBinding(entry.state.RouteBindings, carrier.RouteID)
	healthy := sortedContains(entry.state.HealthyRoutes, carrier.RouteID)
	r.mu.RUnlock()
	if !bound || !healthy || binding.AssignmentID != carrier.AssignmentID || binding.AssignmentGeneration != carrier.AssignmentGeneration || binding.RouteGeneration != carrier.RouteGeneration || binding.ConfigContentHash != carrier.ConfigContentHash {
		return nil, ErrDataCarrierRouteUnavailable
	}
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: carrier.RouteID, RequestID: requestID, Kind: connectorprotocol.InspectorHTTP}
	stream, err := entry.server.OpenStreamWithLifetime(ctx, ctx, open)
	if err != nil {
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	return stream, nil
}

func (r *DataCarrierPreviewRegistry) openInspectorStream(ctx context.Context, access control.InspectorAccess, requestID string) (io.ReadWriteCloser, error) {
	carrier := access.Carrier
	if r == nil || ctx == nil || connectorprotocol.ValidateIdentifier(requestID) != nil || carrier.LeaseGeneration == 0 || carrier.AttachmentGeneration == 0 || carrier.AssignmentGeneration != carrier.AttachmentGeneration || carrier.OwnerDeviceID == "" {
		return nil, ErrDataCarrierPreviewRegistryInvalid
	}
	route, ok := r.Route(carrier.RouteID)
	if !ok || route.Server == nil || route.PreviewID != access.ResourceID || route.OperationID != carrier.AssignmentID || route.OwnerDeviceID != carrier.OwnerDeviceID || route.OwnerDeviceID != access.MachineID || route.LeaseGeneration != carrier.LeaseGeneration || route.AttachmentGeneration != carrier.AttachmentGeneration || route.Revision != carrier.RouteGeneration || route.ConfigContentHash != carrier.ConfigContentHash || route.EdgeNodeID != carrier.EdgeNodeID || route.EdgeProcessEpoch != carrier.EdgeProcessEpoch || !route.ExpiresAt.After(time.Now().UTC()) {
		return nil, ErrDataCarrierPreviewRegistryStale
	}
	identity := route.Server.Identity()
	if identity.AccountID != carrier.AccountID || identity.HostID != carrier.MachineID || identity.TunnelID != carrier.TunnelID || identity.ConnectorID != carrier.ConnectorID || identity.SessionID != carrier.SessionID || identity.ProcessGeneration != carrier.ProcessGeneration || identity.Generation != carrier.Generation {
		return nil, ErrDataCarrierPreviewRegistryStale
	}
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: carrier.RouteID, RequestID: requestID, Kind: connectorprotocol.InspectorHTTP}
	stream, err := route.Server.OpenStreamWithLifetime(ctx, ctx, open)
	if err != nil {
		return nil, errors.Join(ErrDataCarrierRouteTransport, err)
	}
	return stream, nil
}
