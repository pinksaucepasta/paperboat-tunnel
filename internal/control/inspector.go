package control

import (
	"context"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

const InspectorAccessPath = "/v1/edge/inspector/access"

var (
	ErrInspectorAccessInvalid     = errors.New("invalid inspector edge access request")
	ErrInspectorAccessUnavailable = errors.New("inspector edge access unavailable")
)

type InspectorAccessRequest struct {
	EdgeNodeID      string `json:"edge_node_id"`
	ProcessEpoch    string `json:"process_epoch"`
	CredentialToken string `json:"credential_token"`
	ResourceKind    string `json:"resource_kind"`
	ResourceID      string `json:"resource_id"`
	RouteID         string `json:"route_id"`
	Action          string `json:"action"`
}

type InspectorCarrier struct {
	AccountID            string `json:"account_id"`
	MachineID            string `json:"machine_id"`
	TunnelID             string `json:"tunnel_id"`
	ConnectorID          string `json:"connector_id"`
	SessionID            string `json:"session_id"`
	ProcessGeneration    uint64 `json:"process_generation"`
	Generation           uint64 `json:"generation"`
	RouteID              string `json:"route_id"`
	AssignmentID         string `json:"assignment_id"`
	AssignmentGeneration uint64 `json:"assignment_generation"`
	RouteGeneration      uint64 `json:"route_generation"`
	LeaseGeneration      uint64 `json:"lease_generation,omitempty"`
	AttachmentGeneration uint64 `json:"attachment_generation,omitempty"`
	OwnerDeviceID        string `json:"owner_device_id,omitempty"`
	ConfigContentHash    string `json:"config_content_hash"`
	EdgeNodeID           string `json:"edge_node_id"`
	EdgeProcessEpoch     string `json:"edge_process_epoch"`
}

type InspectorAccess struct {
	CredentialID       string           `json:"credential_id"`
	OwnerAccountID     string           `json:"owner_account_id"`
	MachineID          string           `json:"machine_id"`
	MachineGeneration  uint64           `json:"machine_generation"`
	ResourceKind       string           `json:"resource_kind"`
	ResourceID         string           `json:"resource_id"`
	RouteID            string           `json:"route_id"`
	ResourceGeneration uint64           `json:"resource_generation"`
	RouteGeneration    uint64           `json:"route_generation"`
	TargetGeneration   uint64           `json:"target_generation"`
	ExpiresAt          time.Time        `json:"expires_at"`
	EdgeURL            string           `json:"edge_url"`
	Carrier            InspectorCarrier `json:"carrier"`
}

type InspectorAccessClient struct {
	HTTP         *HTTPClient
	NodeID       string
	ProcessEpoch string
}

func (c *InspectorAccessClient) Authorize(ctx context.Context, token, kind, resource, route, action string) (InspectorAccess, error) {
	if c == nil || c.HTTP == nil || ctx == nil || connectorprotocol.ValidateIdentifier(c.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(c.ProcessEpoch) != nil || token == "" || len(token) > 512 || (kind != "preview" && kind != "tunnel") || connectorprotocol.ValidateIdentifier(resource) != nil || connectorprotocol.ValidateIdentifier(route) != nil || (action != "inspect" && action != "replay") {
		return InspectorAccess{}, ErrInspectorAccessInvalid
	}
	in := InspectorAccessRequest{EdgeNodeID: c.NodeID, ProcessEpoch: c.ProcessEpoch, CredentialToken: token, ResourceKind: kind, ResourceID: resource, RouteID: route, Action: action}
	var out InspectorAccess
	if err := c.HTTP.postNodeWithMaximumAndIdentity(ctx, InspectorAccessPath, c.NodeID, c.ProcessEpoch, in, &out, 64<<10); err != nil {
		return InspectorAccess{}, ErrInspectorAccessUnavailable
	}
	if out.CredentialID == "" || out.OwnerAccountID == "" || out.MachineID == "" || out.ResourceKind != kind || out.ResourceID != resource || out.RouteID != route || out.ResourceGeneration == 0 || out.RouteGeneration == 0 || out.TargetGeneration == 0 || !out.ExpiresAt.After(time.Now().UTC()) || out.Carrier.AccountID != out.OwnerAccountID || out.Carrier.MachineID != out.MachineID || out.Carrier.EdgeNodeID != c.NodeID || out.Carrier.EdgeProcessEpoch != c.ProcessEpoch || out.Carrier.TunnelID == "" || out.Carrier.ConnectorID == "" || out.Carrier.SessionID == "" || out.Carrier.RouteID == "" || out.Carrier.ProcessGeneration == 0 || out.Carrier.Generation == 0 || out.Carrier.AssignmentID == "" || out.Carrier.AssignmentGeneration == 0 || out.Carrier.RouteGeneration == 0 || out.Carrier.ConfigContentHash == "" {
		return InspectorAccess{}, ErrInspectorAccessInvalid
	}
	return out, nil
}
