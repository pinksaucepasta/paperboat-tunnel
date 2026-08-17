package edgefrp

import (
	"context"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const maxAdmissionMetadata = 64 << 10

type MetadataResolver struct{}

type metadataHandoff struct {
	OperationID   string          `json:"operation_id"`
	Credential    string          `json:"credential"`
	EnvironmentID string          `json:"environment_id"`
	MachineID     string          `json:"machine_id"`
	ConnectorID   string          `json:"connector_id"`
	Generation    uint64          `json:"connector_generation"`
	EdgePool      string          `json:"edge_pool"`
	EdgeNodeID    string          `json:"edge_node_id"`
	Routes        []metadataRoute `json:"routes"`
}
type metadataRoute struct {
	RouteID    string `json:"route_id"`
	Revision   uint64 `json:"route_revision"`
	Kind       string `json:"kind"`
	PublicHost string `json:"public_host"`
	ProxyName  string `json:"proxy_name"`
	Target     struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	} `json:"target"`
}

func (MetadataResolver) ResolveLogin(_ context.Context, login LoginContent) (admission.Request, error) {
	if len(login.Metas) != 1 {
		return admission.Request{}, route.ErrInvalid
	}
	raw, ok := login.Metas[AdmissionMetadataKey]
	if !ok || len(raw) == 0 || len(raw) > maxAdmissionMetadata {
		return admission.Request{}, route.ErrInvalid
	}
	var handoff metadataHandoff
	if err := strictjson.Decode([]byte(raw), &handoff, 64); err != nil {
		return admission.Request{}, route.ErrInvalid
	}
	routes := make([]admission.Route, 0, len(handoff.Routes))
	for _, item := range handoff.Routes {
		routes = append(routes, admission.Route{RouteID: item.RouteID, Revision: item.Revision, Kind: item.Kind, PublicHost: item.PublicHost, ProxyName: item.ProxyName, TargetHost: item.Target.Host, TargetPort: item.Target.Port})
	}
	return admission.Request{OperationID: handoff.OperationID, Credential: handoff.Credential, Environment: handoff.EnvironmentID, Machine: handoff.MachineID, Connector: handoff.ConnectorID, Generation: handoff.Generation, EdgePool: handoff.EdgePool, EdgeNode: handoff.EdgeNodeID, Routes: routes}, nil
}
