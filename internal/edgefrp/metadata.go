package edgefrp

import (
	"context"
	"fmt"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const maxAdmissionMetadata = 64 << 10

type MetadataResolver struct{}

// MetadataRejectReason classifies a login metadata envelope failure without
// retaining or exposing metadata contents. It is intentionally small and
// stable because the hook reports it in operational diagnostics.
type MetadataRejectReason string

const (
	MetadataRejectCount   MetadataRejectReason = "count"
	MetadataRejectMissing MetadataRejectReason = "missing"
	MetadataRejectSize    MetadataRejectReason = "size"
	MetadataRejectDecode  MetadataRejectReason = "decode"
)

// MetadataDiagnostic contains only safe shape information. In particular, it
// never carries a metadata key, value, credential, or decoded handoff field.
type MetadataDiagnostic struct {
	Reason           MetadataRejectReason
	MetadataCount    int
	AdmissionPresent bool
	AdmissionBytes   int
}

// MetadataError is a route-invalid error with a safe operational reason. The
// route error remains in the unwrap chain so callers retain the normal typed
// route classification while the hook can distinguish malformed envelopes.
type MetadataError struct {
	Diagnostic MetadataDiagnostic
}

func (e *MetadataError) Error() string { return "admission metadata is invalid" }
func (e *MetadataError) Unwrap() error { return route.ErrInvalid }

func (e *MetadataError) SafeReason() string {
	if e == nil {
		return "request rejected:metadata"
	}
	return fmt.Sprintf("request rejected:metadata_%s count=%d present=%t bytes=%d", e.Diagnostic.Reason, e.Diagnostic.MetadataCount, e.Diagnostic.AdmissionPresent, e.Diagnostic.AdmissionBytes)
}

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
		return admission.Request{}, metadataError(MetadataRejectCount, login, "")
	}
	raw, ok := login.Metas[AdmissionMetadataKey]
	if !ok {
		return admission.Request{}, metadataError(MetadataRejectMissing, login, "")
	}
	if len(raw) == 0 || len(raw) > maxAdmissionMetadata {
		return admission.Request{}, metadataError(MetadataRejectSize, login, raw)
	}
	var handoff metadataHandoff
	if err := strictjson.Decode([]byte(raw), &handoff, 64); err != nil {
		return admission.Request{}, metadataError(MetadataRejectDecode, login, raw)
	}
	routes := make([]admission.Route, 0, len(handoff.Routes))
	for _, item := range handoff.Routes {
		routes = append(routes, admission.Route{RouteID: item.RouteID, Revision: item.Revision, Kind: item.Kind, PublicHost: item.PublicHost, ProxyName: item.ProxyName, TargetHost: item.Target.Host, TargetPort: item.Target.Port})
	}
	return admission.Request{OperationID: handoff.OperationID, Credential: handoff.Credential, Environment: handoff.EnvironmentID, Machine: handoff.MachineID, Connector: handoff.ConnectorID, Generation: handoff.Generation, EdgePool: handoff.EdgePool, EdgeNode: handoff.EdgeNodeID, Routes: routes}, nil
}

func metadataError(reason MetadataRejectReason, login LoginContent, raw string) error {
	return &MetadataError{Diagnostic: MetadataDiagnostic{Reason: reason, MetadataCount: len(login.Metas), AdmissionPresent: hasAdmissionMetadata(login.Metas), AdmissionBytes: len(raw)}}
}

func hasAdmissionMetadata(metas map[string]string) bool {
	_, ok := metas[AdmissionMetadataKey]
	return ok
}
