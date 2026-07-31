package control

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

type CredentialVerifier interface {
	Verify(context.Context, string) (admission.Claims, error)
}

type AssignmentSource interface {
	Current(context.Context, string, string, string) (admission.Current, error)
}

type UsageReport struct {
	OperationID string       `json:"operation_id"`
	Key         usage.Key    `json:"-"`
	Bytes       uint64       `json:"bytes"`
	Interval    [2]time.Time `json:"-"`
	Payload     []byte       `json:"-"`
}

type UsageSink interface {
	ReportUsage(context.Context, UsageReport) (UsageResult, error)
}

type UsageResult struct {
	Delta uint64 `json:"delta"`
}

type RouteAssignment struct {
	RouteID       string `json:"route_id"`
	Revision      uint64 `json:"route_revision"`
	Environment   string `json:"environment_id"`
	ConnectorID   string `json:"connector_id"`
	Generation    uint64 `json:"connector_generation"`
	NodeID        string `json:"edge_node_id"`
	Kind          string `json:"kind"`
	PublicHost    string `json:"public_host"`
	TargetHost    string `json:"target_host"`
	TargetPort    uint16 `json:"target_port"`
	PreviewState  string `json:"preview_state,omitempty"`
	PreviewReason string `json:"preview_reason,omitempty"`
}

type RouteSource interface {
	DesiredRoutes(context.Context, string) ([]RouteAssignment, error)
}

type RouteObservation struct {
	RouteID             string `json:"route_id"`
	RouteRevision       uint64 `json:"route_revision"`
	EdgeNodeID          string `json:"edge_node_id"`
	ConnectorGeneration uint64 `json:"connector_generation"`
}

type RouteObserver interface {
	ObserveRoutes(context.Context, string, []RouteObservation) error
}

type RevocationSource interface {
	Revocations(context.Context) ([]byte, error)
}

type NodeRegistration struct {
	NodeID       string            `json:"edge_node_id"`
	EdgePool     string            `json:"edge_pool"`
	Artifact     string            `json:"artifact"`
	Protocol     string            `json:"protocol"`
	ProcessEpoch string            `json:"process_epoch"`
	Capacity     uint32            `json:"capacity"`
	Endpoint     ConnectorEndpoint `json:"connector_endpoint"`
}

type ConnectorEndpoint struct {
	Host     string `json:"host"`
	TCPPort  uint16 `json:"tcp_port"`
	QUICPort uint16 `json:"quic_port"`
}

type NodeObservation struct {
	NodeID        string    `json:"edge_node_id"`
	ProcessEpoch  string    `json:"process_epoch"`
	Ready         bool      `json:"ready"`
	Draining      bool      `json:"draining"`
	ActiveStreams uint32    `json:"active_streams"`
	At            time.Time `json:"at"`
}

type NodeSink interface {
	RegisterNode(context.Context, NodeRegistration) error
	Heartbeat(context.Context, NodeObservation) error
}
