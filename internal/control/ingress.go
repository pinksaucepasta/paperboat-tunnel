package control

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func (c *HTTPClient) IngressDecisions(ctx context.Context, nodeID, epoch string) ([]connectorprotocol.IngressDecision, error) {
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(epoch) != nil {
		return nil, ErrControlInvalid
	}
	input := struct {
		NodeID string `json:"edge_node_id"`
		Epoch  string `json:"process_epoch"`
	}{nodeID, epoch}
	var output struct {
		Complete  bool                                `json:"complete"`
		Decisions []connectorprotocol.IngressDecision `json:"decisions"`
	}
	if err := c.postNodeWithMaximumAndIdentity(ctx, "/v1/edge/ingress/desired-state", nodeID, epoch, input, &output, 16<<20); err != nil {
		return nil, err
	}
	if !output.Complete || len(output.Decisions) > 4096 {
		return nil, ErrControlUnavailable
	}
	now := time.Now().UTC()
	for _, d := range output.Decisions {
		if d.Validate(now) != nil || d.EdgeNodeID != nodeID || d.EdgeProcessEpoch != epoch {
			return nil, ErrControlUnavailable
		}
	}
	return output.Decisions, nil
}
