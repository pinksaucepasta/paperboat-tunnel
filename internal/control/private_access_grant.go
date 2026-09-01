package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const PrivateAccessGrantAuthorizePath = "/v1/edge/private-access/authorize"

var (
	ErrPrivateAccessGrantInvalid      = errors.New("invalid private access grant authorization")
	ErrPrivateAccessGrantUnauthorized = errors.New("private access machine authentication required")
	ErrPrivateAccessGrantForbidden    = errors.New("private access route forbidden")
	ErrPrivateAccessGrantUnavailable  = errors.New("private access authorization unavailable")
)

type PrivateAccessGrantDecision struct {
	Schema               string    `json:"schema"`
	Kind                 string    `json:"kind"`
	DecisionID           string    `json:"decision_id"`
	Allowed              bool      `json:"allowed"`
	Reason               string    `json:"reason"`
	ExpiresAt            time.Time `json:"expires_at"`
	RequestID            string    `json:"request_id"`
	CorrelationID        string    `json:"correlation_id"`
	ResourceKind         string    `json:"resource_kind,omitempty"`
	ResourceID           string    `json:"resource_id,omitempty"`
	RouteID              string    `json:"route_id,omitempty"`
	OperationID          string    `json:"operation_id,omitempty"`
	ConnectorID          string    `json:"connector_id,omitempty"`
	CarrierSessionID     string    `json:"carrier_session_id,omitempty"`
	RouteGeneration      uint64    `json:"route_generation,omitempty"`
	SessionGeneration    uint64    `json:"session_generation,omitempty"`
	ProcessGeneration    uint64    `json:"process_generation,omitempty"`
	ConfigGeneration     uint64    `json:"config_generation,omitempty"`
	AssignmentGeneration uint64    `json:"assignment_generation,omitempty"`
	Protocol             string    `json:"protocol,omitempty"`
}

type PrivateAccessGrantAuthorizer interface {
	AuthorizePrivateAccessGrant(context.Context, string, connectorprotocol.PrivateAccessRequest) (PrivateAccessGrantDecision, error)
}

type PrivateAccessGrantClient struct {
	http         *HTTPClient
	nodeID       string
	processEpoch string
}

func NewPrivateAccessGrantClient(httpClient *HTTPClient, nodeID, processEpoch string) (*PrivateAccessGrantClient, error) {
	if httpClient == nil || connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return nil, ErrPrivateAccessGrantInvalid
	}
	return &PrivateAccessGrantClient{http: httpClient, nodeID: nodeID, processEpoch: processEpoch}, nil
}

func (c *PrivateAccessGrantClient) AuthorizePrivateAccessGrant(ctx context.Context, grant string, input connectorprotocol.PrivateAccessRequest) (PrivateAccessGrantDecision, error) {
	if c == nil || c.http == nil || ctx == nil || len(grant) == 0 || len(grant) > 16<<10 || input.Validate(time.Now().UTC()) != nil {
		return PrivateAccessGrantDecision{}, ErrPrivateAccessGrantInvalid
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) == 0 || len(payload) > 64<<10 {
		return PrivateAccessGrantDecision{}, ErrPrivateAccessGrantInvalid
	}
	endpoint := c.http.base.ResolveReference(&url.URL{Path: PrivateAccessGrantAuthorizePath})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return PrivateAccessGrantDecision{}, ErrPrivateAccessGrantInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.http.credential)
	request.Header.Set("X-Paperboat-Edge-Node-ID", c.nodeID)
	request.Header.Set("X-Paperboat-Edge-Process-Epoch", c.processEpoch)
	request.Header.Set("X-Paperboat-Private-Access-Grant", grant)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.client.Do(request)
	if err != nil {
		return PrivateAccessGrantDecision{}, fmt.Errorf("%w: %v", ErrPrivateAccessGrantUnavailable, err)
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if readErr != nil || len(data) == 0 || len(data) > 64<<10 {
		return PrivateAccessGrantDecision{}, ErrPrivateAccessGrantInvalid
	}
	var decision PrivateAccessGrantDecision
	if err := strictjson.Decode(data, &decision, 64); err != nil {
		return PrivateAccessGrantDecision{}, ErrPrivateAccessGrantInvalid
	}
	switch response.StatusCode {
	case http.StatusOK:
		if err := validatePrivateAccessGrantDecision(decision, input, time.Now().UTC()); err != nil {
			return PrivateAccessGrantDecision{}, err
		}
		return decision, nil
	case http.StatusUnauthorized:
		return decision, ErrPrivateAccessGrantUnauthorized
	case http.StatusForbidden:
		return decision, ErrPrivateAccessGrantForbidden
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		return decision, ErrPrivateAccessGrantUnavailable
	default:
		if response.StatusCode >= 500 {
			return decision, ErrPrivateAccessGrantUnavailable
		}
		return decision, ErrPrivateAccessGrantInvalid
	}
}

func validatePrivateAccessGrantDecision(decision PrivateAccessGrantDecision, request connectorprotocol.PrivateAccessRequest, now time.Time) error {
	if decision.Schema != connectorprotocol.PrivateAccessSchema || decision.Kind != "private_access_authorization" || !decision.Allowed || decision.Reason != "allowed" || decision.DecisionID == "" || decision.ExpiresAt.IsZero() || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(request.ExpiresAt) || decision.RequestID != request.RequestID || decision.CorrelationID != request.CorrelationID || decision.ResourceKind != request.ResourceKind || decision.ResourceID != request.ResourceID || decision.RouteID != request.RouteID || decision.OperationID != request.OperationID || decision.ConnectorID != request.ConnectorID || decision.CarrierSessionID != request.CarrierSessionID || decision.RouteGeneration != request.RouteGeneration || decision.SessionGeneration != request.SessionGeneration || decision.ProcessGeneration != request.ProcessGeneration || decision.ConfigGeneration != request.ConfigGeneration || decision.AssignmentGeneration != request.AssignmentGeneration || decision.Protocol != request.Protocol {
		return ErrPrivateAccessGrantInvalid
	}
	return nil
}

var _ PrivateAccessGrantAuthorizer = (*PrivateAccessGrantClient)(nil)
