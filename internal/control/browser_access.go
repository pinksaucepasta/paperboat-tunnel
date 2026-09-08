package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

var (
	ErrBrowserUnauthenticated = errors.New("browser authentication required")
	ErrBrowserDenied          = errors.New("browser resource unavailable")
	ErrLazyHostOffline        = errors.New("lazy preview host offline")
	ErrLazyOriginUnavailable  = errors.New("lazy preview origin unavailable")
	ErrLazyActivationTimeout  = errors.New("lazy preview activation timed out")
	ErrLazyGenerationConflict = errors.New("lazy preview generation changed")
	ErrLazyForwardingFailed   = errors.New("lazy preview forwarding failed")
	ErrLazyCooldown           = errors.New("lazy preview activation cooling down")
	ErrLazyCapacity           = errors.New("lazy preview activation capacity exceeded")
)

type BrowserBegin struct {
	TransactionID string    `json:"transaction_id"`
	State         string    `json:"state"`
	ExpiresAt     time.Time `json:"expires_at"`
}
type BrowserSession struct {
	Token      string    `json:"token"`
	ReturnPath string    `json:"return_path"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type BrowserAuthorizeRequest struct {
	CredentialKind string `json:"credential_kind,omitempty"`
	Token          string `json:"token"`
	Host           string `json:"host"`
	ResourceKind   string `json:"resource_kind"`
	ResourceID     string `json:"resource_id"`
	RouteID        string `json:"route_id"`
}

// BrowserAccessClient uses the existing authenticated edge control connection.
// Browser credentials are carried only in bounded request bodies, never URLs.
type BrowserAccessClient struct {
	HTTP         *HTTPClient
	NodeID       string
	ProcessEpoch string
}

func (c *BrowserAccessClient) Begin(ctx context.Context, host, path string) (BrowserBegin, error) {
	var out BrowserBegin
	err := c.call(ctx, "begin", struct {
		Host       string `json:"host"`
		ReturnPath string `json:"return_path"`
	}{host, path}, &out)
	return out, err
}
func (c *BrowserAccessClient) Redeem(ctx context.Context, transaction, state, handoff, host string) (BrowserSession, error) {
	var out BrowserSession
	err := c.call(ctx, "redeem", struct {
		TransactionID string `json:"transaction_id"`
		State         string `json:"state"`
		Handoff       string `json:"handoff"`
		Host          string `json:"host"`
	}{transaction, state, handoff, host}, &out)
	return out, err
}
func (c *BrowserAccessClient) Authorize(ctx context.Context, in BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	var out connectorprotocol.IngressDecision
	err := c.call(ctx, "authorize", in, &out)
	return out, err
}

// Activate asks the browser authority to instantiate a dormant restricted
// preview. The returned decision is evidence of server authorization; callers
// still acquire the resulting route and authorize its concrete binding.
func (c *BrowserAccessClient) Activate(ctx context.Context, in BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	var out connectorprotocol.IngressDecision
	err := c.call(ctx, "activate", in, &out)
	return out, err
}

func (c *BrowserAccessClient) call(ctx context.Context, action string, input, output any) error {
	if c == nil || c.HTTP == nil || connectorprotocol.ValidateIdentifier(c.NodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(c.ProcessEpoch) != nil {
		return ErrControlInvalid
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > 16<<10 {
		return ErrControlInvalid
	}
	endpoint := c.HTTP.base.ResolveReference(&url.URL{Path: "/v1/edge/browser-access/" + action})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ErrControlInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.HTTP.credential)
	request.Header.Set("X-Paperboat-Edge-Node-ID", c.NodeID)
	request.Header.Set("X-Paperboat-Edge-Process-Epoch", c.ProcessEpoch)
	request.Header.Set("Content-Type", "application/json")
	client := c.HTTP.client
	if action == "activate" {
		bounded := *client
		bounded.Timeout = 10 * time.Second
		client = &bounded
	}
	response, err := client.Do(request)
	if err != nil {
		if action == "activate" && (errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded) {
			return ErrLazyActivationTimeout
		}
		return ErrControlUnavailable
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return ErrBrowserUnauthenticated
	case http.StatusNotFound, http.StatusForbidden:
		return ErrBrowserDenied
	case http.StatusOK:
	default:
		if action == "activate" {
			if classified := classifyLazyActivationError(response.Body); classified != nil {
				return classified
			}
		}
		return ErrControlUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(data) > 32<<10 {
		return ErrControlUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrControlUnavailable
	}
	return nil
}

func classifyLazyActivationError(body io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(body, (4<<10)+1))
	if err != nil || len(data) > 4<<10 {
		return nil
	}
	var wire struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &wire) != nil {
		return nil
	}
	switch wire.Error.Code {
	case "host_offline":
		return ErrLazyHostOffline
	case "origin_unavailable":
		return ErrLazyOriginUnavailable
	case "activation_timeout":
		return ErrLazyActivationTimeout
	case "forwarding_failed":
		return ErrLazyForwardingFailed
	case "activation_cooldown":
		return ErrLazyCooldown
	case "generation_conflict", "owner_replaced":
		return ErrLazyGenerationConflict
	case "activation_capacity", "activation_limit", "capacity", "policy_limit":
		return ErrLazyCapacity
	default:
		return nil
	}
}
