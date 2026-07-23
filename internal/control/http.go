package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

const maxControlDocument = 1 << 20

var (
	ErrControlInvalid     = errors.New("private control configuration is invalid")
	ErrControlUnavailable = errors.New("private control is unavailable")
)

type HTTPConfig struct {
	BaseURL    string
	Credential string
	Timeout    time.Duration
	TLS        *tls.Config
	Client     *http.Client
}

type HTTPClient struct {
	base       *url.URL
	credential string
	client     *http.Client
}

func NewHTTPClient(config HTTPConfig) (*HTTPClient, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || len(config.Credential) < 32 || config.Timeout <= 0 {
		return nil, ErrControlInvalid
	}
	client := config.Client
	if client == nil {
		tlsConfig := config.TLS
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		} else {
			tlsConfig = tlsConfig.Clone()
			if tlsConfig.MinVersion < tls.VersionTLS13 {
				tlsConfig.MinVersion = tls.VersionTLS13
			}
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	} else {
		cloned := *client
		client = &cloned
	}
	client.Timeout = config.Timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrControlUnavailable }
	return &HTTPClient{base: base, credential: config.Credential, client: client}, nil
}

func (c *HTTPClient) Current(ctx context.Context, environment, helper string) (admission.Current, error) {
	request := struct {
		Environment string `json:"environment_id"`
		Helper      string `json:"helper_id"`
	}{environment, helper}
	var response struct {
		Generation uint64 `json:"connector_generation"`
		EdgePool   string `json:"edge_pool"`
		EdgeNode   string `json:"edge_node_id"`
		Revoked    bool   `json:"revoked"`
	}
	if err := c.post(ctx, "/v1/assignment/current", request, &response); err != nil {
		return admission.Current{}, err
	}
	if response.Generation == 0 || response.EdgePool == "" || response.EdgeNode == "" {
		return admission.Current{}, ErrControlUnavailable
	}
	return admission.Current{Generation: response.Generation, EdgePool: response.EdgePool, EdgeNode: response.EdgeNode, Revoked: response.Revoked}, nil
}

func (c *HTTPClient) ReportUsage(ctx context.Context, report UsageReport) (UsageResult, error) {
	var result UsageResult
	wire := struct {
		OperationID string          `json:"operation_id"`
		Node        string          `json:"edge_node_id"`
		Epoch       string          `json:"counter_epoch"`
		Environment string          `json:"environment_id"`
		Route       string          `json:"route_id"`
		Revision    uint64          `json:"route_revision"`
		Direction   string          `json:"direction"`
		Bytes       uint64          `json:"bytes"`
		Start       time.Time       `json:"interval_start"`
		End         time.Time       `json:"interval_end"`
		Payload     json.RawMessage `json:"signed_payload,omitempty"`
	}{report.OperationID, report.Key.Node, report.Key.Epoch, report.Key.Environment, report.Key.Route, report.Key.Revision, report.Key.Direction, report.Bytes, report.Interval[0], report.Interval[1], json.RawMessage(report.Payload)}
	if err := c.post(ctx, "/v1/usage/report", wire, &result); err != nil {
		return UsageResult{}, err
	}
	return result, nil
}

func (c *HTTPClient) RegisterNode(ctx context.Context, registration NodeRegistration) error {
	return c.post(ctx, "/v1/nodes/register", registration, nil)
}
func (c *HTTPClient) Heartbeat(ctx context.Context, observation NodeObservation) error {
	return c.post(ctx, "/v1/nodes/heartbeat", observation, nil)
}

func (c *HTTPClient) DesiredRoutes(ctx context.Context, nodeID string) ([]RouteAssignment, error) {
	var result struct {
		Routes []struct {
			RouteID     string `json:"route_id"`
			Revision    uint64 `json:"route_revision"`
			Environment string `json:"environment_id"`
			Generation  uint64 `json:"connector_generation"`
			NodeID      string `json:"edge_node_id"`
			Kind        string `json:"kind"`
			PublicHost  string `json:"public_host"`
			Target      struct {
				Host string `json:"host"`
				Port uint16 `json:"port"`
			} `json:"target"`
			PreviewState  string `json:"preview_state"`
			PreviewReason string `json:"preview_reason"`
		} `json:"routes"`
	}
	if err := c.post(ctx, "/v1/routes/desired", struct {
		NodeID string `json:"edge_node_id"`
	}{nodeID}, &result); err != nil {
		return nil, err
	}
	routes := make([]RouteAssignment, 0, len(result.Routes))
	for _, route := range result.Routes {
		routes = append(routes, RouteAssignment{RouteID: route.RouteID, Revision: route.Revision, Environment: route.Environment, Generation: route.Generation, NodeID: route.NodeID, Kind: route.Kind, PublicHost: route.PublicHost, TargetHost: route.Target.Host, TargetPort: route.Target.Port, PreviewState: route.PreviewState, PreviewReason: route.PreviewReason})
	}
	return routes, nil
}

func (c *HTTPClient) Revocations(ctx context.Context) ([]byte, error) {
	endpoint := c.base.ResolveReference(&url.URL{Path: "/v1/trust/revocations"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, ErrControlInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrControlUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxControlDocument))
		return nil, ErrControlUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxControlDocument+1))
	if err != nil || len(data) == 0 || len(data) > maxControlDocument {
		return nil, ErrControlUnavailable
	}
	return data, nil
}

func (c *HTTPClient) ObserveRoutes(ctx context.Context, nodeID string, routes []RouteObservation) error {
	if len(routes) > 1000 {
		return ErrControlInvalid
	}
	return c.post(ctx, "/v1/routes/observed", struct {
		NodeID string             `json:"edge_node_id"`
		Routes []RouteObservation `json:"routes"`
	}{NodeID: nodeID, Routes: routes}, nil)
}

func (c *HTTPClient) post(ctx context.Context, path string, input, output any) error {
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > maxControlDocument {
		return ErrControlInvalid
	}
	endpoint := c.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return ErrControlInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrControlUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxControlDocument))
		return ErrControlUnavailable
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, maxControlDocument+1))
		return err
	}
	limited := io.LimitReader(response.Body, maxControlDocument+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) > maxControlDocument {
		return ErrControlUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrControlUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrControlUnavailable
	}
	return nil
}
