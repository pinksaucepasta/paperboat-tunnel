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
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

const maxControlDocument = 1 << 20

const maxCanonicalRouteAssignments = 4096

var (
	ErrControlInvalid       = errors.New("private control configuration is invalid")
	ErrControlUnavailable   = errors.New("private control is unavailable")
	ErrNodeObservationStale = errors.New("node observation is stale")
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
	signerMu   sync.RWMutex
	signer     DistributionRequestSigner
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

// SetDistributionRequestSigner installs the node-private signer used for
// certificate pull/ack requests. The bearer remains an outer transport
// credential, while this proof binds the exact body to the registered node
// process. It is intentionally optional for the legacy control exchanges.
func (c *HTTPClient) SetDistributionRequestSigner(signer DistributionRequestSigner) error {
	if c == nil || signer == nil {
		return ErrControlInvalid
	}
	c.signerMu.Lock()
	c.signer = signer
	c.signerMu.Unlock()
	return nil
}

func (c *HTTPClient) distributionRequestSigner() DistributionRequestSigner {
	if c == nil {
		return nil
	}
	c.signerMu.RLock()
	signer := c.signer
	c.signerMu.RUnlock()
	return signer
}

func (c *HTTPClient) Current(ctx context.Context, environment, machine, connector string) (admission.Current, error) {
	request := struct {
		Environment string `json:"environment_id"`
		Machine     string `json:"machine_id"`
		Connector   string `json:"connector_id"`
	}{environment, machine, connector}
	var response struct {
		Generation uint64 `json:"connector_generation"`
		EdgePool   string `json:"edge_pool"`
		EdgeNode   string `json:"edge_node_id"`
		Revoked    bool   `json:"revoked"`
	}
	if err := c.post(ctx, "/v1/edge/assignments/current", request, &response); err != nil {
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
	if err := c.post(ctx, "/v1/edge/usage-reports", wire, &result); err != nil {
		return UsageResult{}, err
	}
	return result, nil
}

func (c *HTTPClient) RegisterNode(ctx context.Context, registration NodeRegistration) error {
	if err := registration.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrControlInvalid, err)
	}
	return c.post(ctx, "/v1/nodes/register", registration, nil)
}
func (c *HTTPClient) Heartbeat(ctx context.Context, observation NodeObservation) error {
	return c.post(ctx, "/v1/nodes/heartbeat", observation, nil)
}

type routeAssignmentWire struct {
	RouteID                    string          `json:"route_id"`
	Revision                   uint64          `json:"route_revision"`
	Environment                string          `json:"environment_id"`
	AccountID                  string          `json:"account_id"`
	HostID                     string          `json:"host_id"`
	MachineIdentityPublicKey   string          `json:"machine_identity_public_key"`
	MachineIdentityThumbprint  string          `json:"machine_identity_thumbprint"`
	TunnelID                   string          `json:"tunnel_id"`
	ConnectorID                string          `json:"connector_id"`
	Generation                 uint64          `json:"connector_generation"`
	ConnectorSessionID         string          `json:"connector_session_id"`
	ConnectorProcessGeneration uint64          `json:"connector_process_generation"`
	ConfigGeneration           uint64          `json:"config_generation"`
	ConfigContentHash          string          `json:"config_content_hash"`
	AssignmentID               string          `json:"assignment_id"`
	AssignmentGeneration       uint64          `json:"assignment_generation"`
	EdgeFailureDomain          string          `json:"edge_failure_domain"`
	EdgeProcessEpoch           string          `json:"edge_process_epoch"`
	NodeID                     string          `json:"edge_node_id"`
	Kind                       string          `json:"kind"`
	PublicHost                 string          `json:"public_host"`
	MatchType                  string          `json:"match_type"`
	MatchHostname              string          `json:"match_hostname"`
	WildcardSuffix             string          `json:"wildcard_suffix"`
	PathPrefix                 string          `json:"path_prefix"`
	Priority                   int             `json:"priority"`
	Protocol                   string          `json:"protocol"`
	OriginScheme               string          `json:"origin_scheme"`
	AccessMode                 string          `json:"access_mode"`
	OriginAddress              string          `json:"origin_address"`
	PreserveHost               bool            `json:"preserve_host"`
	HostOverride               string          `json:"host_override"`
	DomainBindings             []DomainBinding `json:"domain_bindings"`
	State                      string          `json:"state"`
	DesiredState               string          `json:"desired_state"`
	ObservedState              string          `json:"observed_state"`
	Target                     struct {
		Host                       string `json:"host"`
		Port                       uint16 `json:"port"`
		Address                    string `json:"address"`
		RouteID                    string `json:"route_id"`
		ConnectorSessionID         string `json:"connector_session_id"`
		ConnectorProcessGeneration uint64 `json:"connector_process_generation"`
		ConfigGeneration           uint64 `json:"config_generation"`
	} `json:"target"`
	PreviewState  string `json:"preview_state"`
	PreviewReason string `json:"preview_reason"`
}

func (c *HTTPClient) DesiredRoutes(ctx context.Context, nodeID string) ([]RouteAssignment, error) {
	snapshot, err := c.DesiredRouteSnapshot(ctx, nodeID, "")
	if err != nil {
		return nil, err
	}
	return snapshot.Routes, nil
}

func (c *HTTPClient) DesiredRouteSnapshot(ctx context.Context, nodeID, processEpoch string) (RouteSnapshot, error) {
	if nodeID == "" {
		return RouteSnapshot{}, ErrControlInvalid
	}
	var result struct {
		Complete *bool                 `json:"complete"`
		Routes   []routeAssignmentWire `json:"routes"`
	}
	request := struct {
		NodeID       string `json:"edge_node_id"`
		ProcessEpoch string `json:"process_epoch,omitempty"`
	}{NodeID: nodeID, ProcessEpoch: processEpoch}
	if err := c.post(ctx, "/v1/edge/routes/desired-state", request, &result); err != nil {
		return RouteSnapshot{}, err
	}
	if len(result.Routes) > maxCanonicalRouteAssignments {
		return RouteSnapshot{}, ErrControlUnavailable
	}
	// A canonical request is always a complete snapshot.  Treat a missing or
	// false completion marker as an unavailable control response rather than
	// allowing a truncated route list to revoke the last-known-good registry.
	if processEpoch != "" && (result.Complete == nil || !*result.Complete) {
		return RouteSnapshot{}, ErrControlUnavailable
	}
	complete := result.Complete != nil && *result.Complete
	routes := make([]RouteAssignment, 0, len(result.Routes))
	canonical := false
	for _, wire := range result.Routes {
		isCanonical := wire.AssignmentID != "" || wire.Kind == "tunnel_http_wss" || wire.Kind == "tunnel_private_tcp" || wire.ConfigContentHash != ""
		if isCanonical {
			canonical = true
		}
		originAddress := wire.OriginAddress
		if !isCanonical && originAddress == "" {
			originAddress = wire.Target.Address
		}
		matchType := wire.MatchType
		// The durable store calls its server-owned endpoint match "managed".
		// The edge matcher uses the more explicit "managed_exact" name to
		// distinguish it from customer exact and wildcard bindings. Normalize
		// that persistence vocabulary at the control boundary.
		if isCanonical && matchType == "managed" {
			matchType = "managed_exact"
		}
		assignment := RouteAssignment{
			RouteID: wire.RouteID, Revision: wire.Revision, Environment: wire.Environment, AccountID: wire.AccountID,
			HostID: wire.HostID, MachineIdentityPublicKey: wire.MachineIdentityPublicKey, MachineIdentityThumbprint: wire.MachineIdentityThumbprint,
			TunnelID: wire.TunnelID, ConnectorID: wire.ConnectorID, Generation: wire.Generation,
			ConnectorSessionID: wire.ConnectorSessionID, ConnectorProcessGeneration: wire.ConnectorProcessGeneration,
			ConfigGeneration: wire.ConfigGeneration, ConfigContentHash: wire.ConfigContentHash,
			AssignmentID: wire.AssignmentID, AssignmentGeneration: wire.AssignmentGeneration,
			EdgeFailureDomain: wire.EdgeFailureDomain, EdgeProcessEpoch: wire.EdgeProcessEpoch,
			NodeID: wire.NodeID, Kind: wire.Kind, PublicHost: wire.PublicHost, MatchType: matchType,
			MatchHostname: wire.MatchHostname, WildcardSuffix: wire.WildcardSuffix, PathPrefix: wire.PathPrefix,
			Priority: wire.Priority, Protocol: wire.Protocol, OriginScheme: wire.OriginScheme, AccessMode: wire.AccessMode, OriginAddress: originAddress,
			PreserveHost: wire.PreserveHost, HostOverride: wire.HostOverride, DomainBindings: append([]DomainBinding(nil), wire.DomainBindings...), State: wire.State,
			DesiredState: wire.DesiredState, ObservedState: wire.ObservedState, TargetHost: wire.Target.Host,
			TargetPort: wire.Target.Port, TargetRouteID: wire.Target.RouteID,
			TargetConnectorSessionID:  wire.Target.ConnectorSessionID,
			TargetConnectorProcessGen: wire.Target.ConnectorProcessGeneration,
			TargetConfigGeneration:    wire.Target.ConfigGeneration,
			PreviewState:              wire.PreviewState, PreviewReason: wire.PreviewReason, Canonical: isCanonical,
		}
		routes = append(routes, assignment)
	}
	// A successful complete response with an explicit process epoch is the
	// canonical desired set, even when the server includes retained legacy
	// rows in the same document. The worker filters those rows into its
	// independent legacy registry. Legacy callers omit the epoch and retain
	// their old empty behavior.
	if complete && processEpoch != "" {
		canonical = true
	}
	return RouteSnapshot{Routes: routes, Complete: complete, Canonical: canonical}, nil
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
	return c.post(ctx, "/v1/edge/routes/observations", struct {
		NodeID string             `json:"edge_node_id"`
		Routes []RouteObservation `json:"routes"`
	}{NodeID: nodeID, Routes: routes}, nil)
}

func (c *HTTPClient) post(ctx context.Context, path string, input, output any) error {
	return c.postNode(ctx, path, "", input, output)
}

func (c *HTTPClient) postNode(ctx context.Context, path, nodeID string, input, output any) error {
	return c.postNodeWithMaximum(ctx, path, nodeID, input, output, maxControlDocument)
}

func (c *HTTPClient) postNodeWithMaximum(ctx context.Context, path, nodeID string, input, output any, maximum int) error {
	return c.postNodeWithMaximumAndIdentity(ctx, path, nodeID, "", input, output, maximum)
}

// postNodeWithMaximumAndIdentity carries the process epoch alongside the
// node header for internal node-scoped exchanges. The server must still
// derive the authenticated principal independently; these headers are only
// a binding check and are never an authority by themselves.
func (c *HTTPClient) postNodeWithMaximumAndIdentity(ctx context.Context, path, nodeID, processEpoch string, input, output any, maximum int) error {
	if maximum <= 0 || maximum > 16<<20 {
		return ErrControlInvalid
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > maximum {
		return ErrControlInvalid
	}
	endpoint := c.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return ErrControlInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	if nodeID != "" {
		request.Header.Set("X-Paperboat-Edge-Node-ID", nodeID)
	}
	if processEpoch != "" {
		request.Header.Set("X-Paperboat-Edge-Process-Epoch", processEpoch)
	}
	if nodeID != "" && (path == CertificateDistributionPullPath || path == CertificateDistributionAckPath || path == CertificateDistributionRequestPath) {
		signer := c.distributionRequestSigner()
		if signer == nil {
			return ErrControlInvalid
		}
		proof, err := signer.SignDistributionRequest(ctx, http.MethodPost, path, payload)
		if err != nil {
			return err
		}
		headers, err := distributionProofHeaders(proof)
		if err != nil {
			return err
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrControlUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, int64(maximum)))
		if path == "/v1/nodes/heartbeat" && response.StatusCode == http.StatusConflict {
			return ErrNodeObservationStale
		}
		return ErrControlUnavailable
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, int64(maximum)+1))
		return err
	}
	limited := io.LimitReader(response.Body, int64(maximum)+1)
	data, err := io.ReadAll(limited)
	defer clearControlBytes(data)
	if err != nil || len(data) > maximum {
		return ErrControlUnavailable
	}
	if err := strictjson.Decode(data, output, 64); err != nil {
		return ErrControlUnavailable
	}
	return nil
}

func clearControlBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
