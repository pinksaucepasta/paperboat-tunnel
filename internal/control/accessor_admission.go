package control

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

const PrivateAccessCarrierAdmissionsPath = "/v1/edge/private-access/carrier-admissions"

var (
	accessorConfigHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	accessorNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

type PrivateAccessCarrierAdmission struct {
	Schema                               string    `json:"schema"`
	Kind                                 string    `json:"kind"`
	AccountID                            string    `json:"account_id"`
	DeviceID                             string    `json:"device_id"`
	InstallationGeneration               uint64    `json:"installation_generation"`
	AccessorPublicKey                    string    `json:"accessor_public_key"`
	AccessorThumbprint                   string    `json:"accessor_thumbprint"`
	ResourceKind                         string    `json:"resource_kind"`
	ResourceID                           string    `json:"resource_id"`
	TunnelName                           string    `json:"tunnel_name,omitempty"`
	RouteName                            string    `json:"route_name,omitempty"`
	OperationID                          string    `json:"operation_id,omitempty"`
	ConnectorID                          string    `json:"connector_id,omitempty"`
	CarrierSessionID                     string    `json:"carrier_session_id"`
	RouteID                              string    `json:"route_id"`
	RouteGeneration                      uint64    `json:"route_generation"`
	SessionGeneration                    uint64    `json:"session_generation"`
	ProcessGeneration                    uint64    `json:"process_generation"`
	ConfigGeneration                     uint64    `json:"config_generation"`
	AssignmentGeneration                 uint64    `json:"assignment_generation"`
	AssignmentID                         string    `json:"assignment_id"`
	ConfigContentHash                    string    `json:"config_content_hash"`
	EdgeNodeID                           string    `json:"edge_node_id"`
	EdgeProcessEpoch                     string    `json:"edge_process_epoch"`
	Protocol                             string    `json:"protocol"`
	Hostname                             string    `json:"hostname"`
	MatchType                            string    `json:"match_type"`
	WildcardSuffix                       string    `json:"wildcard_suffix,omitempty"`
	EdgeEndpoints                        []string  `json:"edge_endpoints"`
	ExpiresAt                            time.Time `json:"expires_at"`
	TunnelID                             string    `json:"tunnel_id"`
	CarrierConnectorID                   string    `json:"carrier_connector_id"`
	EdgeCarrierServerSPKISHA256          string    `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string    `json:"edge_carrier_server_certificate_chain_pem"`
}

func (a PrivateAccessCarrierAdmission) Durable() datacarrier.DurableAdmission {
	return datacarrier.DurableAdmission{Identity: datacarrier.Identity{AccountID: a.AccountID, HostID: a.DeviceID, TunnelID: a.TunnelID, ConnectorID: a.CarrierConnectorID, SessionID: a.CarrierSessionID, ProcessGeneration: a.ProcessGeneration, Generation: a.ConfigGeneration}, EdgeNodeID: a.EdgeNodeID, EdgeProcessEpoch: a.EdgeProcessEpoch, AssignmentID: a.AssignmentID, RouteID: a.RouteID, AssignmentGeneration: a.AssignmentGeneration, RouteGeneration: a.RouteGeneration, ConfigContentHash: a.ConfigContentHash, MachineIdentityPublicKey: a.AccessorPublicKey, MachineIdentityThumbprint: a.AccessorThumbprint, State: "active", ExpiresAt: a.ExpiresAt}
}

func (a PrivateAccessCarrierAdmission) Validate(nodeID, processEpoch string, now time.Time) error {
	if a.Schema != "paperboat.preview-tunnel/v1" || a.Kind != "private_access_carrier_admission" || a.InstallationGeneration == 0 || len(a.EdgeEndpoints) != 2 || !accessorConfigHashPattern.MatchString(a.ConfigContentHash) {
		return ErrControlUnavailable
	}
	if err := a.Durable().Validate(nodeID, processEpoch, now); err != nil {
		return ErrControlUnavailable
	}
	for index, scheme := range []string{"h2", "h3"} {
		endpoint, err := url.Parse(a.EdgeEndpoints[index])
		port, portErr := strconv.ParseUint(endpoint.Port(), 10, 16)
		if err != nil || endpoint.Scheme != scheme || endpoint.Hostname() == "" || portErr != nil || port == 0 || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return ErrControlUnavailable
		}
	}
	carrierEndpoint, _ := url.Parse(a.EdgeEndpoints[0])
	if ValidateCarrierServerCertificateChain(a.EdgeCarrierServerCertificateChainPEM, a.EdgeCarrierServerSPKISHA256, carrierEndpoint.Hostname(), now.UTC()) != nil {
		return ErrControlUnavailable
	}
	if !validAccessorMatch(a.Protocol, a.Hostname, a.MatchType, a.WildcardSuffix) {
		return ErrControlUnavailable
	}
	if a.ResourceKind == "preview" {
		if a.TunnelName != "" || a.RouteName != "" || connectorprotocol.ValidateIdentifier(a.OperationID) != nil || a.ConnectorID != "" || a.Protocol != "http" {
			return ErrControlUnavailable
		}
	} else if a.ResourceKind != "tunnel" || !validAccessorName(a.TunnelName, 63) || !validAccessorName(a.RouteName, 80) || connectorprotocol.ValidateIdentifier(a.ConnectorID) != nil || a.OperationID != "" {
		return ErrControlUnavailable
	}
	return nil
}

func validAccessorName(value string, maximum int) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= maximum && accessorNamePattern.MatchString(value)
}

func validAccessorMatch(protocol, hostname, matchType, suffix string) bool {
	if protocol == "private_tcp" {
		return hostname == "" && matchType == "catch_all" && suffix == ""
	}
	if protocol != "http" || hostname == "" || hostname != strings.ToLower(hostname) {
		return false
	}
	switch matchType {
	case "exact", "managed_exact", "catch_all":
		return suffix == "" && !strings.Contains(hostname, "*")
	case "one_label_wildcard":
		return suffix != "" && !strings.Contains(suffix, "*") && !strings.HasPrefix(suffix, ".") && !strings.HasSuffix(suffix, ".") && hostname == "*."+suffix
	default:
		return false
	}
}

func (c *HTTPClient) PrivateAccessCarrierAdmissions(ctx context.Context, nodeID, processEpoch string) ([]PrivateAccessCarrierAdmission, error) {
	request := struct {
		EdgeNodeID       string `json:"edge_node_id"`
		EdgeProcessEpoch string `json:"edge_process_epoch"`
	}{nodeID, processEpoch}
	var out struct {
		Schema     string                          `json:"schema"`
		Kind       string                          `json:"kind"`
		Complete   bool                            `json:"complete"`
		Admissions []PrivateAccessCarrierAdmission `json:"admissions"`
	}
	if err := c.postNodeWithMaximumAndIdentity(ctx, PrivateAccessCarrierAdmissionsPath, nodeID, processEpoch, request, &out, maxControlDocument); err != nil {
		return nil, err
	}
	if out.Schema != "paperboat.preview-tunnel/v1" || out.Kind != "private_access_carrier_snapshot" || !out.Complete || out.Admissions == nil {
		return nil, ErrControlUnavailable
	}
	seen := make(map[string]struct{}, len(out.Admissions))
	for _, admission := range out.Admissions {
		if admission.Validate(nodeID, processEpoch, time.Now().UTC()) != nil {
			return nil, ErrControlUnavailable
		}
		key := admission.DeviceID + "\x00" + admission.ResourceID + "\x00" + admission.RouteID + "\x00" + admission.AssignmentID
		if _, ok := seen[key]; ok {
			return nil, ErrControlUnavailable
		}
		seen[key] = struct{}{}
	}
	return out.Admissions, nil
}
