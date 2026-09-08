package control

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

// These paths are the edge-node control boundary for canonical preview
// carrier attachments. Admissions is a complete desired-set snapshot, not a
// bounded outbox page. The edge only trusts a successful authenticated pull
// carrying complete:true; failed or incomplete pulls preserve its
// last-known-good set. The server endpoint accepts a POST body containing
// edge_node_id and the ACK/observation endpoints accept bounded batches.
const (
	PreviewCarrierAdmissionsPath    = "/v1/edge/previews/carrier-admissions"
	PreviewCarrierObservationsPath  = "/v1/edge/previews/carrier-observations"
	PreviewCarrierDetachmentsPath   = "/v1/edge/previews/carrier-detachments"
	PreviewCarrierAdmissionAcksPath = "/v1/edge/previews/carrier-admissions/ack"
	previewCarrierRouteKind         = "preview_public_https_wss"
	previewCarrierSchema            = "paperboat.preview-tunnel/v1"
	previewCarrierKind              = "preview_carrier_attachment"
	maxPreviewCarrierAdmissions     = 4096
	maxPreviewCarrierAliases        = 64
	// A complete snapshot may contain thousands of metadata-only admissions.
	// Keep the regular control document limit for other calls, but bound this
	// response independently so a large response cannot cause unbounded reads.
	maxPreviewCarrierSnapshotBytes = 16 << 20
)

var (
	ErrPreviewCarrierInvalid = errors.New("invalid preview carrier control document")
	ErrPreviewCarrierStale   = errors.New("preview carrier control document is stale")
)

const (
	previewCarrierAccessPublic  = "public"
	previewCarrierAccessPrivate = "private"
	previewCarrierPublicKind    = "preview_public_https_wss"
	previewCarrierPrivateKind   = "preview_private_https_wss"
)

// PreviewCarrierBinding mirrors the server-issued attachment binding. It is
// intentionally metadata only: the machine public key is a verifier value,
// never a private or bearer credential.
type PreviewCarrierBinding struct {
	AccountID                            string `json:"account_id"`
	PreviewID                            string `json:"preview_id"`
	OperationID                          string `json:"operation_id"`
	OwnerDeviceID                        string `json:"owner_device_id"`
	OwnerSessionID                       string `json:"owner_session_id"`
	HostID                               string `json:"host_id"`
	LeaseGeneration                      uint64 `json:"lease_generation"`
	TunnelID                             string `json:"tunnel_id"`
	ConnectorID                          string `json:"connector_id"`
	SessionID                            string `json:"session_id"`
	ProcessGeneration                    uint64 `json:"process_generation"`
	ConfigGeneration                     uint64 `json:"config_generation"`
	RouteID                              string `json:"route_id"`
	RouteGeneration                      uint64 `json:"route_generation"`
	EdgeNodeID                           string `json:"edge_node_id"`
	EdgeProcessEpoch                     string `json:"edge_process_epoch"`
	EdgeCarrierServerSPKISHA256          string `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string `json:"edge_carrier_server_certificate_chain_pem"`
	MachineIdentityPublicKey             string `json:"machine_identity_public_key"`
	MachineIdentityThumbprint            string `json:"machine_identity_thumbprint"`
}

type PreviewCarrierAdmission struct {
	Schema               string                `json:"schema"`
	Kind                 string                `json:"kind"`
	Binding              PreviewCarrierBinding `json:"binding"`
	AttachmentGeneration uint64                `json:"attachment_generation"`
	ConfigContentHash    string                `json:"config_content_hash"`
	EdgeEndpoints        []string              `json:"edge_endpoints"`
	Endpoint             string                `json:"endpoint"`
	ExpiresAt            time.Time             `json:"expires_at"`
	AccessMode           string                `json:"access_mode"`
	State                string                `json:"state,omitempty"`
	// Hostname and RouteRevision are optional on the wire for compatibility
	// with the server CarrierAdmission projection. When omitted they are
	// derived from Endpoint and Binding.RouteGeneration, respectively.
	Hostname      string                `json:"hostname,omitempty"`
	RouteKind     string                `json:"route_kind,omitempty"`
	RouteRevision uint64                `json:"route_revision,omitempty"`
	Aliases       []PreviewCarrierAlias `json:"aliases,omitempty"`
}

type PreviewCarrierAlias struct {
	DomainID              string `json:"domain_id"`
	Hostname              string `json:"hostname"`
	MatchType             string `json:"match_type"`
	WildcardLabels        *int   `json:"wildcard_labels,omitempty"`
	PreviewGeneration     uint64 `json:"preview_generation"`
	DomainGeneration      uint64 `json:"domain_generation"`
	CertificateGeneration uint64 `json:"certificate_generation"`
}

func (a PreviewCarrierAdmission) Normalize() (PreviewCarrierAdmission, error) {
	if a.Hostname == "" {
		parsed, err := url.Parse(a.Endpoint)
		if err != nil {
			return PreviewCarrierAdmission{}, fmt.Errorf("%w: endpoint: %v", ErrPreviewCarrierInvalid, err)
		}
		a.Hostname = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	if a.AccessMode == "" {
		switch a.RouteKind {
		case previewCarrierPublicKind:
			a.AccessMode = previewCarrierAccessPublic
		case previewCarrierPrivateKind:
			a.AccessMode = previewCarrierAccessPrivate
		default:
			return PreviewCarrierAdmission{}, fmt.Errorf("%w: access mode is required", ErrPreviewCarrierInvalid)
		}
	}
	if a.RouteKind == "" {
		switch a.AccessMode {
		case previewCarrierAccessPublic:
			a.RouteKind = previewCarrierPublicKind
		case previewCarrierAccessPrivate, "team":
			a.RouteKind = previewCarrierPrivateKind
		default:
			return PreviewCarrierAdmission{}, fmt.Errorf("%w: access mode is invalid", ErrPreviewCarrierInvalid)
		}
	}
	if a.RouteRevision == 0 {
		a.RouteRevision = a.Binding.RouteGeneration
	}
	a.Aliases = append([]PreviewCarrierAlias(nil), a.Aliases...)
	for index := range a.Aliases {
		a.Aliases[index].DomainID = strings.TrimSpace(a.Aliases[index].DomainID)
		a.Aliases[index].Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Aliases[index].Hostname), "."))
	}
	return a, nil
}

func (a PreviewCarrierAdmission) Validate(nodeID string, now time.Time, processEpoch ...string) error {
	normalized, err := a.Normalize()
	if err != nil {
		return err
	}
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || len(processEpoch) > 1 || len(processEpoch) == 1 && connectorprotocol.ValidateOpaqueEpoch(processEpoch[0]) != nil {
		return fmt.Errorf("%w: schema or edge process binding is invalid", ErrPreviewCarrierInvalid)
	}
	if normalized.Schema != previewCarrierSchema || normalized.Kind != previewCarrierKind || normalized.Binding.EdgeNodeID != nodeID || len(processEpoch) == 1 && normalized.Binding.EdgeProcessEpoch != processEpoch[0] {
		return fmt.Errorf("%w: schema or edge node binding is invalid", ErrPreviewCarrierInvalid)
	}
	for name, value := range map[string]string{
		"account_id": normalized.Binding.AccountID, "preview_id": normalized.Binding.PreviewID,
		"operation_id": normalized.Binding.OperationID, "owner_device_id": normalized.Binding.OwnerDeviceID,
		"owner_session_id": normalized.Binding.OwnerSessionID, "host_id": normalized.Binding.HostID,
		"tunnel_id": normalized.Binding.TunnelID, "connector_id": normalized.Binding.ConnectorID,
		"session_id": normalized.Binding.SessionID, "route_id": normalized.Binding.RouteID,
	} {
		if connectorprotocol.ValidateIdentifier(value) != nil {
			return fmt.Errorf("%w: %s is invalid", ErrPreviewCarrierInvalid, name)
		}
	}
	if connectorprotocol.ValidateOpaqueEpoch(normalized.Binding.EdgeProcessEpoch) != nil {
		return fmt.Errorf("%w: edge_process_epoch is invalid", ErrPreviewCarrierInvalid)
	}
	if normalized.Binding.HostID != normalized.Binding.OwnerDeviceID || normalized.Binding.TunnelID == normalized.Binding.ConnectorID {
		return fmt.Errorf("%w: owner and carrier identity do not bind", ErrPreviewCarrierInvalid)
	}
	if normalized.Binding.LeaseGeneration == 0 || normalized.Binding.ProcessGeneration == 0 || normalized.Binding.ConfigGeneration == 0 || normalized.Binding.RouteGeneration == 0 || normalized.AttachmentGeneration == 0 || normalized.RouteRevision == 0 || normalized.RouteRevision != normalized.Binding.RouteGeneration {
		return fmt.Errorf("%w: generation binding is invalid", ErrPreviewCarrierInvalid)
	}
	if normalized.AccessMode != previewCarrierAccessPublic && normalized.AccessMode != previewCarrierAccessPrivate && normalized.AccessMode != "team" {
		return fmt.Errorf("%w: access mode is invalid", ErrPreviewCarrierInvalid)
	}
	wantRouteKind := previewCarrierPublicKind
	if normalized.AccessMode == previewCarrierAccessPrivate || normalized.AccessMode == "team" {
		wantRouteKind = previewCarrierPrivateKind
	}
	if normalized.RouteKind != wantRouteKind || !validPreviewCarrierHostname(normalized.Hostname) {
		return fmt.Errorf("%w: route hostname or kind is invalid", ErrPreviewCarrierInvalid)
	}
	if normalized.State != "" && normalized.State != "pending" && normalized.State != "admitted" && normalized.State != "edge_ready" && normalized.State != "ready" {
		return fmt.Errorf("%w: admission state is invalid", ErrPreviewCarrierInvalid)
	}
	parsed, err := url.Parse(normalized.Endpoint)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")) != normalized.Hostname {
		return fmt.Errorf("%w: endpoint is not bound to hostname", ErrPreviewCarrierInvalid)
	}
	if !validPreviewCarrierHash(normalized.ConfigContentHash) {
		return fmt.Errorf("%w: config content hash is invalid", ErrPreviewCarrierInvalid)
	}
	if len(normalized.EdgeEndpoints) != 2 {
		return fmt.Errorf("%w: edge endpoint count is invalid", ErrPreviewCarrierInvalid)
	}
	carrierEndpoint, _ := url.Parse(normalized.EdgeEndpoints[0])
	if ValidateCarrierServerCertificateChain(normalized.Binding.EdgeCarrierServerCertificateChainPEM, normalized.Binding.EdgeCarrierServerSPKISHA256, carrierEndpoint.Hostname(), now.UTC()) != nil {
		return fmt.Errorf("%w: carrier server trust is invalid", ErrPreviewCarrierInvalid)
	}
	seenEndpointSchemes := make(map[string]struct{}, len(normalized.EdgeEndpoints))
	for _, endpoint := range normalized.EdgeEndpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Scheme != "h2" && parsed.Scheme != "h3" || parsed.Port() == "" {
			return fmt.Errorf("%w: edge endpoint is invalid", ErrPreviewCarrierInvalid)
		}
		port, portErr := strconv.Atoi(parsed.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%w: edge endpoint port is invalid", ErrPreviewCarrierInvalid)
		}
		if _, exists := seenEndpointSchemes[parsed.Scheme]; exists {
			return fmt.Errorf("%w: edge endpoint is invalid", ErrPreviewCarrierInvalid)
		}
		seenEndpointSchemes[parsed.Scheme] = struct{}{}
	}
	if _, ok := seenEndpointSchemes["h2"]; !ok {
		return fmt.Errorf("%w: HTTP/2 edge endpoint is required", ErrPreviewCarrierInvalid)
	}
	if _, ok := seenEndpointSchemes["h3"]; !ok {
		return fmt.Errorf("%w: HTTP/3 edge endpoint is required", ErrPreviewCarrierInvalid)
	}
	if normalized.ExpiresAt.IsZero() || !normalized.ExpiresAt.After(now) {
		return ErrPreviewCarrierStale
	}
	if len(normalized.Aliases) > maxPreviewCarrierAliases {
		return fmt.Errorf("%w: alias count is invalid", ErrPreviewCarrierInvalid)
	}
	seenAliasIDs := make(map[string]struct{}, len(normalized.Aliases))
	seenAliasHosts := make(map[string]struct{}, len(normalized.Aliases))
	for _, alias := range normalized.Aliases {
		if connectorprotocol.ValidateIdentifier(alias.DomainID) != nil || alias.PreviewGeneration != normalized.Binding.LeaseGeneration || alias.DomainGeneration == 0 || alias.CertificateGeneration == 0 || !validPreviewCarrierAliasHostname(alias.Hostname, alias.MatchType, alias.WildcardLabels) {
			return fmt.Errorf("%w: alias binding is invalid", ErrPreviewCarrierInvalid)
		}
		if _, duplicate := seenAliasIDs[alias.DomainID]; duplicate {
			return fmt.Errorf("%w: duplicate alias", ErrPreviewCarrierInvalid)
		}
		if _, duplicate := seenAliasHosts[alias.Hostname]; duplicate {
			return fmt.Errorf("%w: duplicate alias", ErrPreviewCarrierInvalid)
		}
		seenAliasIDs[alias.DomainID] = struct{}{}
		seenAliasHosts[alias.Hostname] = struct{}{}
	}
	if _, err := machineKey(normalized.Binding.MachineIdentityPublicKey, normalized.Binding.MachineIdentityThumbprint); err != nil {
		return err
	}
	return nil
}

func validPreviewCarrierAliasHostname(hostname, matchType string, wildcardLabels *int) bool {
	switch matchType {
	case "exact":
		return wildcardLabels == nil && !strings.HasPrefix(hostname, "*.") && validPreviewCarrierHostname(hostname)
	case "one_label_wildcard":
		return wildcardLabels != nil && *wildcardLabels == 1 && strings.HasPrefix(hostname, "*.") && validPreviewCarrierHostname(strings.TrimPrefix(hostname, "*."))
	default:
		return false
	}
}

// Expected converts the strict control representation into the edge
// datacarrier representation. Validate must run first so no caller can bypass
// operation, generation, route, or machine-key binding.
func (a PreviewCarrierAdmission) Expected(nodeID string, now time.Time) (datacarrier.ExpectedAdmission, error) {
	normalized, err := a.Normalize()
	if err != nil {
		return datacarrier.ExpectedAdmission{}, err
	}
	if err := normalized.Validate(nodeID, now); err != nil {
		return datacarrier.ExpectedAdmission{}, err
	}
	return datacarrier.ExpectedAdmission{
		Schema: normalized.Schema, Kind: normalized.Kind, EdgeNodeID: normalized.Binding.EdgeNodeID,
		PreviewID: normalized.Binding.PreviewID, OperationID: normalized.Binding.OperationID,
		OwnerDeviceID: normalized.Binding.OwnerDeviceID, OwnerSessionID: normalized.Binding.OwnerSessionID,
		Identity:        datacarrier.Identity{AccountID: normalized.Binding.AccountID, HostID: normalized.Binding.HostID, TunnelID: normalized.Binding.TunnelID, ConnectorID: normalized.Binding.ConnectorID, SessionID: normalized.Binding.SessionID, ProcessGeneration: normalized.Binding.ProcessGeneration, Generation: normalized.Binding.ConfigGeneration},
		LeaseGeneration: normalized.Binding.LeaseGeneration, ConfigGeneration: normalized.Binding.ConfigGeneration,
		ConfigContentHash: normalized.ConfigContentHash, RouteID: normalized.Binding.RouteID, EdgeProcessEpoch: normalized.Binding.EdgeProcessEpoch,
		EdgeCarrierServerSPKISHA256: normalized.Binding.EdgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: normalized.Binding.EdgeCarrierServerCertificateChainPEM,
		AccessMode: normalized.AccessMode, RouteKind: normalized.RouteKind, Hostname: normalized.Hostname, RouteRevision: normalized.RouteRevision,
		AttachmentGeneration: normalized.AttachmentGeneration, Endpoint: normalized.Endpoint, ExpiresAt: normalized.ExpiresAt,
		MachineIdentityPublicKey: normalized.Binding.MachineIdentityPublicKey, MachineIdentityThumbprint: normalized.Binding.MachineIdentityThumbprint,
	}, nil
}

type PreviewCarrierObservation struct {
	Schema               string                `json:"schema"`
	Kind                 string                `json:"kind"`
	Binding              PreviewCarrierBinding `json:"binding"`
	AttachmentGeneration uint64                `json:"attachment_generation"`
	State                string                `json:"state"`
	Reason               string                `json:"reason,omitempty"`
	ObservedAt           time.Time             `json:"observed_at"`
}

type PreviewCarrierDetachment struct {
	Schema               string                `json:"schema"`
	Kind                 string                `json:"kind"`
	Binding              PreviewCarrierBinding `json:"binding"`
	AttachmentGeneration uint64                `json:"attachment_generation"`
	Reason               string                `json:"reason"`
	ObservedAt           time.Time             `json:"observed_at"`
}

type PreviewCarrierSource interface {
	PreviewCarrierAdmissions(context.Context, string, string) ([]PreviewCarrierAdmission, error)
	AcknowledgePreviewCarrierAdmissions(context.Context, string, string, []PreviewCarrierAdmission) error
	ObservePreviewCarriers(context.Context, string, string, []PreviewCarrierObservation) error
	DetachPreviewCarriers(context.Context, string, string, []PreviewCarrierDetachment) error
}

// PreviewCarrierSnapshot is the complete desired state returned by the edge
// control plane. Detachments are server-created terminal commands with their
// own durable generation; the edge must never derive one from an old route.
type PreviewCarrierSnapshot struct {
	Admissions  []PreviewCarrierAdmission
	Detachments []PreviewCarrierDetachment
}

// PreviewCarrierSnapshotSource is optional so small deterministic fakes can
// continue to model admissions only. Production HTTPClient implements it.
// A worker uses it whenever available and otherwise falls back to the legacy
// admissions-only test boundary.
type PreviewCarrierSnapshotSource interface {
	PreviewCarrierSnapshot(context.Context, string, string) (PreviewCarrierSnapshot, error)
}

func (c *HTTPClient) PreviewCarrierSnapshot(ctx context.Context, nodeID, processEpoch string) (PreviewCarrierSnapshot, error) {
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return PreviewCarrierSnapshot{}, ErrControlInvalid
	}
	var result struct {
		Schema      string                      `json:"schema"`
		Kind        string                      `json:"kind"`
		Complete    bool                        `json:"complete"`
		Admissions  *[]PreviewCarrierAdmission  `json:"admissions"`
		Detachments *[]PreviewCarrierDetachment `json:"detachments"`
	}
	if err := c.postNodeWithMaximumAndIdentity(ctx, PreviewCarrierAdmissionsPath, nodeID, processEpoch, struct {
		NodeID       string `json:"edge_node_id"`
		ProcessEpoch string `json:"edge_process_epoch"`
	}{nodeID, processEpoch}, &result, maxPreviewCarrierSnapshotBytes); err != nil {
		return PreviewCarrierSnapshot{}, err
	}
	if result.Schema != previewCarrierSchema || result.Kind != previewCarrierKind || !result.Complete || result.Admissions == nil || result.Detachments == nil || len(*result.Admissions) > maxPreviewCarrierAdmissions || len(*result.Detachments) > maxPreviewCarrierAdmissions {
		return PreviewCarrierSnapshot{}, ErrControlUnavailable
	}
	now := time.Now().UTC()
	admissions := append([]PreviewCarrierAdmission(nil), (*result.Admissions)...)
	for index := range admissions {
		if _, err := admissions[index].Normalize(); err != nil {
			return PreviewCarrierSnapshot{}, ErrControlUnavailable
		}
		if err := admissions[index].Validate(nodeID, now, processEpoch); err != nil {
			return PreviewCarrierSnapshot{}, ErrControlUnavailable
		}
	}
	detachments := append([]PreviewCarrierDetachment(nil), (*result.Detachments)...)
	for index := range detachments {
		if err := validatePreviewCarrierDetachment(nodeID, processEpoch, detachments[index]); err != nil {
			return PreviewCarrierSnapshot{}, ErrControlUnavailable
		}
	}
	return PreviewCarrierSnapshot{Admissions: admissions, Detachments: detachments}, nil
}

func (c *HTTPClient) PreviewCarrierAdmissions(ctx context.Context, nodeID, processEpoch string) ([]PreviewCarrierAdmission, error) {
	snapshot, err := c.PreviewCarrierSnapshot(ctx, nodeID, processEpoch)
	if err != nil {
		return nil, err
	}
	return snapshot.Admissions, nil
}

func (c *HTTPClient) ObservePreviewCarriers(ctx context.Context, nodeID, processEpoch string, observations []PreviewCarrierObservation) error {
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil || len(observations) > maxPreviewCarrierAdmissions {
		return ErrControlInvalid
	}
	for _, observation := range observations {
		if err := validatePreviewCarrierObservation(nodeID, processEpoch, observation); err != nil {
			return err
		}
	}
	if len(observations) == 0 {
		return nil
	}
	return c.postNodeWithMaximumAndIdentity(ctx, PreviewCarrierObservationsPath, nodeID, processEpoch, struct {
		NodeID       string                      `json:"edge_node_id"`
		ProcessEpoch string                      `json:"edge_process_epoch"`
		Observations []PreviewCarrierObservation `json:"observations"`
	}{nodeID, processEpoch, observations}, nil, maxControlDocument)
}

// AcknowledgePreviewCarrierAdmissions commits exact admissions after the edge
// has installed and validated them. The server treats operation ID plus
// attachment generation as an idempotent outbox acknowledgement.
func (c *HTTPClient) AcknowledgePreviewCarrierAdmissions(ctx context.Context, nodeID, processEpoch string, admissions []PreviewCarrierAdmission) error {
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil || len(admissions) > maxPreviewCarrierAdmissions {
		return ErrControlInvalid
	}
	normalized := make([]PreviewCarrierAdmission, len(admissions))
	now := time.Now().UTC()
	for index, admission := range admissions {
		value, err := admission.Normalize()
		if err != nil {
			return err
		}
		if err := value.Validate(nodeID, now, processEpoch); err != nil {
			return err
		}
		normalized[index] = value
	}
	if len(normalized) == 0 {
		return nil
	}
	return c.postNodeWithMaximumAndIdentity(ctx, PreviewCarrierAdmissionAcksPath, nodeID, processEpoch, struct {
		NodeID       string                    `json:"edge_node_id"`
		ProcessEpoch string                    `json:"edge_process_epoch"`
		Admissions   []PreviewCarrierAdmission `json:"admissions"`
	}{nodeID, processEpoch, normalized}, nil, maxPreviewCarrierSnapshotBytes)
}

func (c *HTTPClient) DetachPreviewCarriers(ctx context.Context, nodeID, processEpoch string, detachments []PreviewCarrierDetachment) error {
	if connectorprotocol.ValidateIdentifier(nodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil || len(detachments) > maxPreviewCarrierAdmissions {
		return ErrControlInvalid
	}
	for _, detachment := range detachments {
		if err := validatePreviewCarrierDetachment(nodeID, processEpoch, detachment); err != nil {
			return err
		}
	}
	if len(detachments) == 0 {
		return nil
	}
	return c.postNodeWithMaximumAndIdentity(ctx, PreviewCarrierDetachmentsPath, nodeID, processEpoch, struct {
		NodeID       string                     `json:"edge_node_id"`
		ProcessEpoch string                     `json:"edge_process_epoch"`
		Detachments  []PreviewCarrierDetachment `json:"detachments"`
	}{nodeID, processEpoch, detachments}, nil, maxPreviewCarrierSnapshotBytes)
}

func validatePreviewCarrierObservation(nodeID, processEpoch string, value PreviewCarrierObservation) error {
	if value.Schema != previewCarrierSchema || value.Kind != previewCarrierKind || value.Binding.EdgeNodeID != nodeID || value.Binding.EdgeProcessEpoch != processEpoch || value.AttachmentGeneration == 0 || value.ObservedAt.IsZero() || value.Reason != "" && len(value.Reason) > 512 || strings.ContainsAny(value.Reason, "\r\n\x00") {
		return ErrPreviewCarrierInvalid
	}
	if value.State != "edge_ready" && value.State != "detached" && value.State != "expired" {
		return ErrPreviewCarrierInvalid
	}
	return validatePreviewCarrierBinding(nodeID, processEpoch, value.Binding)
}

func validatePreviewCarrierDetachment(nodeID, processEpoch string, value PreviewCarrierDetachment) error {
	if value.Schema != previewCarrierSchema || value.Kind != previewCarrierKind || value.Binding.EdgeNodeID != nodeID || value.Binding.EdgeProcessEpoch != processEpoch || value.AttachmentGeneration == 0 || value.ObservedAt.IsZero() || value.Reason == "" || len(value.Reason) > 512 || strings.ContainsAny(value.Reason, "\r\n\x00") {
		return ErrPreviewCarrierInvalid
	}
	return validatePreviewCarrierBinding(nodeID, processEpoch, value.Binding)
}

func validatePreviewCarrierBinding(nodeID, processEpoch string, binding PreviewCarrierBinding) error {
	for _, value := range []string{binding.AccountID, binding.PreviewID, binding.OperationID, binding.OwnerDeviceID, binding.OwnerSessionID, binding.HostID, binding.TunnelID, binding.ConnectorID, binding.SessionID, binding.RouteID, binding.EdgeNodeID} {
		if connectorprotocol.ValidateIdentifier(value) != nil {
			return ErrPreviewCarrierInvalid
		}
	}
	if connectorprotocol.ValidateOpaqueEpoch(binding.EdgeProcessEpoch) != nil {
		return ErrPreviewCarrierInvalid
	}
	if binding.EdgeNodeID != nodeID || binding.EdgeProcessEpoch != processEpoch || binding.HostID != binding.OwnerDeviceID || binding.TunnelID == binding.ConnectorID || binding.LeaseGeneration == 0 || binding.ProcessGeneration == 0 || binding.ConfigGeneration == 0 || binding.RouteGeneration == 0 {
		return ErrPreviewCarrierInvalid
	}
	_, err := machineKey(binding.MachineIdentityPublicKey, binding.MachineIdentityThumbprint)
	return err
}

func machineKey(value, thumbprint string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrPreviewCarrierInvalid
	}
	digest := sha256.Sum256(decoded)
	want := "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	if thumbprint != want {
		return nil, ErrPreviewCarrierInvalid
	}
	return ed25519.PublicKey(decoded), nil
}

func validPreviewCarrierHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validPreviewCarrierHostname(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@[] \t\r\n") {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(strings.TrimSuffix(value, ".")), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}
