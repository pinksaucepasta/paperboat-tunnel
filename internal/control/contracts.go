package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
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
	RouteID                    string          `json:"route_id"`
	Revision                   uint64          `json:"route_revision"`
	Environment                string          `json:"environment_id"`
	AccountID                  string          `json:"account_id,omitempty"`
	HostID                     string          `json:"host_id,omitempty"`
	MachineIdentityPublicKey   string          `json:"machine_identity_public_key,omitempty"`
	MachineIdentityThumbprint  string          `json:"machine_identity_thumbprint,omitempty"`
	TunnelID                   string          `json:"tunnel_id,omitempty"`
	ConnectorID                string          `json:"connector_id"`
	Generation                 uint64          `json:"connector_generation"`
	ConnectorSessionID         string          `json:"connector_session_id,omitempty"`
	ConnectorProcessGeneration uint64          `json:"connector_process_generation,omitempty"`
	ConfigGeneration           uint64          `json:"config_generation,omitempty"`
	ConfigContentHash          string          `json:"config_content_hash,omitempty"`
	AssignmentID               string          `json:"assignment_id,omitempty"`
	AssignmentGeneration       uint64          `json:"assignment_generation,omitempty"`
	EdgeFailureDomain          string          `json:"edge_failure_domain,omitempty"`
	EdgeProcessEpoch           string          `json:"edge_process_epoch,omitempty"`
	NodeID                     string          `json:"edge_node_id"`
	Kind                       string          `json:"kind"`
	PublicHost                 string          `json:"public_host"`
	MatchType                  string          `json:"match_type,omitempty"`
	MatchHostname              string          `json:"match_hostname,omitempty"`
	WildcardSuffix             string          `json:"wildcard_suffix,omitempty"`
	PathPrefix                 string          `json:"path_prefix,omitempty"`
	Priority                   int             `json:"priority,omitempty"`
	Protocol                   string          `json:"protocol,omitempty"`
	OriginScheme               string          `json:"origin_scheme,omitempty"`
	AccessMode                 string          `json:"access_mode,omitempty"`
	OriginAddress              string          `json:"origin_address,omitempty"`
	PreserveHost               bool            `json:"preserve_host,omitempty"`
	HostOverride               string          `json:"host_override,omitempty"`
	DomainBindings             []DomainBinding `json:"domain_bindings,omitempty"`
	State                      string          `json:"state,omitempty"`
	DesiredState               string          `json:"desired_state,omitempty"`
	ObservedState              string          `json:"observed_state,omitempty"`
	TargetHost                 string          `json:"target_host,omitempty"`
	TargetPort                 uint16          `json:"target_port,omitempty"`
	TargetRouteID              string          `json:"-"`
	TargetConnectorSessionID   string          `json:"-"`
	TargetConnectorProcessGen  uint64          `json:"-"`
	TargetConfigGeneration     uint64          `json:"-"`
	PreviewState               string          `json:"preview_state,omitempty"`
	PreviewReason              string          `json:"preview_reason,omitempty"`
	// Canonical is an in-process marker set only by the versioned snapshot
	// decoder. It is deliberately not accepted from callers or serialized.
	Canonical bool `json:"-"`
}

type DomainBinding struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	MatchType  string `json:"match_type"`
	Generation uint64 `json:"generation"`
}

type RouteSource interface {
	DesiredRoutes(context.Context, string) ([]RouteAssignment, error)
}

// RouteSnapshot is the complete control-plane route response. Complete is a
// safety fence: a failed or truncated response must never be interpreted as
// an empty desired set. Canonical distinguishes tunnel assignments from the
// legacy helper/preview feed, including a successful empty canonical set in
// deterministic tests and future server responses.
type RouteSnapshot struct {
	Routes    []RouteAssignment
	Complete  bool
	Canonical bool
}

// RouteSnapshotSource is optional so legacy fakes and retained helper routes
// can continue to use RouteSource. Production HTTP clients implement this
// interface and require the edge process epoch for canonical assignments.
type RouteSnapshotSource interface {
	DesiredRouteSnapshot(context.Context, string, string) (RouteSnapshot, error)
}

type RouteObservation struct {
	RouteID                    string `json:"route_id"`
	RouteRevision              uint64 `json:"route_revision"`
	AssignmentID               string `json:"assignment_id,omitempty"`
	AssignmentGeneration       uint64 `json:"assignment_generation,omitempty"`
	EdgeNodeID                 string `json:"edge_node_id"`
	EdgeProcessEpoch           string `json:"edge_process_epoch,omitempty"`
	ConnectorID                string `json:"connector_id,omitempty"`
	HostID                     string `json:"host_id,omitempty"`
	ConnectorGeneration        uint64 `json:"connector_generation"`
	ConnectorSessionID         string `json:"connector_session_id,omitempty"`
	ConnectorProcessGeneration uint64 `json:"connector_process_generation,omitempty"`
	ConfigGeneration           uint64 `json:"config_generation,omitempty"`
	ConfigContentHash          string `json:"config_content_hash,omitempty"`
	State                      string `json:"state,omitempty"`
	ObservedState              string `json:"observed_state,omitempty"`
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
	RelayID      string            `json:"relay_id"`
	RelayRegion  string            `json:"relay_region"`
	RelayName    string            `json:"relay_name"`
	Artifact     string            `json:"artifact"`
	Protocol     string            `json:"protocol"`
	ProcessEpoch string            `json:"process_epoch"`
	Capacity     uint32            `json:"capacity"`
	Endpoint     ConnectorEndpoint `json:"connector_endpoint"`
	// CarrierEndpoint is required by the connector-v1 node contract. It is
	// separate from the legacy FRP endpoint and always advertises both
	// dedicated transports.
	CarrierEndpoint ConnectorEndpoint `json:"carrier_endpoint"`
	// CarrierServerSPKISHA256 pins the configured carrier TLS public key to
	// this exact node registration and process epoch. It is non-secret.
	CarrierServerSPKISHA256          string      `json:"carrier_server_spki_sha256"`
	CarrierServerCertificateChainPEM string      `json:"carrier_server_certificate_chain_pem"`
	SignalingHost                    string      `json:"signaling_host"`
	STUNEndpoint                     UDPEndpoint `json:"stun_endpoint"`
}

type ConnectorEndpoint struct {
	Host     string `json:"host"`
	TCPPort  uint16 `json:"tcp_port"`
	QUICPort uint16 `json:"quic_port"`
}

func (registration NodeRegistration) Validate() error {
	if registration.NodeID == "" || registration.ProcessEpoch == "" || registration.Capacity == 0 || !ValidCarrierServerSPKISHA256(registration.CarrierServerSPKISHA256) || ValidateCarrierServerCertificateChain(registration.CarrierServerCertificateChainPEM, registration.CarrierServerSPKISHA256, registration.CarrierEndpoint.Host, time.Now().UTC()) != nil {
		return errors.New("node registration identity and capacity are required")
	}
	if err := registration.CarrierEndpoint.Validate(); err != nil {
		return fmt.Errorf("carrier endpoint: %w", err)
	}
	return nil
}

func ValidCarrierServerSPKISHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

// CarrierServerSPKISHA256 verifies that a configured certificate and private
// key form one pair, then returns the RFC 5280 SubjectPublicKeyInfo pin.
func CarrierServerSPKISHA256(certificate tls.Certificate) (string, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return "", errors.New("carrier server certificate and private key are required")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("parse carrier server certificate: %w", err)
	}
	privatePublic, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return "", errors.New("carrier server private key has no public key")
	}
	privateSPKI, err := x509.MarshalPKIXPublicKey(privatePublic.Public())
	if err != nil {
		return "", fmt.Errorf("marshal carrier server private key public part: %w", err)
	}
	if !bytes.Equal(privateSPKI, leaf.RawSubjectPublicKeyInfo) {
		return "", errors.New("carrier server certificate and private key do not match")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

const maximumCarrierServerCertificateChainPEM = 64 << 10

func CarrierServerCertificateChainPEM(certificate tls.Certificate) (string, error) {
	if len(certificate.Certificate) == 0 || len(certificate.Certificate) > 8 {
		return "", errors.New("carrier server certificate chain is invalid")
	}
	var result bytes.Buffer
	for _, der := range certificate.Certificate {
		if len(der) == 0 {
			return "", errors.New("carrier server certificate chain is invalid")
		}
		if err := pem.Encode(&result, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil || result.Len() > maximumCarrierServerCertificateChainPEM {
			return "", errors.New("carrier server certificate chain is invalid")
		}
	}
	return result.String(), nil
}

func ValidateCarrierServerCertificateChain(chainPEM, pin, hostname string, now time.Time) error {
	if len(chainPEM) == 0 || len(chainPEM) > maximumCarrierServerCertificateChainPEM || !ValidCarrierServerSPKISHA256(pin) {
		return errors.New("carrier server certificate chain is invalid")
	}
	rest := []byte(chainPEM)
	count := 0
	var leaf *x509.Certificate
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return errors.New("carrier server certificate chain is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("carrier server certificate chain is invalid")
		}
		if count == 0 {
			leaf = certificate
		}
		count++
		if count > 8 {
			return errors.New("carrier server certificate chain is invalid")
		}
		rest = next
	}
	if leaf == nil {
		return errors.New("carrier server certificate chain is invalid")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(hostname) != nil {
		return errors.New("carrier server certificate chain is invalid")
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if pin != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("carrier server certificate pin does not match chain leaf")
	}
	return nil
}

func (endpoint ConnectorEndpoint) Validate() error {
	if endpoint.Host == "" || len(endpoint.Host) > 253 || strings.ContainsAny(endpoint.Host, "/:@\r\n\x00") || endpoint.TCPPort == 0 || endpoint.QUICPort == 0 {
		return errors.New("host and both nonzero transport ports are required")
	}
	return nil
}

type UDPEndpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
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
