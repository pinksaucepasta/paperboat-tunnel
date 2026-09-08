package connectorprotocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
)

// WriteIngressDecision precedes application bytes on every replacement edge
// stream. Its bounded, strict encoding is shared by HTTP and opaque TCP.
func WriteIngressDecision(w io.Writer, d IngressDecision, now time.Time) error {
	if w == nil || d.Validate(now) != nil {
		return ErrIngressDenied
	}
	p, err := json.Marshal(d)
	if err != nil || len(p) > MaxStreamOpenBytes {
		return ErrIngressDenied
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := writeAllStreamOpen(w, h[:]); err != nil {
		return err
	}
	_, err = writeAllStreamOpen(w, p)
	return err
}

func ReadIngressDecision(r io.Reader, now time.Time) (IngressDecision, error) {
	var d IngressDecision
	if r == nil {
		return d, ErrIngressDenied
	}
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return d, ErrIngressDenied
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxStreamOpenBytes {
		return d, ErrIngressDenied
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return d, ErrIngressDenied
	}
	if decodeStrict(p, &d) != nil || d.Validate(now) != nil {
		return IngressDecision{}, ErrIngressDenied
	}
	return d, nil
}

const (
	IngressAuthorityLifetime = 10 * time.Second
	IngressRefreshInterval   = 5 * time.Second
	TunnelEphemeral          = "ephemeral"
	TunnelDurable            = "durable"
)

var ErrIngressDenied = errors.New("connector ingress authority denied")

// IngressBinding is the single v1 tunnel route/target identity shared by both
// lifecycle modes. It is issued by the server, never inferred from reachability
// or public request headers. Native access does not consume edge bindings.
type IngressBinding struct {
	EnvironmentID           string `json:"environment_id"`
	AccountID               string `json:"account_id"`
	TunnelID                string `json:"tunnel_id"`
	Lifecycle               string `json:"lifecycle"`
	ResourceGeneration      uint64 `json:"resource_generation"`
	RouteID                 string `json:"route_id"`
	RouteGeneration         uint64 `json:"route_generation"`
	TargetID                string `json:"target_id"`
	TargetGeneration        uint64 `json:"target_generation"`
	HostID                  string `json:"host_id"`
	InstallationGeneration  uint64 `json:"installation_generation"`
	Audience                string `json:"audience"`
	ConnectionMethod        string `json:"connection_method"`
	Protocol                string `json:"protocol"`
	Hostname                string `json:"hostname"`
	PathPrefix              string `json:"path_prefix"`
	OriginScheme            string `json:"origin_scheme"`
	OriginAddress           string `json:"origin_address"`
	TLSServerName           string `json:"tls_server_name"`
	TLSVerification         string `json:"tls_verification"`
	CAReference             string `json:"ca_reference"`
	MTLSCredentialReference string `json:"mtls_credential_reference"`
	PublicationID           string `json:"publication_id"`
	PublicationGeneration   uint64 `json:"publication_generation"`
	ListenerID              string `json:"listener_id"`
	PublicPort              uint16 `json:"public_port"`
}

func (b IngressBinding) Validate() error {
	for _, id := range []string{b.EnvironmentID, b.AccountID, b.TunnelID, b.RouteID, b.TargetID, b.HostID, b.PublicationID} {
		if ValidateIdentifier(id) != nil {
			return ErrIngressDenied
		}
	}
	if (b.Lifecycle != TunnelEphemeral && b.Lifecycle != TunnelDurable) || b.ConnectionMethod != "edge" ||
		b.ResourceGeneration == 0 || b.RouteGeneration == 0 || b.TargetGeneration == 0 || b.InstallationGeneration == 0 || b.PublicationGeneration == 0 {
		return ErrIngressDenied
	}
	if b.Audience != "public" && b.Audience != "private" && b.Audience != "team" {
		return ErrIngressDenied
	}
	if b.OriginScheme == "unix" {
		if b.Protocol != "http" || len(b.OriginAddress) > 512 || !path.IsAbs(b.OriginAddress) || path.Clean(b.OriginAddress) != b.OriginAddress || strings.ContainsAny(b.OriginAddress, "\x00\r\n") {
			return ErrIngressDenied
		}
	} else {
		host, port, err := net.SplitHostPort(b.OriginAddress)
		ip := net.ParseIP(host)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() {
			return ErrIngressDenied
		}
	}
	if b.Hostname == "" || len(b.Hostname) > 253 || b.Hostname != strings.ToLower(b.Hostname) || strings.ContainsAny(b.Hostname, " /\\:@\r\n") {
		return ErrIngressDenied
	}
	switch b.Protocol {
	case "http":
		if b.ListenerID != "" || b.PublicPort != 0 || !strings.HasPrefix(b.PathPrefix, "/") || strings.ContainsAny(b.PathPrefix, "?#\r\n") {
			return ErrIngressDenied
		}
		if b.OriginScheme != "http" && b.OriginScheme != "https" && b.OriginScheme != "h2c" && b.OriginScheme != "unix" {
			return ErrIngressDenied
		}
	case "tcp":
		if b.Audience != "public" || ValidateIdentifier(b.ListenerID) != nil || b.PublicPort == 0 || b.PathPrefix != "" || b.OriginScheme != "tcp" {
			return ErrIngressDenied
		}
	default:
		return ErrIngressDenied
	}
	if b.OriginScheme == "https" {
		if b.TLSVerification != "system" && b.TLSVerification != "custom_ca" {
			return ErrIngressDenied
		}
		if b.TLSVerification == "custom_ca" && b.CAReference == "" {
			return ErrIngressDenied
		}
	} else if b.TLSVerification != "not_applicable" || b.TLSServerName != "" || b.CAReference != "" || b.MTLSCredentialReference != "" {
		return ErrIngressDenied
	}
	return nil
}

// IngressDecision is typed provenance over the authenticated connector. Public
// publication is owner authority; restricted viewer grants are separate fields.
// A daemon compares Binding to its independently obtained current server binding.
type IngressDecision struct {
	Binding              IngressBinding `json:"binding"`
	DecisionID           string         `json:"decision_id"`
	PolicyGeneration     uint64         `json:"policy_generation"`
	EdgeNodeID           string         `json:"edge_node_id"`
	EdgeProcessEpoch     string         `json:"edge_process_epoch"`
	ConnectorID          string         `json:"connector_id"`
	SessionID            string         `json:"session_id"`
	ProcessGeneration    uint64         `json:"process_generation"`
	ConfigGeneration     uint64         `json:"config_generation"`
	AssignmentGeneration uint64         `json:"assignment_generation"`
	PrincipalID          string         `json:"principal_id"`
	GrantID              string         `json:"grant_id"`
	GrantGeneration      uint64         `json:"grant_generation"`
	MembershipGeneration uint64         `json:"membership_generation"`
	Action               string         `json:"action"`
	IssuedAt             time.Time      `json:"issued_at"`
	ExpiresAt            time.Time      `json:"expires_at"`
}

func (d IngressDecision) Validate(now time.Time) error {
	if d.Binding.Validate() != nil || now.IsZero() || d.IssuedAt.IsZero() || d.IssuedAt.After(now) || !d.ExpiresAt.After(now) || d.ExpiresAt.Sub(d.IssuedAt) > IngressAuthorityLifetime || d.Action != "view" {
		return ErrIngressDenied
	}
	for _, id := range []string{d.DecisionID, d.EdgeNodeID, d.ConnectorID, d.SessionID} {
		if ValidateIdentifier(id) != nil {
			return ErrIngressDenied
		}
	}
	if ValidateOpaqueEpoch(d.EdgeProcessEpoch) != nil || d.PolicyGeneration == 0 || d.ProcessGeneration == 0 || d.ConfigGeneration == 0 || d.AssignmentGeneration == 0 {
		return ErrIngressDenied
	}
	if d.Binding.Audience == "public" {
		if d.PrincipalID != "" || d.GrantID != "" || d.GrantGeneration != 0 || d.MembershipGeneration != 0 {
			return ErrIngressDenied
		}
	} else {
		if ValidateIdentifier(d.PrincipalID) != nil || ValidateIdentifier(d.GrantID) != nil || d.GrantGeneration == 0 {
			return ErrIngressDenied
		}
		if d.Binding.Audience == "team" && d.MembershipGeneration == 0 {
			return ErrIngressDenied
		}
	}
	return nil
}

func (d IngressDecision) Authorize(authority IngressDecision, open StreamOpen, edgeNodeID, edgeEpoch string, now time.Time) error {
	current := authority.Binding
	if d.Validate(now) != nil || authority.Validate(now) != nil || d.Binding != current || open.Validate() != nil ||
		d.PolicyGeneration != authority.PolicyGeneration || d.AssignmentGeneration != authority.AssignmentGeneration ||
		d.ConnectorID != authority.ConnectorID || d.SessionID != authority.SessionID || d.ProcessGeneration != authority.ProcessGeneration || d.ConfigGeneration != authority.ConfigGeneration ||
		d.EdgeNodeID != authority.EdgeNodeID || d.EdgeProcessEpoch != authority.EdgeProcessEpoch ||
		d.PrincipalID != authority.PrincipalID || d.GrantID != authority.GrantID || d.GrantGeneration != authority.GrantGeneration || d.MembershipGeneration != authority.MembershipGeneration ||
		open.AccountID != current.AccountID || open.TunnelID != current.TunnelID || open.RouteID != current.RouteID ||
		d.ConnectorID != open.ConnectorID || d.SessionID != open.SessionID || d.ProcessGeneration != open.ProcessGeneration || d.ConfigGeneration != open.Generation ||
		d.EdgeNodeID != edgeNodeID || d.EdgeProcessEpoch != edgeEpoch {
		return ErrIngressDenied
	}
	return nil
}
