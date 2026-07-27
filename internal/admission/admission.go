package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
)

const audience = "paperboat-edge"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)

type Claims struct {
	KeyID               string
	Issuer              string
	Audience            string
	JTI                 string
	CredentialClass     string
	Scopes              []string
	EnvironmentID       string
	HelperID            string
	ConnectorGeneration uint64
	EdgePool            string
	EdgeNodeID          string
	ExpiresAt           time.Time
	Revoked             bool
}

type Route struct {
	RouteID    string `json:"route_id"`
	Revision   uint64 `json:"route_revision"`
	Kind       string `json:"kind"`
	PublicHost string `json:"public_host"`
	ProxyName  string `json:"proxy_name"`
	TargetHost string `json:"target_host"`
	TargetPort uint16 `json:"target_port"`
}

type Request struct {
	OperationID string  `json:"operation_id"`
	Credential  string  `json:"-"`
	Environment string  `json:"environment_id"`
	Helper      string  `json:"helper_id"`
	Generation  uint64  `json:"connector_generation"`
	EdgePool    string  `json:"edge_pool"`
	EdgeNode    string  `json:"edge_node_id"`
	Routes      []Route `json:"routes"`
}

type Response struct {
	RunID       RunID
	Environment string
	Helper      string
	Generation  uint64
	EdgeNode    string
	Routes      []Route
}

type Verifier interface {
	Verify(context.Context, string) (Claims, error)
}

type Current struct {
	Generation uint64
	EdgePool   string
	EdgeNode   string
	Revoked    bool
}

type Authorizer interface {
	Current(context.Context, string, string) (Current, error)
}

type Service struct {
	Verifier   Verifier
	Authorizer Authorizer
	Journal    *operation.Journal
	Issuer     string
	Now        func() time.Time
	NewRunID   func(uint64, time.Time) (RunID, error)
}

func (s *Service) Admit(ctx context.Context, request Request) (Response, error) {
	if s == nil || s.Verifier == nil || s.Authorizer == nil || s.Journal == nil || s.Issuer == "" || request.OperationID == "" {
		return Response{}, invalid("admission request is invalid")
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	claims, err := s.Verifier.Verify(ctx, request.Credential)
	if err != nil {
		if _, typed := edgeerrors.CodeOf(err); typed {
			return Response{}, err
		}
		return Response{}, edgeerrors.Wrap(edgeerrors.CodeCredentialInvalid, "credential verification failed", "request a fresh admission", err)
	}
	if err := validateClaims(claims, request, s.Issuer, now); err != nil {
		return Response{}, err
	}
	current, err := s.Authorizer.Current(ctx, request.Environment, request.Helper)
	if err != nil {
		return Response{}, edgeerrors.Wrap(edgeerrors.CodeCredentialInvalid, "admission state unavailable", "retry after control state recovers", err)
	}
	if current.Revoked {
		return Response{}, edgeerrors.New(edgeerrors.CodeRevoked, "admission is revoked", "request a fresh admission")
	}
	if current.Generation != request.Generation || claims.ConnectorGeneration != current.Generation {
		return Response{}, edgeerrors.New(edgeerrors.CodeGenerationStale, "connector generation is stale", "request a fresh admission")
	}
	if current.EdgePool != request.EdgePool || current.EdgeNode != request.EdgeNode {
		return Response{}, invalid("admission node binding is invalid")
	}
	if err := validateRoutes(request.Routes); err != nil {
		return Response{}, err
	}
	canonical, _ := json.Marshal(request)
	expires := claims.ExpiresAt
	newRunID := s.NewRunID
	if newRunID == nil {
		newRunID = NewRunID
	}
	runID, err := newRunID(request.Generation, expires)
	if err != nil {
		return Response{}, err
	}
	decision, _ := json.Marshal(Response{RunID: runID, Environment: request.Environment, Helper: request.Helper, Generation: request.Generation, EdgeNode: request.EdgeNode, Routes: request.Routes})
	outcome, err := s.Journal.Consume(now, operation.Request{OperationID: request.OperationID, JTI: claims.JTI, Canonical: canonical, Decision: decision, RetainUntil: expires.Add(time.Minute)})
	if err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.Unmarshal(outcome.Decision, &response); err != nil {
		return Response{}, errors.New("journal decision is corrupt")
	}
	return response, nil
}

func validateClaims(c Claims, r Request, issuer string, now time.Time) error {
	if c.Issuer != issuer || c.Audience != audience || c.CredentialClass != "connector_admission" || len(c.Scopes) != 1 || c.Scopes[0] != "connector:admit" || c.JTI == "" {
		return invalid("credential claims are not valid")
	}
	if c.Revoked {
		return edgeerrors.New(edgeerrors.CodeRevoked, "admission is revoked", "request a fresh admission")
	}
	if !c.ExpiresAt.After(now) {
		return edgeerrors.New(edgeerrors.CodeCredentialExpired, "credential is expired", "request a fresh admission")
	}
	if c.EnvironmentID != r.Environment || c.HelperID != r.Helper || c.ConnectorGeneration != r.Generation || c.EdgePool != r.EdgePool || c.EdgeNodeID != r.EdgeNode {
		return invalid("credential binding is invalid")
	}
	return nil
}

func validateRoutes(routes []Route) error {
	if len(routes) == 0 || len(routes) > 128 {
		return invalid("route handoff is invalid")
	}
	seenHosts, seenIDs := map[string]bool{}, map[string]bool{}
	for _, route := range routes {
		if !idPattern.MatchString(route.RouteID) || !idPattern.MatchString(route.ProxyName) || route.Revision == 0 || (route.Kind != "helper_https_wss" && route.Kind != "preview_public_https_wss") || route.TargetPort == 0 || route.TargetHost != "127.0.0.1" && route.TargetHost != "::1" {
			return invalid("route handoff is invalid")
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(route.PublicHost), "."))
		if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, "/?@") || seenHosts[host] || seenIDs[route.RouteID] {
			return invalid("route handoff is invalid")
		}
		seenHosts[host], seenIDs[route.RouteID] = true, true
	}
	return nil
}

func invalid(message string) error {
	return edgeerrors.New(edgeerrors.CodeBindingInvalid, message, "request a fresh admission")
}
