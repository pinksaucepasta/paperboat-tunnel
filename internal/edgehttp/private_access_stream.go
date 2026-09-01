package edgehttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

var ErrPrivateAccessStreamInvalid = errors.New("invalid private access stream bridge")

type PrivateAccessTarget interface {
	OpenPrivateAccessTarget(context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error)
}

type privateAccessTargetWithLifetime interface {
	OpenPrivateAccessTargetWithLifetime(context.Context, context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error)
}

type PrivateAccessTargetFunc func(context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error)

func (f PrivateAccessTargetFunc) OpenPrivateAccessTarget(ctx context.Context, request connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
	if f == nil {
		return nil, ErrPrivateAccessStreamInvalid
	}
	return f(ctx, request)
}

type PrivateAccessStreamBridgeConfig struct {
	Authorizer       control.PrivateAccessGrantAuthorizer
	Target           PrivateAccessTarget
	MaximumStreams   int
	AuthorizeTimeout time.Duration
	OpenTimeout      time.Duration
	Clock            func() time.Time
}

type PrivateAccessStreamBridge struct {
	authorizer       control.PrivateAccessGrantAuthorizer
	target           PrivateAccessTarget
	maximum          int
	authorizeTimeout time.Duration
	openTimeout      time.Duration
	clock            func() time.Time
}

func NewPrivateAccessStreamBridge(config PrivateAccessStreamBridgeConfig) (*PrivateAccessStreamBridge, error) {
	if config.Authorizer == nil || config.Target == nil {
		return nil, ErrPrivateAccessStreamInvalid
	}
	if config.MaximumStreams == 0 {
		config.MaximumStreams = 256
	}
	if config.AuthorizeTimeout == 0 {
		config.AuthorizeTimeout = 10 * time.Second
	}
	if config.OpenTimeout == 0 {
		config.OpenTimeout = 10 * time.Second
	}
	if config.MaximumStreams < 1 || config.MaximumStreams > 4096 || config.AuthorizeTimeout <= 0 || config.AuthorizeTimeout > time.Minute || config.OpenTimeout <= 0 || config.OpenTimeout > time.Minute {
		return nil, ErrPrivateAccessStreamInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &PrivateAccessStreamBridge{authorizer: config.Authorizer, target: config.Target, maximum: config.MaximumStreams, authorizeTimeout: config.AuthorizeTimeout, openTimeout: config.OpenTimeout, clock: config.Clock}, nil
}

func (b *PrivateAccessStreamBridge) Serve(ctx context.Context, server *datacarrier.Server) error {
	if b == nil || ctx == nil || server == nil {
		return ErrPrivateAccessStreamInvalid
	}
	permits := make(chan struct{}, b.maximum)
	var streams sync.WaitGroup
	defer streams.Wait()
	for {
		select {
		case permits <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		case <-server.Done():
			return nil
		}
		stream, metadata, err := server.AcceptAccessStream(ctx)
		if err != nil {
			<-permits
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			select {
			case <-server.Done():
				return nil
			default:
				return err
			}
		}
		streams.Add(1)
		identity := server.Identity()
		go func() {
			defer streams.Done()
			defer func() { <-permits }()
			b.serveStream(ctx, stream, metadata, identity)
		}()
	}
}

func (b *PrivateAccessStreamBridge) serveStream(parent context.Context, stream *datacarrier.Stream, metadata connectorprotocol.StreamOpen, identity datacarrier.Identity) {
	if stream == nil {
		return
	}
	defer stream.Close()
	now := b.clock().UTC()
	open, err := connectorprotocol.ReadPrivateAccessOpen(stream, now)
	if err != nil || !privateAccessMetadataMatches(metadata, open.Request, identity) {
		_ = connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: http.StatusUnauthorized})
		return
	}
	authorizeCtx, cancelAuthorize := context.WithTimeout(parent, b.authorizeTimeout)
	decision, err := b.authorizer.AuthorizePrivateAccessGrant(authorizeCtx, open.Grant, open.Request)
	cancelAuthorize()
	if err != nil {
		_ = connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: privateAccessErrorStatus(err)})
		return
	}
	if !decision.Allowed || !decision.ExpiresAt.After(b.clock().UTC()) {
		_ = connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: http.StatusForbidden})
		return
	}
	lifetime, cancelLifetime := context.WithDeadline(parent, decision.ExpiresAt)
	defer cancelLifetime()
	openCtx, cancelOpen := context.WithTimeout(lifetime, b.openTimeout)
	var target io.ReadWriteCloser
	if lifetimeTarget, ok := b.target.(privateAccessTargetWithLifetime); ok {
		target, err = lifetimeTarget.OpenPrivateAccessTargetWithLifetime(openCtx, lifetime, open.Request)
	} else {
		target, err = b.target.OpenPrivateAccessTarget(openCtx, open.Request)
	}
	cancelOpen()
	if err != nil || target == nil {
		if target != nil {
			_ = target.Close()
		}
		_ = connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: http.StatusServiceUnavailable})
		return
	}
	defer target.Close()
	if err := connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: http.StatusOK, ExpiresAt: decision.ExpiresAt}); err != nil {
		return
	}
	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, stream); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, target); copyDone <- struct{}{} }()
	select {
	case <-copyDone:
	case <-lifetime.Done():
	}
}

func privateAccessMetadataMatches(metadata connectorprotocol.StreamOpen, request connectorprotocol.PrivateAccessRequest, identity datacarrier.Identity) bool {
	wantKind := connectorprotocol.PrivateAccessHTTP
	if request.Protocol == "tcp" {
		wantKind = connectorprotocol.PrivateAccessTCP
	}
	return identity.AccountID == request.AccountID && identity.HostID == request.DeviceID && identity.TunnelID == metadata.TunnelID && identity.ConnectorID == metadata.ConnectorID && identity.SessionID == metadata.SessionID && identity.ProcessGeneration == metadata.ProcessGeneration && identity.Generation == metadata.Generation && metadata.Kind == wantKind && metadata.AccountID == request.AccountID && metadata.RouteID == request.RouteID && metadata.SessionID == request.CarrierSessionID && metadata.ProcessGeneration == request.ProcessGeneration && metadata.Generation == request.ConfigGeneration && metadata.RequestID == request.RequestID
}

func privateAccessErrorStatus(err error) int {
	switch {
	case errors.Is(err, control.ErrPrivateAccessGrantUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, control.ErrPrivateAccessGrantForbidden):
		return http.StatusForbidden
	default:
		return http.StatusServiceUnavailable
	}
}

type PrivateAccessCaddyTarget struct {
	Address     string
	Dialer      *net.Dialer
	Connections *PrivateAccessConnectionRegistry
}

func (t PrivateAccessCaddyTarget) OpenPrivateAccessTarget(ctx context.Context, request connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
	if ctx == nil || request.Protocol != "http" {
		return nil, ErrPrivateAccessStreamInvalid
	}
	host, port, err := net.SplitHostPort(t.Address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || port == "" || port == "0" {
		return nil, ErrPrivateAccessStreamInvalid
	}
	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	connection, err := dialer.DialContext(ctx, "tcp", t.Address)
	if err != nil {
		return nil, err
	}
	if t.Connections == nil {
		_ = connection.Close()
		return nil, ErrPrivateAccessStreamInvalid
	}
	token, err := t.Connections.Register(connection.LocalAddr().String(), request, request.ExpiresAt)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &registeredPrivateConnection{Conn: connection, registry: t.Connections, address: connection.LocalAddr().String(), token: token}, nil
}

var _ PrivateAccessTarget = PrivateAccessCaddyTarget{}

// PrivateAccessRouteTarget keeps HTTP on loopback-only Caddy and sends raw
// TCP only to the exact authenticated durable private_tcp carrier route.
type PrivateAccessRouteTarget struct {
	HTTP   PrivateAccessTarget
	Routes interface {
		CanonicalSnapshot() (uint64, []route.RouteRule, bool)
	}
	Carriers *DataCarrierRouteRegistry
}

func (t PrivateAccessRouteTarget) OpenPrivateAccessTarget(ctx context.Context, request connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
	return t.OpenPrivateAccessTargetWithLifetime(ctx, ctx, request)
}

func (t PrivateAccessRouteTarget) OpenPrivateAccessTargetWithLifetime(openCtx, lifetimeCtx context.Context, request connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
	if request.Protocol == "http" {
		if t.HTTP == nil {
			return nil, ErrPrivateAccessStreamInvalid
		}
		return t.HTTP.OpenPrivateAccessTarget(openCtx, request)
	}
	if request.Protocol != "tcp" || request.ResourceKind != "tunnel" || request.Audience != "paperboat-tunnel-tcp" || t.Routes == nil || t.Carriers == nil {
		return nil, ErrPrivateAccessStreamInvalid
	}
	_, rules, ok := t.Routes.CanonicalSnapshot()
	if !ok {
		return nil, ErrPrivateAccessStreamInvalid
	}
	matched, err := privateTCPRule(rules, request)
	if err != nil {
		return nil, err
	}
	return t.Carriers.openExactAssignmentWithTimeout(openCtx, lifetimeCtx, matched, request.RequestID)
}

func privateTCPRule(rules []route.RouteRule, request connectorprotocol.PrivateAccessRequest) (route.RouteRule, error) {
	var matched *route.RouteRule
	for i := range rules {
		rule := &rules[i]
		if privateTCPRuleMatches(*rule, request) {
			if matched != nil {
				return route.RouteRule{}, ErrPrivateAccessStreamInvalid
			}
			matched = rule
		}
	}
	if matched == nil {
		return route.RouteRule{}, ErrPrivateAccessStreamInvalid
	}
	return *matched, nil
}

func privateTCPRuleMatches(rule route.RouteRule, request connectorprotocol.PrivateAccessRequest) bool {
	return rule.RouteID == request.RouteID && rule.Kind == route.TunnelPrivateTCP && rule.AccountID == request.AccountID && rule.TunnelID == request.ResourceID && rule.ConnectorID == request.ConnectorID && rule.ConnectorSessionID == request.CarrierSessionID && rule.RouteGeneration == request.RouteGeneration && rule.SessionGeneration == request.SessionGeneration && rule.ConnectorProcessGeneration == request.ProcessGeneration && rule.ConfigGeneration == request.ConfigGeneration && rule.AssignmentGeneration == request.AssignmentGeneration && rule.Node == request.EdgeNodeID && rule.EdgeProcessEpoch == request.EdgeProcessEpoch && rule.AccessMode == "private" && rule.Protocol == "private_tcp"
}

var _ PrivateAccessTarget = PrivateAccessRouteTarget{}
