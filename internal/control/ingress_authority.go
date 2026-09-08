package control

import (
	"context"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

// IngressAuthority caches only the server's bounded decision lifetime. Fetches
// coalesce per edge process; a failed refresh cannot extend cached authority.
type IngressAuthority struct {
	Client       *HTTPClient
	NodeID       string
	ProcessEpoch string
	mu           sync.Mutex
	decisions    []connectorprotocol.IngressDecision
	fetched      time.Time
}

func (a *IngressAuthority) Snapshot(ctx context.Context) ([]connectorprotocol.IngressDecision, error) {
	if a == nil || a.Client == nil || ctx == nil {
		return nil, ErrControlInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	if a.fetched.IsZero() || now.Sub(a.fetched) >= connectorprotocol.IngressRefreshInterval {
		fetch, cancel := context.WithTimeout(ctx, 2*time.Second)
		decisions, err := a.Client.IngressDecisions(fetch, a.NodeID, a.ProcessEpoch)
		cancel()
		if err != nil {
			a.decisions = nil
			a.fetched = time.Time{}
			return nil, err
		}
		a.decisions, a.fetched = decisions, now
	}
	return append([]connectorprotocol.IngressDecision(nil), a.decisions...), nil
}

func (a *IngressAuthority) ResolveDecision(ctx context.Context, candidate connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error) {
	decisions, err := a.Snapshot(ctx)
	if err != nil {
		return connectorprotocol.IngressDecision{}, err
	}
	now := time.Now().UTC()
	for _, current := range decisions {
		open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: candidate.Binding.AccountID, TunnelID: candidate.Binding.TunnelID, ConnectorID: candidate.ConnectorID, SessionID: candidate.SessionID, ProcessGeneration: candidate.ProcessGeneration, Generation: candidate.ConfigGeneration, RouteID: candidate.Binding.RouteID, RequestID: "tcp-authority-refresh", Kind: "tcp_public"}
		if candidate.Authorize(current, open, a.NodeID, a.ProcessEpoch, now) == nil {
			return current, nil
		}
	}
	return connectorprotocol.IngressDecision{}, connectorprotocol.ErrIngressDenied
}

func (a *IngressAuthority) Resolve(ctx context.Context, r route.RouteRule) (connectorprotocol.IngressDecision, error) {
	if a == nil || a.Client == nil || ctx == nil {
		return connectorprotocol.IngressDecision{}, ErrControlInvalid
	}
	decisions, err := a.Snapshot(ctx)
	if err != nil {
		return connectorprotocol.IngressDecision{}, err
	}
	id := r.RouteID
	if id == "" {
		id = r.ID
	}
	for _, d := range decisions {
		if d.Binding.RouteID == id && d.Binding.TunnelID == r.TunnelID && d.Binding.AccountID == r.AccountID && d.ConnectorID == r.ConnectorID && d.SessionID == r.ConnectorSessionID && d.ProcessGeneration == r.ConnectorProcessGeneration && d.ConfigGeneration == r.ConfigGeneration && d.AssignmentGeneration == r.AssignmentGeneration && d.Binding.RouteGeneration == r.RouteGeneration && d.Validate(time.Now().UTC()) == nil {
			return d, nil
		}
	}
	return connectorprotocol.IngressDecision{}, connectorprotocol.ErrIngressDenied
}
