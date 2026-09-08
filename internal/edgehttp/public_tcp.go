package edgehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
)

var publicTCPRequestSequence atomic.Uint64

// ForwardPublicTCP forwards one connection already accepted by the listener
// named in a current server decision. Listener allocation and lifecycle remain
// with the caller. This method takes ownership of connection and closes it on return.
func (r *DataCarrierRouteRegistry) ForwardPublicTCP(ctx context.Context, connection net.Conn, decision connectorprotocol.IngressDecision, currentAuthority func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error)) error {
	if connection != nil {
		defer connection.Close()
	}
	now := time.Now().UTC()
	if r == nil || ctx == nil || connection == nil || currentAuthority == nil || decision.Validate(now) != nil || decision.Binding.Protocol != "tcp" || decision.Binding.Audience != "public" || decision.Binding.ListenerID == "" || decision.Binding.PublicPort == 0 {
		return ErrDataCarrierRouteInvalid
	}
	local, ok := connection.LocalAddr().(*net.TCPAddr)
	if !ok || local.Port != int(decision.Binding.PublicPort) {
		return ErrDataCarrierRouteInvalid
	}
	if _, ok := connection.(interface{ CloseWrite() error }); !ok {
		return ErrDataCarrierRouteInvalid
	}
	requestID := fmt.Sprintf("edge-tcp-%d", publicTCPRequestSequence.Add(1))
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: decision.Binding.AccountID, TunnelID: decision.Binding.TunnelID, ConnectorID: decision.ConnectorID, SessionID: decision.SessionID, ProcessGeneration: decision.ProcessGeneration, Generation: decision.ConfigGeneration, RouteID: decision.Binding.RouteID, RequestID: requestID, Kind: "tcp_public"}
	authority, err := resolvePublicTCPAuthority(ctx, currentAuthority, decision, open)
	if err != nil {
		return err
	}
	lease, err := r.AcquireIngress(ctx, authority)
	if err != nil {
		return err
	}
	defer lease.Release()
	identity := datacarrier.Identity{AccountID: open.AccountID, HostID: authority.Binding.HostID, TunnelID: open.TunnelID, ConnectorID: open.ConnectorID, SessionID: open.SessionID, ProcessGeneration: open.ProcessGeneration, Generation: open.Generation}
	r.mu.RLock()
	entry := r.byKey[carrierRouteIdentityKey(identity)]
	if r.closed || entry == nil || entry.server == nil {
		r.mu.RUnlock()
		return ErrDataCarrierRouteUnavailable
	}
	server := entry.server
	r.mu.RUnlock()
	stream, err := server.OpenStreamWithLifetime(ctx, ctx, open)
	if err != nil {
		return errors.Join(ErrDataCarrierRouteTransport, err)
	}
	defer stream.Close()
	if err := connectorprotocol.WriteIngressDecision(stream, authority, time.Now().UTC()); err != nil {
		return errors.Join(ErrDataCarrierRouteTransport, err)
	}
	applicationStream := lease.Wrap(ctx, stream)
	defer applicationStream.Close()
	return bridgePublicTCP(ctx, connection, applicationStream, authority, open, currentAuthority)
}

func resolvePublicTCPAuthority(ctx context.Context, current func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error), decision connectorprotocol.IngressDecision, open connectorprotocol.StreamOpen) (connectorprotocol.IngressDecision, error) {
	resolveCtx, cancel := context.WithDeadline(ctx, decision.ExpiresAt)
	defer cancel()
	authority, err := current(resolveCtx, decision)
	now := time.Now().UTC()
	if err != nil || decision.Authorize(authority, open, decision.EdgeNodeID, decision.EdgeProcessEpoch, now) != nil || authority.Binding.Protocol != "tcp" || authority.Binding.Audience != "public" {
		return connectorprotocol.IngressDecision{}, connectorprotocol.ErrIngressDenied
	}
	return authority, nil
}

func bridgePublicTCP(ctx context.Context, connection net.Conn, stream io.ReadWriteCloser, authority connectorprotocol.IngressDecision, open connectorprotocol.StreamOpen, current func(context.Context, connectorprotocol.IngressDecision) (connectorprotocol.IngressDecision, error)) error {
	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	closed := make(chan struct{})
	go func() {
		select {
		case <-bridgeCtx.Done():
			_ = connection.Close()
			_ = stream.Close()
		case <-closed:
		}
	}()
	authorityFailed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(connectorprotocol.IngressRefreshInterval)
		defer ticker.Stop()
		active := authority
		for {
			expires := time.NewTimer(time.Until(active.ExpiresAt))
			select {
			case <-bridgeCtx.Done():
				expires.Stop()
				return
			case <-expires.C:
				authorityFailed <- connectorprotocol.ErrIngressDenied
				cancel()
				return
			case <-ticker.C:
				expires.Stop()
				refreshed, err := resolvePublicTCPAuthority(bridgeCtx, current, active, open)
				if err != nil {
					authorityFailed <- err
					cancel()
					return
				}
				active = refreshed
			}
		}
	}()
	results := make(chan error, 2)
	copyDirection := func(destination io.Writer, source io.Reader, closeWrite func() error) {
		_, copyErr := io.Copy(destination, source)
		copyErr = errors.Join(copyErr, closeWrite())
		results <- copyErr
	}
	streamCloseWrite := func() error { return nil }
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		streamCloseWrite = closer.CloseWrite
	}
	connectionCloseWrite := func() error { return nil }
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		connectionCloseWrite = closer.CloseWrite
	}
	go copyDirection(stream, connection, streamCloseWrite)
	go copyDirection(connection, stream, connectionCloseWrite)
	first := <-results
	if first != nil {
		_ = connection.Close()
		_ = stream.Close()
	}
	second := <-results
	close(closed)
	cancel()
	select {
	case err := <-authorityFailed:
		return errors.Join(connectorprotocol.ErrIngressDenied, err, first, second)
	default:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(first, second)
}
