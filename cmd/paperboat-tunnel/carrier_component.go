package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	edgeruntime "github.com/pinksaucepasta/paperboat-tunnel/internal/runtime"
)

func newCarrierComponentWithTelemetry(
	deployment config.Deployment,
	serverCertificate tls.Certificate,
	previewExpected *datacarrier.ExpectedAdmissionRegistry,
	durableExpected *datacarrier.DurableAdmissionRegistry,
	accessorExpected *datacarrier.DurableAdmissionRegistry,
	previewHandle edgeruntime.CarrierHandler,
	durableRoutes *edgehttp.DataCarrierRouteRegistry,
	privateAccess *edgehttp.PrivateAccessStreamBridge,
	carrierTelemetry *datacarrier.CarrierTelemetry,
) (edgeruntime.Component, func() error, error) {
	if previewExpected == nil || previewHandle == nil {
		return nil, nil, errors.New("preview carrier admission and handler are required")
	}
	if durableExpected == nil && durableRoutes != nil || durableExpected != nil && durableRoutes == nil {
		return nil, nil, errors.New("durable carrier admission and route registry are required")
	}
	if deployment.CarrierTCPListenAddress == "" || deployment.CarrierQUICListenAddress == "" {
		return nil, nil, errors.New("canonical carrier requires both carrier_tcp_listen_address and carrier_quic_listen_address")
	}
	if len(serverCertificate.Certificate) == 0 || serverCertificate.PrivateKey == nil {
		return nil, nil, errors.New("canonical carrier requires a process-bound server certificate")
	}
	bindings := []datacarrier.PeerBinding{previewExpected.PeerBinding}
	if durableExpected != nil {
		bindings = append(bindings, durableExpected.PeerBinding)
	}
	if accessorExpected != nil {
		bindings = append(bindings, accessorExpected.PeerBinding)
	}
	peerBinding := datacarrier.AnyPeerBinding(bindings...)
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		// The connector's leaf is self-signed and its public key is the
		// enrolled machine identity. The admission registries perform the
		// exact public-key and CarrierIdentityURN checks below.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if _, err := peerBinding(state); err != nil {
				return fmt.Errorf("carrier machine identity is not admitted: %w", err)
			}
			return nil
		},
	}
	carrierConfig := datacarrier.DefaultConfig()
	authorizers := []datacarrier.Authorizer{previewExpected}
	if durableExpected != nil {
		authorizers = append(authorizers, durableExpected)
	}
	if accessorExpected != nil {
		authorizers = append(authorizers, accessorExpected)
	}
	carrierConfig.Authorize = datacarrier.AnyAuthorizer(authorizers...)
	service, err := datacarrier.NewHTTPService(context.Background(), datacarrier.ServiceConfig{
		Carrier: carrierConfig,
		TCP:     &datacarrier.EndpointConfig{Address: deployment.CarrierTCPListenAddress, TLS: tlsConfig, PeerBinding: peerBinding},
		QUIC:    &datacarrier.EndpointConfig{Address: deployment.CarrierQUICListenAddress, TLS: tlsConfig, PeerBinding: peerBinding},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create carrier service: %w", err)
	}
	maximumHandlers := 1024
	if deployment.NodeCapacity < uint32(maximumHandlers) {
		maximumHandlers = int(deployment.NodeCapacity)
	}
	if maximumHandlers == 0 {
		maximumHandlers = 64
	}
	handle := func(ctx context.Context, server *datacarrier.Server) error {
		identity := server.Identity()
		slog.Info("carrier session accepted", "account_id", identity.AccountID, "host_id", identity.HostID, "tunnel_id", identity.TunnelID, "connector_id", identity.ConnectorID, "session_id", identity.SessionID, "process_generation", identity.ProcessGeneration, "config_generation", identity.Generation)
		durableRegistered := false
		syncDurable := func(now time.Time) error {
			if durableExpected == nil || !durableExpected.HasIdentity(identity, now) {
				if durableRegistered {
					_ = durableRoutes.Detach(server)
					durableRegistered = false
				}
				return nil
			}
			publicKey, thumbprint, ok := durableExpected.MachineBinding(identity, now)
			if !ok {
				return datacarrier.ErrDurableAdmissionMissing
			}
			admissions := durableExpected.ForIdentity(identity, now)
			routeIDs := make([]string, 0, len(admissions))
			routeBindings := make([]edgehttp.ReplicaRouteBinding, 0, len(admissions))
			for _, admission := range admissions {
				if admission.State == "active" || admission.State == "staged" {
					routeIDs = append(routeIDs, admission.RouteID)
					routeBindings = append(routeBindings, edgehttp.ReplicaRouteBinding{RouteID: admission.RouteID, AssignmentID: admission.AssignmentID, AssignmentGeneration: admission.AssignmentGeneration, RouteGeneration: admission.RouteGeneration, ConfigContentHash: admission.ConfigContentHash})
				}
			}
			if len(routeIDs) == 0 {
				return datacarrier.ErrDurableAdmissionMissing
			}
			state := edgehttp.ReplicaState{Ready: true, Generation: identity.Generation, RouteIDs: routeIDs, HealthyRoutes: routeIDs, RouteBindings: routeBindings, FailureDomain: identity.HostID, Latency: time.Nanosecond, Capacity: deployment.NodeCapacity}
			if durableRegistered {
				if err := durableRoutes.UpdateReplicaState(server, state); err != nil {
					return fmt.Errorf("refresh durable carrier: %w", err)
				}
				return nil
			}
			if err := durableRoutes.AttachReplica(server, publicKey, thumbprint, state); err != nil {
				return fmt.Errorf("attach durable carrier: %w", err)
			}
			slog.Info("carrier promoted to durable routes", "tunnel_id", identity.TunnelID, "connector_id", identity.ConnectorID, "session_id", identity.SessionID, "routes", len(routeIDs))
			durableRegistered = true
			return nil
		}
		previewAttached := len(previewExpected.ForIdentity(identity, time.Now().UTC())) != 0
		durableAuthorized := durableExpected != nil && durableExpected.HasIdentity(identity, time.Now().UTC())
		accessorAttached := accessorExpected != nil && accessorExpected.HasIdentity(identity, time.Now().UTC())
		// Preview-only carriers do not participate in the durable route
		// lifecycle. Accessor carriers remain eligible for in-place durable
		// promotion because one authenticated connector may legitimately own
		// both ephemeral preview and durable routes.
		durableLifecycle := durableAuthorized || accessorAttached
		if durableLifecycle {
			if err := syncDurable(time.Now().UTC()); err != nil {
				return err
			}
		}
		if !previewAttached && !durableAuthorized && !accessorAttached {
			return datacarrier.ErrDurableAdmissionMissing
		}
		if durableRoutes != nil {
			defer func() { _ = durableRoutes.Detach(server) }()
		}
		handlerCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		results := make(chan error, 3)
		workers := 0
		if durableLifecycle {
			workers++
			go func() {
				ticker := time.NewTicker(deployment.ControlInterval)
				defer ticker.Stop()
				for {
					select {
					case <-handlerCtx.Done():
						results <- handlerCtx.Err()
						return
					case now := <-ticker.C:
						if err := syncDurable(now.UTC()); err != nil {
							results <- err
							return
						}
					}
				}
			}()
		}
		if privateAccess != nil {
			workers++
			go func() { results <- privateAccess.Serve(handlerCtx, server) }()
		}
		if previewAttached {
			workers++
			go func() { results <- previewHandle(handlerCtx, server) }()
		}
		if workers != 0 {
			select {
			case err := <-results:
				return err
			case <-server.Done():
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-server.Done():
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	assembly, err := edgeruntime.NewCarrierAssembly(edgeruntime.CarrierAssemblyConfig{Service: service, Handle: handle, MaximumHandlers: maximumHandlers, Telemetry: carrierTelemetry})
	if err != nil {
		_ = service.Close()
		return nil, nil, fmt.Errorf("create carrier assembly: %w", err)
	}
	return assembly, service.Close, nil
}
