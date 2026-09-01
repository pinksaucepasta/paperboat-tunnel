package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	service, err := datacarrier.NewService(context.Background(), datacarrier.ServiceConfig{
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
		durableAttached := durableExpected != nil && durableExpected.HasIdentity(identity, time.Now().UTC())
		if durableAttached {
			publicKey, thumbprint, ok := durableExpected.MachineBinding(identity, time.Now().UTC())
			if !ok {
				return datacarrier.ErrDurableAdmissionMissing
			}
			admissions := durableExpected.ForIdentity(identity, time.Now().UTC())
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
			if err := durableRoutes.AttachReplica(server, publicKey, thumbprint, edgehttp.ReplicaState{Ready: true, Generation: identity.Generation, RouteIDs: routeIDs, HealthyRoutes: routeIDs, RouteBindings: routeBindings, FailureDomain: identity.HostID, Latency: time.Nanosecond, Capacity: deployment.NodeCapacity}); err != nil {
				return fmt.Errorf("attach durable carrier: %w", err)
			}
			defer func() { _ = durableRoutes.Detach(server) }()
		}
		previewAttached := len(previewExpected.ForIdentity(identity, time.Now().UTC())) != 0
		accessorAttached := accessorExpected != nil && accessorExpected.HasIdentity(identity, time.Now().UTC())
		if !previewAttached && !durableAttached && !accessorAttached {
			return datacarrier.ErrDurableAdmissionMissing
		}
		handlerCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		results := make(chan error, 2)
		workers := 0
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
	assembly, err := edgeruntime.NewDataCarrierAssemblyWithTelemetry(service, handle, maximumHandlers, nil, carrierTelemetry)
	if err != nil {
		_ = service.Close()
		return nil, nil, fmt.Errorf("create carrier assembly: %w", err)
	}
	return assembly, service.Close, nil
}
