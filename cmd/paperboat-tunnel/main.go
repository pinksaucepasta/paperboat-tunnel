package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/auth"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/config"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgefrp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/frpconfig"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/observability"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelayhttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalinghttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignalingprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/publicpreviewrelay"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	edgeruntime "github.com/pinksaucepasta/paperboat-tunnel/internal/runtime"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/store"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/stunserver"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}
	if cfg.DeploymentPath == "" {
		return errors.New("deployment-config is required")
	}
	deployment, err := config.LoadDeployment(cfg.DeploymentPath)
	if err != nil {
		return err
	}
	service, err := buildService(cfg, deployment)
	if err != nil {
		return err
	}
	root, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Start(root); err != nil {
		return err
	}
	var runtimeErr error
	select {
	case <-root.Done():
	case runtimeErr = <-service.Done():
		stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return runtimeErr
}

func buildService(cfg config.Config, deployment config.Deployment) (*edgeruntime.Service, error) {
	if deployment.CertificateDNSCredentialFile != "" {
		credential, err := os.ReadFile(deployment.CertificateDNSCredentialFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate DNS credential: %w", err)
		}
		if err := os.Setenv("CLOUDFLARE_API_TOKEN", strings.TrimSpace(string(credential))); err != nil {
			return nil, fmt.Errorf("configure certificate DNS credential: %w", err)
		}
	}
	credential, err := readCredential(deployment.ControlCredentialFile)
	if err != nil {
		return nil, fmt.Errorf("load control credential: %w", err)
	}
	trust, err := edgeruntime.LoadTrust(deployment.JWKSFile, deployment.RevocationsFile, deployment.UsageSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load trust: %w", err)
	}
	trust.Snapshot.ConfigureRevocationFreshness(3*deployment.ControlInterval, time.Now)
	tlsConfig, err := controlTLS(deployment.ControlCAFile)
	if err != nil {
		return nil, fmt.Errorf("load control TLS: %w", err)
	}
	client, err := control.NewHTTPClient(control.HTTPConfig{BaseURL: deployment.ControlURL, Credential: credential, Timeout: deployment.ControlTimeout, TLS: tlsConfig})
	if err != nil {
		return nil, fmt.Errorf("create control client: %w", err)
	}
	journal, counters, queue, err := restoreState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("restore edge state: %w", err)
	}
	epoch, err := usage.NewCounterEpoch()
	if err != nil {
		return nil, fmt.Errorf("create counter epoch: %w", err)
	}
	processEpoch, err := usage.NewCounterEpoch()
	if err != nil {
		return nil, fmt.Errorf("create process epoch: %w", err)
	}
	state := node.New(cfg.NodeID)
	manager, err := node.NewManager(state, deployment.NodeCapacity)
	if err != nil {
		return nil, fmt.Errorf("create node manager: %w", err)
	}
	routes := route.NewRegistry(deployment.PreviewBaseDomain, deployment.HelperBaseDomain)
	snapshotState := func() store.State {
		return store.State{Version: store.CurrentVersion, CounterEpoch: epoch, Operations: journal.Snapshot(), Counters: counters.Snapshot(), PendingUsage: queue.Snapshot()}
	}
	verifier := &auth.Verifier{Issuer: deployment.CredentialIssuer, NodeID: cfg.NodeID, Keys: trust.Snapshot, Revocations: trust.Snapshot, ClockSkew: 30 * time.Second}
	signalingService, err := peersignaling.New(peersignaling.Config{Authenticator: verifier, Validators: peersignalingprotocol.Factory{}, MaximumSessions: int(deployment.SignalingCapacity), MaximumConsumed: int(deployment.SignalingCapacity) * 4, QueueDepth: 128, MaximumMessage: peersignalingprotocol.MaximumMessage})
	if err != nil {
		return nil, fmt.Errorf("create peer signaling service: %w", err)
	}
	admissions := &admission.Service{Issuer: deployment.CredentialIssuer, Verifier: verifier, Authorizer: client, Journal: journal}
	adapter := edgefrp.NewAdapter(admissions, routes, deployment.NodeCapacity)
	previewRelay, err := publicpreviewrelay.New(admissions, routes)
	if err != nil {
		return nil, fmt.Errorf("create public preview relay: %w", err)
	}
	meter := &usage.Meter{Node: cfg.NodeID, Epoch: epoch, Counters: counters, Queue: queue, KeyID: trust.UsageKeyID, PrivateKey: trust.UsagePrivateKey, Persist: func() error {
		return store.Save(cfg.StatePath, snapshotState())
	}}
	if err := meter.RestoreBaseline(); err != nil {
		return nil, fmt.Errorf("restore usage baseline: %w", err)
	}
	adapter.Traffic = meter
	relayManager, err := peerrelay.NewManager(peerrelay.DevelopmentConfig(), peerrelay.MeterRecorder{Meter: meter}, nil)
	if err != nil {
		return nil, fmt.Errorf("create peer relay manager: %w", err)
	}
	internalToken, err := edgefrp.NewInternalAuthToken()
	if err != nil {
		return nil, fmt.Errorf("create internal frps token: %w", err)
	}
	vhostHost, vhostPortText, err := net.SplitHostPort(deployment.PrivateVhostAddress)
	if err != nil {
		return nil, fmt.Errorf("prepare process bundle: %w", err)
	}
	vhostPort, err := strconv.Atoi(vhostPortText)
	if err != nil {
		return nil, fmt.Errorf("assemble data plane: %w", err)
	}
	bundle, err := edgeruntime.PrepareBundle(edgeruntime.BundleSpec{
		Directory: filepath.Join(deployment.RuntimeDirectory, "config"), FRPSBinary: deployment.FRPSBinary, CaddyBinary: deployment.CaddyBinary, FRPSSHA256: deployment.FRPSSHA256, CaddySHA256: deployment.CaddySHA256, MaxOutputBytes: 1 << 20,
		FRPS:  frpconfig.Input{BindAddr: deployment.ConnectorBindAddress, BindPort: deployment.ConnectorTCPPort, QUICBindPort: deployment.ConnectorQUICPort, PrivateProxyAddr: vhostHost, VhostHTTPPort: vhostPort, HookAddr: deployment.HookAddress, HookPath: deployment.HookPath, StreamBrokerPath: filepath.Join(deployment.RuntimeDirectory, "config", "frps-stream.sock"), InternalAuthToken: internalToken, LogLevel: deployment.FRPSLogLevel, TCPMux: deployment.ConnectorTCPMux},
		Caddy: caddyconfig.Input{PreviewBaseDomain: deployment.PreviewBaseDomain, HelperBaseDomain: deployment.HelperBaseDomain, SignalingHost: deployment.SignalingHost, PrivateUpstream: deployment.EdgeGatewayAddress, ListenAddress: deployment.CaddyListenAddress, HTTPListenAddress: deployment.CaddyHTTPListenAddress, AdminAddress: deployment.CaddyAdminAddress, TrustedProxies: deployment.TrustedProxyCIDRs, IssuerModule: deployment.CertificateIssuer, DNSProvider: deployment.CertificateDNSProvider, CertificateAskURL: "http://" + deployment.EdgeGatewayAddress + "/private/certificate-ask", StreamBrokerPath: filepath.Join(deployment.RuntimeDirectory, "config", "frps-stream.sock"), PublicRoutes: publicCaddyRoutes(deployment.PublicRoutes)},
	})
	if err != nil {
		return nil, err
	}
	persistence := edgeruntime.Persistence{Path: cfg.StatePath, Restore: func(store.State) error { return nil }, Snapshot: snapshotState}
	_, stunPortText, err := net.SplitHostPort(deployment.STUNListenAddress)
	if err != nil {
		return nil, fmt.Errorf("parse STUN listen address: %w", err)
	}
	stunPort, err := strconv.ParseUint(stunPortText, 10, 16)
	if err != nil || stunPort == 0 {
		return nil, fmt.Errorf("parse STUN listen port")
	}
	nodeWorker := &edgeruntime.NodeWorker{Manager: manager, Sink: client, Registration: control.NodeRegistration{NodeID: cfg.NodeID, EdgePool: cfg.EdgePool, Artifact: bundle.FRPSMetadata.FRPVersion + "+" + bundle.CaddyMetadata.Version, Protocol: "1.0", ProcessEpoch: processEpoch, Capacity: deployment.NodeCapacity, Endpoint: control.ConnectorEndpoint{Host: deployment.ConnectorAdvertiseHost, TCPPort: uint16(deployment.ConnectorTCPPort), QUICPort: uint16(deployment.ConnectorQUICPort)}, SignalingHost: deployment.SignalingHost, STUNEndpoint: control.UDPEndpoint{Host: deployment.ConnectorAdvertiseHost, Port: uint16(stunPort)}}, Interval: deployment.ControlInterval}
	routeWorker := &edgeruntime.RouteWorker{Registry: routes, Source: client, Observer: client, State: state, NodeID: cfg.NodeID, Interval: deployment.ControlInterval}
	usageWorker := &edgeruntime.UsageWorker{Queue: queue, Sink: client, Prepare: meter, Persist: meter.Persist, Interval: 250 * time.Millisecond}
	metrics := observability.NewMetrics()
	tlsProbeHost := caddyProbeHost(deployment)
	controlDependency := &edgeruntime.ControlDependency{Source: client, TrustSource: client, ApplyTrust: trust.Snapshot.ReplaceRevocations, NodeID: cfg.NodeID, Interval: deployment.ControlInterval}
	trusted, err := edgehttp.ParseTrustedProxies(append(deployment.TrustedProxyCIDRs, "127.0.0.1/32"))
	if err != nil {
		return nil, fmt.Errorf("parse edge trusted proxies: %w", err)
	}
	previewTransport := &http.Transport{Proxy: nil, DialContext: previewRelay.DialContext, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	gateway, err := edgehttp.NewGatewayWithTransport(edgehttp.Config{PreviewBaseDomain: deployment.PreviewBaseDomain, HelperBaseDomain: deployment.HelperBaseDomain, TrustedProxies: trusted, MaxHeaderBytes: 32 << 10, MaxBodyBytes: 50 << 20, Readiness: previewRelay, HelperAccess: verifier, Revocations: trust.Snapshot, RevocationCheckInterval: deployment.ControlInterval}, deployment.PrivateVhostAddress, previewTransport)
	if err != nil {
		return nil, fmt.Errorf("create edge gateway: %w", err)
	}
	signalingHandler := peersignalinghttp.Handler{Path: "/v1/peer-signaling", Service: signalingService, ObserveError: func(err error) {
		log.Printf("peer signaling failed: %v", err)
	}}
	relayHandler := peerrelayhttp.Handler{Path: "/v1/peer-relay", Authenticator: verifier, Manager: relayManager, ObserveAttach: func(attachment peerrelayhttp.Attachment) {
		handle := sha256.Sum256(attachment.StreamHandle[:])
		log.Printf("peer relay attachment endpoint=%s role=%d carrier=%d handle=%x", attachment.EndpointID, attachment.Role, attachment.Carrier, handle[:8])
	}, ObserveError: func(err error) {
		log.Printf("peer relay failed: %v", err)
	}}
	previewRelayHandler := publicpreviewrelay.Handler{Manager: previewRelay, ObserveAttach: func(carrier string) {
		log.Printf("public preview relay attached carrier=%s", carrier)
	}}
	gatewayDispatch := peerServiceDispatch(deployment.SignalingHost, signalingHandler, relayHandler, previewRelayHandler, gateway)
	gatewayHandler := edgehttp.WithCertificateAsk(gatewayDispatch, adapter)
	assembly, err := edgeruntime.NewAssembly(edgeruntime.AssemblySpec{Persistence: persistence, Control: controlDependency, Node: nodeWorker, Routes: routeWorker, Usage: usageWorker, HookAddress: deployment.HookAddress, GatewayAddress: deployment.EdgeGatewayAddress, GatewayHandler: gatewayHandler, HookPath: deployment.HookPath, Policy: edgefrp.Policy{Adapter: adapter, Resolver: edgefrp.MetadataResolver{}, InternalAuthToken: internalToken}, HookReject: func(operation, reason string) {
		log.Printf("frp hook rejected operation=%s reason=%s", operation, reason)
	}, HookObserve: func(operation string, rejected bool) {
		if !rejected && (operation == "Login" || operation == "NewProxy") {
			log.Printf("frp hook accepted operation=%s", operation)
		}
		kind := map[string]observability.Kind{"Login": observability.Admission, "NewProxy": observability.Route, "NewUserConn": observability.Stream, "CloseUserConn": observability.Stream, "Traffic": observability.Usage, "CloseProxy": observability.Cleanup}[operation]
		if kind == "" {
			return
		}
		result := observability.Success
		if rejected {
			result = observability.Rejected
		}
		metrics.Add(observability.MetricKey{Kind: kind, Result: result}, 1)
	}, Bundle: bundle, CaddyReady: edgeruntime.Readiness{Probe: func() error {
		_, err := probeCaddyTLS(deployment.CaddyListenAddress, tlsProbeHost)
		return err
	}, Timeout: deployment.ControlTimeout + deployment.ControlInterval, Interval: 250 * time.Millisecond}})
	if err != nil {
		return nil, err
	}
	stunService, err := stunserver.New(stunserver.Config{Address: deployment.STUNListenAddress, AuthenticatePMTU: func(token string, _ netip.AddrPort) bool {
		return verifier.AuthenticatePMTU(context.Background(), token) == nil
	}})
	if err != nil {
		return nil, fmt.Errorf("create STUN service: %w", err)
	}
	health, err := observability.NewHandler(observability.Sources{
		Node:          state.Snapshot,
		Manager:       manager.Snapshot,
		Sessions:      func() int { return adapter.Stats().Sessions },
		SessionRoutes: func() int { return adapter.Stats().Routes },
		ActiveStreams: func() uint32 { return adapter.Stats().ActiveStreams },
		RouteCount:    func() int { return len(routes.Snapshot()) },
		Usage:         queue.Stats,
		ControlErr:    nodeWorker.LastError,
		RouteErr:      routeWorker.LastError,
		UsageErr:      usageWorker.LastError,
		FRPRunning:    assembly.FRPS.Running,
		CaddyRunning:  assembly.Caddy.Running,
		STUN: func() observability.STUNStats {
			stats := stunService.Stats()
			return observability.STUNStats{Running: stats.Running, Accepted: stats.Accepted, Rejected: stats.Rejected, Errors: stats.Errors}
		},
		Signaling: func() observability.SignalingStats {
			stats := signalingService.Stats()
			return observability.SignalingStats{Running: stats.Running, Sessions: stats.Sessions, Attachments: stats.Attachments, Capacity: stats.Capacity}
		},
		CaddyTLS: func() (time.Time, error) {
			return probeCaddyTLS(deployment.CaddyListenAddress, tlsProbeHost)
		},
		Events:  metrics.Snapshot,
		Traffic: counters.Snapshot,
	})
	if err != nil {
		return nil, fmt.Errorf("create private observability handler: %w", err)
	}
	service := edgeruntime.New(cfg, state, signalingService, relayLifecycle{manager: relayManager}, assembly, stunService)
	if err := service.SetHealthHandler(health); err != nil {
		return nil, err
	}
	return service, nil
}

func peerServiceDispatch(signalingHost string, signaling, relay, previewRelay, gateway http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := request.Host
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		if strings.ToLower(host) == signalingHost {
			if request.Method == http.MethodGet && request.URL.Path == "/network-check/v1" {
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set("X-Content-Type-Options", "nosniff")
				writer.WriteHeader(http.StatusNoContent)
				return
			}
			if request.URL.Path == "/v1/peer-signaling" {
				signaling.ServeHTTP(writer, request)
				return
			}
			if request.URL.Path == "/v1/peer-relay" {
				relay.ServeHTTP(writer, request)
				return
			}
			if request.URL.Path == publicpreviewrelay.Path {
				previewRelay.ServeHTTP(writer, request)
				return
			}
			http.NotFound(writer, request)
			return
		}
		gateway.ServeHTTP(writer, request)
	})
}

type relayLifecycle struct{ manager *peerrelay.Manager }

func (relayLifecycle) Start(context.Context) error { return nil }
func (r relayLifecycle) Shutdown(context.Context) error {
	if r.manager == nil {
		return nil
	}
	r.manager.BeginDrain()
	return r.manager.Close()
}

func publicCaddyRoutes(routes []config.PublicRoute) []caddyconfig.PublicRoute {
	result := make([]caddyconfig.PublicRoute, len(routes))
	for index, route := range routes {
		result[index] = caddyconfig.PublicRoute{Host: route.Host, PathPrefix: route.PathPrefix, StripPrefix: route.StripPrefix, Upstream: route.Upstream}
	}
	return result
}

func probeCaddyTLS(address, serverName string) (time.Time, error) {
	dialer := &net.Dialer{Timeout: time.Second}
	// The owned Caddy uses a private issuer. Verify its hostname and validity
	// explicitly while leaving chain trust to the private deployment boundary.
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, InsecureSkipVerify: true}) // #nosec G402
	if err != nil {
		return time.Time{}, err
	}
	defer connection.Close()
	certificates := connection.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return time.Time{}, errors.New("Caddy presented no certificate")
	}
	certificate := certificates[0]
	if err := certificate.VerifyHostname(serverName); err != nil {
		return certificate.NotAfter, err
	}
	now := time.Now().UTC()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return certificate.NotAfter, errors.New("Caddy certificate is outside its validity interval")
	}
	return certificate.NotAfter, nil
}

func caddyProbeHost(deployment config.Deployment) string {
	if len(deployment.PublicRoutes) > 0 {
		return deployment.PublicRoutes[0].Host
	}
	return deployment.SignalingHost
}

func controlTLS(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return &tls.Config{MinVersion: tls.VersionTLS13}, nil
	}
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("control CA file contains no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}, nil
}

func restoreState(path string) (*operation.Journal, *usage.Counters, *usage.Queue, error) {
	saved, err := store.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		journal, journalErr := operation.NewJournal(4096)
		queue, queueErr := usage.NewQueue(4096, 64<<20)
		return journal, usage.NewCounters(), queue, errors.Join(journalErr, queueErr)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	journal, err := operation.Restore(saved.Operations, 4096)
	if err != nil {
		return nil, nil, nil, err
	}
	queue, err := usage.RestoreQueue(saved.PendingUsage, 4096, 64<<20)
	return journal, usage.RestoreCounters(saved.Counters), queue, err
}

func readCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return "", errors.New("invalid control credential file")
	}
	data, err := os.ReadFile(path)
	value := strings.TrimSpace(string(data))
	if err != nil || len(value) < 32 || len(value) > 8192 {
		return "", errors.New("invalid control credential file")
	}
	return value, nil
}
