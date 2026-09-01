package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgehttp"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type trk36SoakReport struct {
	Schema                    string             `json:"schema"`
	StartedAt                 time.Time          `json:"started_at"`
	FinishedAt                time.Time          `json:"finished_at"`
	ConfiguredDuration        time.Duration      `json:"configured_duration_ns"`
	Samples                   int                `json:"samples"`
	Bytes                     int64              `json:"bytes"`
	Errors                    int                `json:"errors"`
	ConnectorReplacements     int                `json:"connector_replacements"`
	StableEndpointChecks      int                `json:"stable_endpoint_checks"`
	StableEndpointFailures    int                `json:"stable_endpoint_failures"`
	MaximumActiveStreams      int                `json:"maximum_active_streams"`
	OpenLatency               trk36LatencyReport `json:"open_latency"`
	RecoveryLatency           trk36LatencyReport `json:"recovery_latency"`
	GoroutinesBefore          int                `json:"goroutines_before"`
	GoroutinesAfter           int                `json:"goroutines_after"`
	HeapBytesBefore           uint64             `json:"heap_bytes_before"`
	HeapBytesAfter            uint64             `json:"heap_bytes_after"`
	HeapBytesMaximum          uint64             `json:"heap_bytes_maximum"`
	FinalAdmissionCount       int                `json:"final_admission_count"`
	FinalCarrierReplicaCount  int                `json:"final_carrier_replica_count"`
	FinalCarrierActiveStreams int                `json:"final_carrier_active_streams"`
	Exclusions                []string           `json:"exclusions"`
}

type trk36LatencyReport struct {
	Count int           `json:"count"`
	P50   time.Duration `json:"p50_ns"`
	P95   time.Duration `json:"p95_ns"`
	P99   time.Duration `json:"p99_ns"`
	Max   time.Duration `json:"max_ns"`
}

// TestTRK36SustainedPreviewTunnelSoak keeps real route, yamux carrier,
// origin-stream, wildcard matcher, and replacement lifecycles active for a
// sustained interval. It is opt-in so the ordinary unit gate stays bounded.
func TestTRK36SustainedPreviewTunnelSoak(t *testing.T) {
	if os.Getenv("PAPERBOAT_TRK36_SOAK") != "1" {
		t.Skip("set PAPERBOAT_TRK36_SOAK=1 to run the sustained soak")
	}
	duration := trk36DurationEnv(t, "PAPERBOAT_TRK36_SOAK_DURATION", 30*time.Second, time.Second, 15*time.Minute)
	replacementEvery := trk36IntEnv(t, "PAPERBOAT_TRK36_REPLACEMENT_EVERY", 100, 5, 10000)
	payloadBytes := trk36IntEnv(t, "PAPERBOAT_TRK36_PAYLOAD_BYTES", 32<<10, 1024, 1<<20)

	publicKey, thumbprint := durableWorkerIdentity(t)
	assignment := durableWorkerAssignment(publicKey, thumbprint, "route_trk36_soak", "assignment_trk36_1", route.TunnelHTTPSWSS)
	assignment.DomainBindings = []control.DomainBinding{
		{ID: "domain_trk36_exact", Hostname: "exact.soak.example.test", MatchType: route.MatchExact, Generation: 1},
		{ID: "domain_trk36_wildcard", Hostname: "*.apps.soak.example.test", MatchType: route.MatchOneLabelWildcard, Generation: 1},
	}
	source := &trk35IntegrationRouteSource{snapshot: control.RouteSnapshot{Routes: []control.RouteAssignment{assignment}, Complete: true, Canonical: true}}
	observer := &trk35IntegrationRouteObserver{}
	canonical, err := route.NewRegistryWithOptions("", "", route.GenerationRegistryOptions{MaximumStreams: 32})
	if err != nil {
		t.Fatal(err)
	}
	durableAdmissions, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: "edge_1", ProcessEpoch: "edge_epoch_1"})
	if err != nil {
		t.Fatal(err)
	}
	carrierRoutes, err := edgehttp.NewDataCarrierRouteRegistry(edgehttp.DataCarrierRouteRegistryConfig{MaximumRoutes: 32})
	if err != nil {
		t.Fatal(err)
	}
	carrier := &trk35IntegrationCarrier{registry: carrierRoutes}
	edgeState := node.New("edge_1")
	if !edgeState.MarkReady() {
		t.Fatal("edge did not become ready")
	}
	worker := &RouteWorker{
		Registry: canonical, Source: source, Observer: observer, State: edgeState,
		NodeID: "edge_1", ProcessEpoch: "edge_epoch_1", Carrier: carrier,
		DurableAdmissions: durableAdmissions, Pulse: make(chan time.Time), DrainTimeout: time.Second,
	}

	pairs := trk36AttachReplicas(t, assignment, durableAdmissions, carrierRoutes, 1)
	cleanupComplete := false
	t.Cleanup(func() {
		if !cleanupComplete {
			_ = worker.Shutdown(context.Background())
			for _, pair := range pairs {
				_ = carrierRoutes.Detach(pair.server)
				_ = pair.Close()
			}
		}
		_ = carrierRoutes.Close()
		_ = durableAdmissions.Close()
		_ = canonical.Close()
	})

	started := time.Now().UTC()
	var before goruntime.MemStats
	goruntime.GC()
	goruntime.ReadMemStats(&before)
	report := trk36SoakReport{
		Schema: "paperboat.trk36-soak/v1", StartedAt: started, ConfiguredDuration: duration,
		GoroutinesBefore: goruntime.NumGoroutine(), HeapBytesBefore: before.HeapAlloc,
		Exclusions: []string{
			"dashboard and live-browser execution excluded by user direction",
			"host reboot restoration requires a native remote host and is not counted by this local edge harness",
		},
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("start route worker: %v", err)
	}
	if got := canonical.Generation(); got != 1 {
		t.Fatalf("initial route generation = %d, want 1", got)
	}

	deadline := time.Now().Add(duration)
	payload := make([]byte, payloadBytes)
	for index := range payload {
		payload[index] = byte(index % 251)
	}
	openLatencies := make([]time.Duration, 0, 4096)
	recoveryLatencies := make([]time.Duration, 0, 128)
	for time.Now().Before(deadline) {
		requestID := fmt.Sprintf("trk36_request_%d", report.Samples+1)
		host := assignment.PublicHost
		switch report.Samples % 3 {
		case 1:
			host = "exact.soak.example.test"
		case 2:
			host = "app.apps.soak.example.test"
		}
		requestStarted := time.Now()
		requestContext, cancelRequest := context.WithTimeout(context.Background(), 5*time.Second)
		lease, match, acquireErr := canonical.Acquire(requestContext, host, "/stream/chunk")
		if acquireErr != nil {
			cancelRequest()
			report.Errors++
			t.Fatalf("sample %d acquire: %v", report.Samples, acquireErr)
		}
		if match.Rule.RouteID != assignment.RouteID || match.Rule.AssignmentID != assignment.AssignmentID {
			report.StableEndpointFailures++
			_ = lease.Close()
			cancelRequest()
			t.Fatalf("sample %d matched stale endpoint: %+v", report.Samples, match.Rule)
		}
		report.StableEndpointChecks++
		stream, openErr := carrier.OpenRouteStream(requestContext, match.Rule, requestID)
		if openErr != nil {
			_ = lease.Close()
			cancelRequest()
			report.Errors++
			t.Fatalf("sample %d open carrier stream: %v", report.Samples, openErr)
		}
		hostStream, acceptErr := pairs[0].waitHeld(requestContext, requestID)
		if acceptErr != nil {
			_ = stream.Close()
			_ = lease.Close()
			cancelRequest()
			report.Errors++
			t.Fatalf("sample %d accept origin stream: %v", report.Samples, acceptErr)
		}
		if active := trk36ActiveStreams(pairs); active > report.MaximumActiveStreams {
			report.MaximumActiveStreams = active
		}
		openLatencies = append(openLatencies, time.Since(requestStarted))
		written, writeErr := stream.Write(payload)
		closeErr := stream.Close()
		_ = hostStream.Close()
		_ = lease.Close()
		cancelRequest()
		if writeErr != nil || written != len(payload) || closeErr != nil {
			report.Errors++
			t.Fatalf("sample %d streaming write=%d/%d write_err=%v close_err=%v", report.Samples, written, len(payload), writeErr, closeErr)
		}
		report.Samples++
		report.Bytes += int64(written)
		if report.Samples%replacementEvery == 0 {
			next := trk36NextAssignment(assignment, uint64(report.ConnectorReplacements+2))
			nextPairs := trk36AttachReplicas(t, next, durableAdmissions, carrierRoutes, 1)
			recoveryStarted := time.Now()
			source.setSnapshot(control.RouteSnapshot{Routes: []control.RouteAssignment{assignment, next}, Complete: true, Canonical: true})
			if err := worker.reconcile(context.Background()); err != nil {
				report.Errors++
				t.Fatalf("replace generation %d: %v", next.ConfigGeneration, err)
			}
			recoveryLatencies = append(recoveryLatencies, time.Since(recoveryStarted))
			for _, pair := range pairs {
				if err := carrierRoutes.Detach(pair.server); err != nil {
					t.Fatalf("detach old replica: %v", err)
				}
				if err := pair.Close(); err != nil {
					t.Fatalf("close old replica: %v", err)
				}
			}
			assignment = next
			assignment.State = "active"
			pairs = nextPairs
			source.setSnapshot(control.RouteSnapshot{Routes: []control.RouteAssignment{assignment}, Complete: true, Canonical: true})
			if err := worker.reconcile(context.Background()); err != nil {
				t.Fatalf("settle generation %d: %v", assignment.ConfigGeneration, err)
			}
			report.ConnectorReplacements++
		}

		var current goruntime.MemStats
		goruntime.ReadMemStats(&current)
		if current.HeapAlloc > report.HeapBytesMaximum {
			report.HeapBytesMaximum = current.HeapAlloc
		}
		if delay := 5*time.Millisecond - time.Since(requestStarted); delay > 0 {
			time.Sleep(delay)
		}
	}

	report.OpenLatency = trk36Summarize(openLatencies)
	report.RecoveryLatency = trk36Summarize(recoveryLatencies)
	source.setSnapshot(control.RouteSnapshot{Complete: true, Canonical: true})
	if err := worker.reconcile(context.Background()); err != nil {
		t.Fatalf("activate terminal empty snapshot: %v", err)
	}
	if err := worker.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown route worker: %v", err)
	}
	for _, pair := range pairs {
		if err := carrierRoutes.Detach(pair.server); err != nil {
			t.Fatalf("detach final replica: %v", err)
		}
		if err := pair.Close(); err != nil {
			t.Fatalf("close final replica: %v", err)
		}
	}
	pairs = nil
	cleanupComplete = true

	trk36Wait(t, 5*time.Second, func() bool { return carrierRoutes.Len() == 0 && len(durableAdmissions.Snapshot()) == 0 })
	if _, err := canonical.Match(assignment.PublicHost, "/after-cleanup"); !errors.Is(err, route.ErrNoMatch) {
		t.Fatalf("terminal snapshot left route selectable: %v", err)
	}
	goruntime.GC()
	var after goruntime.MemStats
	goruntime.ReadMemStats(&after)
	report.FinishedAt = time.Now().UTC()
	report.GoroutinesAfter = goruntime.NumGoroutine()
	report.HeapBytesAfter = after.HeapAlloc
	report.FinalAdmissionCount = len(durableAdmissions.Snapshot())
	report.FinalCarrierReplicaCount = carrierRoutes.Len()
	report.FinalCarrierActiveStreams = trk36ActiveStreams(pairs)

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TRK36_SOAK_REPORT %s", encoded)
	if path := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK36_REPORT")); path != "" {
		if !strings.HasPrefix(path, "/") {
			t.Fatal("PAPERBOAT_TRK36_REPORT must be an absolute path")
		}
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			t.Fatalf("create report without overwrite: %v", openErr)
		}
		_, writeErr := file.Write(append(encoded, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("write report: %v", errors.Join(writeErr, closeErr))
		}
	}

	if report.Samples == 0 || report.Errors != 0 || report.StableEndpointFailures != 0 {
		t.Fatalf("invalid soak outcome: %+v", report)
	}
	if report.OpenLatency.P95 >= 2*time.Second || report.OpenLatency.P99 >= 5*time.Second {
		t.Fatalf("allocation latency missed target: %+v", report.OpenLatency)
	}
	if report.RecoveryLatency.Count == 0 || report.RecoveryLatency.P95 >= 5*time.Second || report.RecoveryLatency.P99 >= 30*time.Second {
		t.Fatalf("carrier recovery latency missed target: %+v", report.RecoveryLatency)
	}
	if report.GoroutinesAfter > report.GoroutinesBefore+8 {
		t.Fatalf("goroutine growth is not bounded: before=%d after=%d", report.GoroutinesBefore, report.GoroutinesAfter)
	}
	if report.HeapBytesAfter > report.HeapBytesBefore+(64<<20) {
		t.Fatalf("heap growth is not bounded: before=%d after=%d", report.HeapBytesBefore, report.HeapBytesAfter)
	}
	if report.FinalAdmissionCount != 0 || report.FinalCarrierReplicaCount != 0 || report.FinalCarrierActiveStreams != 0 {
		t.Fatalf("cleanup was incomplete: %+v", report)
	}
}

func trk36AttachReplicas(t *testing.T, assignment control.RouteAssignment, admissions *datacarrier.DurableAdmissionRegistry, registry *edgehttp.DataCarrierRouteRegistry, count int) []*trk35IntegrationCarrierPair {
	t.Helper()
	pairs := make([]*trk35IntegrationCarrierPair, 0, count)
	for index := 0; index < count; index++ {
		pair, err := newTRK35IntegrationCarrierPair(assignment, admissions)
		if err != nil {
			t.Fatalf("create replica %d: %v", index, err)
		}
		if err := registry.AttachReplica(pair.server, assignment.MachineIdentityPublicKey, assignment.MachineIdentityThumbprint, trk35IntegrationReplicaState(assignment)); err != nil {
			_ = pair.Close()
			t.Fatalf("attach replica %d: %v", index, err)
		}
		pairs = append(pairs, pair)
	}
	return pairs
}

func trk36NextAssignment(current control.RouteAssignment, generation uint64) control.RouteAssignment {
	next := current
	next.State = "staged"
	next.Revision = generation
	next.Generation = generation
	next.AssignmentID = fmt.Sprintf("assignment_trk36_%d", generation)
	next.AssignmentGeneration = generation
	next.ConnectorID = fmt.Sprintf("connector_trk36_%d", generation%2+1)
	next.ConnectorSessionID = fmt.Sprintf("session_trk36_%d", generation)
	next.ConnectorProcessGeneration = generation
	next.ConfigGeneration = generation
	digest := sha256.Sum256([]byte(strconv.FormatUint(generation, 10)))
	next.ConfigContentHash = "sha256:" + hex.EncodeToString(digest[:])
	for index := range next.DomainBindings {
		next.DomainBindings[index].Generation = generation
	}
	return next
}

func trk36ActiveStreams(pairs []*trk35IntegrationCarrierPair) int {
	total := 0
	for _, pair := range pairs {
		if pair != nil {
			total += pair.client.ActiveStreams() + pair.server.ActiveStreams()
		}
	}
	return total
}

func trk36Summarize(values []time.Duration) trk36LatencyReport {
	if len(values) == 0 {
		return trk36LatencyReport{}
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	percentile := func(value int) time.Duration {
		index := (len(sorted)*value + 99) / 100
		if index < 1 {
			index = 1
		}
		if index > len(sorted) {
			index = len(sorted)
		}
		return sorted[index-1]
	}
	return trk36LatencyReport{Count: len(sorted), P50: percentile(50), P95: percentile(95), P99: percentile(99), Max: sorted[len(sorted)-1]}
}

func trk36DurationEnv(t *testing.T, name string, fallback, minimum, maximum time.Duration) time.Duration {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum {
		t.Fatalf("%s must be between %s and %s", name, minimum, maximum)
	}
	return parsed
}

func trk36IntEnv(t *testing.T, name string, fallback, minimum, maximum int) int {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		t.Fatalf("%s must be between %d and %d", name, minimum, maximum)
	}
	return parsed
}

func trk36Wait(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("TRK-36 cleanup did not converge before deadline")
}
