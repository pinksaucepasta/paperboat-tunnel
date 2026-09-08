package edgehttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type ingressUsageRecord struct {
	environment, route        string
	revision, ingress, egress uint64
}
type ingressUsageRecorder struct {
	mu      sync.Mutex
	records []ingressUsageRecord
}

func (r *ingressUsageRecorder) Record(environment, route string, revision uint64, ingress, egress uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, ingressUsageRecord{environment, route, revision, ingress, egress})
	return nil
}

type ingressMemoryStream struct {
	bytes.Buffer
	writeLimit int
	writeErr   error
	closed     bool
}

func (s *ingressMemoryStream) Read(payload []byte) (int, error) { return s.Buffer.Read(payload) }
func (s *ingressMemoryStream) Write(payload []byte) (int, error) {
	if s.writeLimit > 0 && len(payload) > s.writeLimit {
		n, _ := s.Buffer.Write(payload[:s.writeLimit])
		return n, s.writeErr
	}
	return s.Buffer.Write(payload)
}
func (s *ingressMemoryStream) Close() error      { s.closed = true; return nil }
func (s *ingressMemoryStream) CloseWrite() error { return nil }

func testIngressLimits(connections int, byteRate rate.Limit) *IngressLimits {
	return &IngressLimits{Publication: IngressLimitConfig{Connections: connections, OpenRate: 100, OpenBurst: 100, ByteRate: byteRate, ByteBurst: ingressPacingChunk}, Account: IngressLimitConfig{Connections: connections, OpenRate: 100, OpenBurst: 100, ByteRate: byteRate, ByteBurst: ingressPacingChunk}}
}

func TestIngressLimitsSharePublicationAndAccountAcrossCarriers(t *testing.T) {
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2, IngressLimits: testIngressLimits(1, 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	first := publicTCPDecision(time.Now().UTC(), 4001)
	lease, err := registry.AcquireIngress(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.DecisionID, second.ConnectorID, second.SessionID = "decision_other", "connector_other", "session_other"
	if _, err := registry.AcquireIngress(context.Background(), second); !errors.Is(err, ErrIngressLimitExceeded) {
		t.Fatalf("shared publication limit error=%v", err)
	}
	lease.Release()
	if next, err := registry.AcquireIngress(context.Background(), second); err != nil {
		t.Fatal(err)
	} else {
		next.Release()
	}
}

func TestIngressOpenRateIsSharedAfterConnectionsClose(t *testing.T) {
	limits := testIngressLimits(4, 1<<20)
	limits.Publication.OpenRate, limits.Publication.OpenBurst = rate.Limit(0.01), 1
	limits.Account.OpenRate, limits.Account.OpenBurst = rate.Limit(0.01), 1
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2, IngressLimits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	decision := publicTCPDecision(time.Now().UTC(), 4001)
	first, err := registry.AcquireIngress(context.Background(), decision)
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	decision.ConnectorID, decision.SessionID = "connector_other", "session_other"
	if _, err := registry.AcquireIngress(context.Background(), decision); !errors.Is(err, ErrIngressLimitExceeded) {
		t.Fatalf("shared open rate error=%v", err)
	}
}

func TestIngressPacingCancellationMetersSuccessfulPartialBytesAndReleases(t *testing.T) {
	recorder := &ingressUsageRecorder{}
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2, IngressLimits: testIngressLimits(1, 1), Usage: recorder})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	decision := publicTCPDecision(time.Now().UTC(), 4001)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	lease, err := registry.AcquireIngress(ctx, decision)
	if err != nil {
		t.Fatal(err)
	}
	underlying := &ingressMemoryStream{}
	stream := lease.Wrap(ctx, underlying)
	written, err := stream.Write(make([]byte, ingressPacingChunk*2))
	if err == nil || written != ingressPacingChunk {
		t.Fatalf("paced write=%d err=%v", written, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !underlying.closed {
		t.Fatal("paced stream was not closed")
	}
	if len(recorder.records) != 1 || recorder.records[0].ingress != ingressPacingChunk || recorder.records[0].egress != 0 {
		t.Fatalf("usage=%+v", recorder.records)
	}
	if next, err := registry.AcquireIngress(context.Background(), decision); err != nil {
		t.Fatalf("connection permit leaked: %v", err)
	} else {
		next.Release()
	}
}

func TestIngressMeterRecordsBytesReturnedWithError(t *testing.T) {
	recorder := &ingressUsageRecorder{}
	registry, err := NewDataCarrierRouteRegistry(DataCarrierRouteRegistryConfig{MaximumRoutes: 2, IngressLimits: testIngressLimits(1, 1<<20), Usage: recorder})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	decision := publicTCPDecision(time.Now().UTC(), 4001)
	lease, err := registry.AcquireIngress(context.Background(), decision)
	if err != nil {
		t.Fatal(err)
	}
	stream := lease.Wrap(context.Background(), &ingressMemoryStream{writeLimit: 7, writeErr: io.ErrUnexpectedEOF})
	n, err := stream.Write([]byte("partial payload"))
	if n != 7 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial write=%d err=%v", n, err)
	}
	_ = stream.Close()
	if len(recorder.records) != 1 || recorder.records[0] != (ingressUsageRecord{environment: decision.Binding.EnvironmentID, route: decision.Binding.RouteID, revision: decision.Binding.RouteGeneration, ingress: 7}) {
		t.Fatalf("usage=%+v", recorder.records)
	}
}

var _ io.ReadWriteCloser = (*ingressMemoryStream)(nil)
var _ interface{ CloseWrite() error } = (*ingressMemoryStream)(nil)
var _ IngressUsage = (*ingressUsageRecorder)(nil)
