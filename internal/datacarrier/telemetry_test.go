package datacarrier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	edgetelemetry "github.com/pinksaucepasta/paperboat-tunnel/internal/telemetry"
)

func newTestCarrierTelemetry(t *testing.T) (*CarrierTelemetry, *edgetelemetry.Metrics, *edgetelemetry.EventLog) {
	t.Helper()
	metrics := edgetelemetry.NewMetrics()
	events, err := edgetelemetry.NewEventLogWithQueue(128, 128)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	producer, err := NewCarrierTelemetry(CarrierTelemetryConfig{
		Metrics: metrics,
		Events:  events,
		Clock:   func() time.Time { return time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC) },
		Info: StreamInfo{
			IDs:           edgetelemetry.SafeIDs{TunnelID: "tunnel_1", RouteID: "route_1", ConnectorID: "connector_1"},
			Generations:   edgetelemetry.Generations{Route: 4, Connector: 2},
			CorrelationID: "corr_carrier_test_1",
			RouteKind:     "tunnel_https_wss",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return producer, metrics, events
}

func TestCarrierTelemetryOpenCloseCountsBytesAndIsExactlyOnce(t *testing.T) {
	producer, metrics, events := newTestCarrierTelemetry(t)
	local, remote := net.Pipe()
	stream, err := producer.Open(context.Background(), StreamInfo{Kind: "grpc", Protocol: "h2c"}, func(context.Context) (io.ReadWriteCloser, error) {
		return local, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		payload := make([]byte, len("carrier-ingress"))
		_, readErr := io.ReadFull(remote, payload)
		if string(payload) != "carrier-ingress" {
			readDone <- errors.New("wrong ingress payload")
			return
		}
		readDone <- readErr
	}()
	if _, err := stream.Write([]byte("carrier-ingress")); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = remote.Write([]byte("carrier-egress")) }()
	payload := make([]byte, len("carrier-egress"))
	if _, err := io.ReadFull(stream, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "carrier-egress" {
		t.Fatalf("egress payload = %q", payload)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()

	samples := metrics.Snapshot()
	if got := carrierMetricValue(samples, edgetelemetry.MetricTrafficBytes, "egress"); got != uint64(len("carrier-ingress")) {
		t.Fatalf("egress bytes = %d", got)
	}
	if got := carrierMetricValue(samples, edgetelemetry.MetricTrafficBytes, "ingress"); got != uint64(len("carrier-egress")) {
		t.Fatalf("ingress bytes = %d", got)
	}
	if got := carrierMetricValue(samples, edgetelemetry.MetricActiveStreams); got != 0 {
		t.Fatalf("active streams = %d", got)
	}
	closed := 0
	opened := 0
	for _, event := range events.Snapshot() {
		switch event.Name {
		case carrierStreamClosed:
			closed++
		case carrierStreamOpened:
			opened++
		}
		encoded, _ := json.Marshal(event)
		if bytes.Contains(encoded, []byte("carrier-ingress")) || bytes.Contains(encoded, []byte("secret")) {
			t.Fatalf("event leaked application data: %s", encoded)
		}
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("opened=%d closed=%d", opened, closed)
	}
}

func TestCarrierTelemetryCancellationAndOpenFailure(t *testing.T) {
	producer, metrics, events := newTestCarrierTelemetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	local, remote := net.Pipe()
	stream, err := producer.Open(ctx, StreamInfo{CancellationReason: "client"}, func(context.Context) (io.ReadWriteCloser, error) {
		return local, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	readDone := make(chan error, 1)
	go func() {
		_, readErr := remote.Read(make([]byte, 8))
		readDone <- readErr
	}()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("canceled stream did not close")
	}
	_ = stream.Close()
	_ = remote.Close()

	failedCtx, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	_, err = producer.Accept(failedCtx, StreamInfo{}, func(ctx context.Context) (io.ReadWriteCloser, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("accept error = %v", err)
	}

	if got := carrierMetricValue(metrics.Snapshot(), edgetelemetry.MetricStreamCancellations, "client"); got != 1 {
		t.Fatalf("client cancellation count = %d", got)
	}
	closed := 0
	canceledOpen := 0
	for _, event := range events.Snapshot() {
		if event.Name == carrierStreamClosed {
			closed++
		}
		if event.Name == carrierStreamAcceptFailed && event.Outcome == edgetelemetry.OutcomeCanceled {
			canceledOpen++
		}
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), "context deadline") || strings.Contains(string(encoded), "secret") {
			t.Fatalf("event leaked error data: %s", encoded)
		}
	}
	if closed != 1 || canceledOpen != 1 {
		t.Fatalf("closed=%d canceled accepts=%d", closed, canceledOpen)
	}
}

func TestCarrierTelemetryQueueAndFlowStallLabels(t *testing.T) {
	producer, metrics, _ := newTestCarrierTelemetry(t)
	if err := producer.SetQueueDepth("stream", 3); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordFlowStall("egress"); err != nil {
		t.Fatal(err)
	}
	if err := producer.SetQueueDepth("hostname.secret", 1); !errors.Is(err, ErrInvalidCarrierTelemetry) {
		t.Fatalf("invalid queue error = %v", err)
	}
	if got := carrierMetricValue(metrics.Snapshot(), edgetelemetry.MetricQueueDepth, "stream"); got != 3 {
		t.Fatalf("queue depth = %d", got)
	}
	if got := carrierMetricValue(metrics.Snapshot(), edgetelemetry.MetricFlowControlStalls, "egress"); got != 1 {
		t.Fatalf("flow stall count = %d", got)
	}
}

func carrierMetricValue(samples []edgetelemetry.MetricSample, name string, labels ...string) uint64 {
	for _, sample := range samples {
		if sample.Name != name || len(sample.Labels) != len(labels) {
			continue
		}
		match := true
		for index, value := range labels {
			if sample.Labels[index].Value != value {
				match = false
				break
			}
		}
		if match {
			return sample.Value
		}
	}
	return 0
}
