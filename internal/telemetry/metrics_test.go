package telemetry

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestMetricsAreFixedCardinalityDeterministicAndExactJSON(t *testing.T) {
	metrics := NewMetrics()
	if err := metrics.AddCounter("paperboat_edge_requests_total", MetricLabels{"protocol": "https", "outcome": "success"}, 3); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddCounter("paperboat_edge_access_decisions_total", MetricLabels{"decision": "denied"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := metrics.SetGauge("paperboat_edge_health_dimension", MetricLabels{"dimension": "route", "status": "degraded"}, 1); err != nil {
		t.Fatal(err)
	}
	body, err := metrics.JSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"name":"paperboat_edge_access_decisions_total","kind":"counter","labels":[{"name":"decision","value":"denied"}],"value":2},{"name":"paperboat_edge_health_dimension","kind":"gauge","labels":[{"name":"dimension","value":"route"},{"name":"status","value":"degraded"}],"value":1},{"name":"paperboat_edge_requests_total","kind":"counter","labels":[{"name":"protocol","value":"https"},{"name":"outcome","value":"success"}],"value":3}]`
	if string(body) != want {
		t.Fatalf("JSON = %s\nwant = %s", body, want)
	}
	second, _ := metrics.JSON()
	if string(second) != want {
		t.Fatalf("non-deterministic JSON = %s", second)
	}

	descriptors := MetricDescriptors()
	descriptors[0].Labels[0].AllowedValues[0] = "customer.example.com"
	if MetricDescriptors()[0].Labels[0].AllowedValues[0] == "customer.example.com" {
		t.Fatal("descriptor mutation escaped")
	}
}

func TestMetricsRejectUnknownAndHighCardinalityLabels(t *testing.T) {
	metrics := NewMetrics()
	base := MetricLabels{"protocol": "https", "outcome": "success"}
	tests := []struct {
		name   string
		labels MetricLabels
		code   ErrorCode
	}{
		{"hostname", MetricLabels{"protocol": "customer.example.com", "outcome": "success"}, ErrorLabelValueRejected},
		{"url", MetricLabels{"protocol": "https://customer.example.com", "outcome": "success"}, ErrorLabelValueRejected},
		{"arbitrary id", MetricLabels{"protocol": "route_customer123", "outcome": "success"}, ErrorLabelValueRejected},
		{"token", MetricLabels{"protocol": "Bearer-secret", "outcome": "success"}, ErrorLabelValueRejected},
		{"unknown", MetricLabels{"protocol": "https", "outcome": "success", "hostname": "customer.example.com"}, ErrorUnknownLabel},
		{"missing", MetricLabels{"protocol": "https"}, ErrorMissingLabel},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := metrics.AddCounter("paperboat_edge_requests_total", test.labels, 1); errorCode(err) != test.code {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if err := metrics.SetGauge("paperboat_edge_requests_total", base, 1); errorCode(err) != ErrorMetricKindMismatch {
		t.Fatalf("kind mismatch = %v", err)
	}
	if err := metrics.AddCounter("paperboat_edge_unknown_total", base, 1); errorCode(err) != ErrorUnknownMetric {
		t.Fatalf("unknown metric = %v", err)
	}
	if err := metrics.AddCounter("paperboat_edge_requests_total", base, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddCounter("paperboat_edge_requests_total", base, 1); errorCode(err) != ErrorMetricOverflow {
		t.Fatalf("overflow = %v", err)
	}
	body, _ := metrics.JSON()
	for _, unsafe := range []string{"customer.example.com", "route_customer123", "Bearer-secret"} {
		if strings.Contains(string(body), unsafe) {
			t.Fatalf("unsafe metric value %q in %s", unsafe, body)
		}
	}
}

func TestMetricsConcurrentUse(t *testing.T) {
	metrics := NewMetrics()
	labels := MetricLabels{"protocol": "https", "outcome": "success"}
	var group sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if err := metrics.AddCounter("paperboat_edge_requests_total", labels, 1); err != nil {
					t.Errorf("AddCounter: %v", err)
					return
				}
				_ = metrics.Snapshot()
			}
		}()
	}
	group.Wait()
	samples := metrics.Snapshot()
	if len(samples) != 1 || samples[0].Value != 6400 {
		t.Fatalf("samples = %#v", samples)
	}
}
