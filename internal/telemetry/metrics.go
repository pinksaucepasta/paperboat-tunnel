package telemetry

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
)

type MetricKind string

const (
	MetricCounter   MetricKind = "counter"
	MetricGauge     MetricKind = "gauge"
	MetricHistogram MetricKind = "histogram"
)

const (
	MetricAccessDecisions   = "paperboat_edge_access_decisions_total"
	MetricCertificateOps    = "paperboat_edge_certificate_operations_total"
	MetricHealthDimension   = "paperboat_edge_health_dimension"
	MetricHealthTransitions = "paperboat_edge_health_transitions_total"
	MetricOriginConnections = "paperboat_edge_origin_connections_total"
	MetricEdgeRequests      = "paperboat_edge_requests_total"
	MetricRouteRequests     = "paperboat_edge_route_requests_total"
	MetricUpdateOperations  = "paperboat_edge_update_operations_total"
	MetricOperationLatency  = "paperboat_edge_operation_latency_seconds"

	MetricConnectorSessions         = "paperboat_edge_connector_sessions"
	MetricConnectorConnections      = "paperboat_edge_connector_connections_total"
	MetricConnectorReconnects       = "paperboat_edge_connector_reconnects_total"
	MetricConnectorBackoff          = "paperboat_edge_connector_backoff_seconds"
	MetricConnectorHandshake        = "paperboat_edge_connector_handshake_latency_seconds"
	MetricConnectorDisconnects      = "paperboat_edge_connector_disconnects_total"
	MetricDesiredConfigGeneration   = "paperboat_edge_config_desired_generation"
	MetricAppliedConfigGeneration   = "paperboat_edge_config_applied_generation"
	MetricActiveStreams             = "paperboat_edge_active_streams"
	MetricQueueDepth                = "paperboat_edge_queue_depth"
	MetricFlowControlStalls         = "paperboat_edge_flow_control_stalls_total"
	MetricTrafficBytes              = "paperboat_edge_traffic_bytes_total"
	MetricStreamDuration            = "paperboat_edge_stream_duration_seconds"
	MetricStreamCancellations       = "paperboat_edge_stream_cancellations_total"
	MetricRouteErrors               = "paperboat_edge_route_errors_total"
	MetricRouteLatency              = "paperboat_edge_route_latency_seconds"
	MetricOriginFailures            = "paperboat_edge_origin_connect_failures_total"
	MetricProtocolUpgrades          = "paperboat_edge_protocol_upgrades_total"
	MetricHealthProbes              = "paperboat_edge_health_probes_total"
	MetricDomainVerification        = "paperboat_edge_domain_verification_seconds"
	MetricDomainVerificationFails   = "paperboat_edge_domain_verification_failures_total"
	MetricCertificateExpiryHorizon  = "paperboat_edge_certificate_expiry_horizon_seconds"
	MetricCertificateFailures       = "paperboat_edge_certificate_failures_total"
	MetricServiceUptime             = "paperboat_edge_service_uptime_seconds"
	MetricServiceRestarts           = "paperboat_edge_service_restarts_total"
	MetricWatchdogFailures          = "paperboat_edge_watchdog_failures_total"
	MetricCrashLoop                 = "paperboat_edge_crash_loop"
	MetricPreviewAllocations        = "paperboat_edge_preview_allocations_total"
	MetricPreviewLeaseCleanup       = "paperboat_edge_preview_lease_cleanup_total"
	MetricOperationIdempotencyReuse = "paperboat_edge_operation_idempotency_reuse_total"
	MetricOperationConflicts        = "paperboat_edge_operation_conflicts_total"
)

type LabelDescriptor struct {
	Name          string   `json:"name"`
	AllowedValues []string `json:"allowed_values"`
}

type MetricDescriptor struct {
	Name      string               `json:"name"`
	Kind      MetricKind           `json:"kind"`
	Labels    []LabelDescriptor    `json:"labels"`
	Histogram *HistogramDescriptor `json:"histogram,omitempty"`
}

type HistogramDescriptor struct {
	Buckets []float64 `json:"buckets"`
}

var fixedMetricDescriptors = []MetricDescriptor{
	{Name: MetricAccessDecisions, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "decision", AllowedValues: []string{"allowed", "denied", "unavailable"}},
	}},
	{Name: MetricCertificateOps, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "operation", AllowedValues: []string{"issue", "renew", "replace", "revoke"}},
		{Name: "outcome", AllowedValues: []string{"success", "failed", "canceled"}},
	}},
	{Name: MetricHealthDimension, Kind: MetricGauge, Labels: []LabelDescriptor{
		{Name: "dimension", AllowedValues: []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}},
		{Name: "status", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}},
	}},
	{Name: MetricHealthTransitions, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "dimension", AllowedValues: []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}},
		{Name: "from", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}},
		{Name: "to", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}},
	}},
	{Name: MetricOriginConnections, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "protocol", AllowedValues: []string{"http1", "http2", "h2c", "tcp", "websocket"}},
		{Name: "outcome", AllowedValues: []string{"success", "failed", "canceled", "timeout"}},
	}},
	{Name: MetricEdgeRequests, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "protocol", AllowedValues: []string{"http", "https", "tcp", "websocket"}},
		{Name: "outcome", AllowedValues: []string{"success", "rejected", "failed", "canceled"}},
	}},
	{Name: MetricRouteRequests, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "route_kind", AllowedValues: []string{"preview_public_https_wss", "tunnel_https_wss", "tunnel_tcp", "tunnel_private_tcp"}},
		{Name: "outcome", AllowedValues: []string{"success", "rejected", "failed", "canceled"}},
	}},
	{Name: MetricUpdateOperations, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "phase", AllowedValues: []string{"download", "verify", "stage", "activate", "health_gate", "rollback", "quarantine"}},
		{Name: "outcome", AllowedValues: []string{"success", "failed", "canceled"}},
	}},
	{Name: MetricOperationLatency, Kind: MetricHistogram, Labels: []LabelDescriptor{
		{Name: "operation", AllowedValues: []string{"create", "update", "delete", "reconcile", "certificate", "access"}},
	}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},

	// Connector lifecycle. Values are intentionally role/protocol/reason
	// buckets, never connector, host, route or session identifiers.
	{Name: MetricConnectorSessions, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"attached", "draining", "offline"}}}},
	{Name: MetricConnectorConnections, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "transport", AllowedValues: []string{"quic", "wss"}}, {Name: "outcome", AllowedValues: []string{"success", "failed", "canceled"}}}},
	{Name: MetricConnectorReconnects, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"network", "control", "lease", "stale", "shutdown", "unknown"}}}},
	{Name: MetricConnectorBackoff, Kind: MetricGauge},
	{Name: MetricConnectorHandshake, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "transport", AllowedValues: []string{"quic", "wss"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},
	{Name: MetricConnectorDisconnects, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"remote", "auth", "timeout", "shutdown", "stale", "protocol", "error", "unknown"}}}},

	// Configuration and stream resource state.
	{Name: MetricDesiredConfigGeneration, Kind: MetricGauge},
	{Name: MetricAppliedConfigGeneration, Kind: MetricGauge},
	{Name: MetricActiveStreams, Kind: MetricGauge},
	{Name: MetricQueueDepth, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "queue", AllowedValues: []string{"control", "route", "stream", "usage", "telemetry"}}}},
	{Name: MetricFlowControlStalls, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "direction", AllowedValues: []string{"ingress", "egress"}}}},
	{Name: MetricTrafficBytes, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "direction", AllowedValues: []string{"ingress", "egress"}}}},
	{Name: MetricStreamDuration, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "route_kind", AllowedValues: []string{"preview_public_https_wss", "tunnel_https_wss", "tunnel_tcp", "tunnel_private_tcp"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 900}}},
	{Name: MetricStreamCancellations, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"client", "origin", "edge", "timeout", "shutdown", "unknown"}}}},

	// Route, origin and probe outcomes use only fixed protocol/reason buckets.
	{Name: MetricRouteErrors, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "route_kind", AllowedValues: []string{"preview_public_https_wss", "tunnel_https_wss", "tunnel_tcp", "tunnel_private_tcp"}}, {Name: "reason", AllowedValues: []string{"not_found", "rejected", "origin", "timeout", "protocol", "internal"}}}},
	{Name: MetricRouteLatency, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "route_kind", AllowedValues: []string{"preview_public_https_wss", "tunnel_https_wss", "tunnel_tcp", "tunnel_private_tcp"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},
	{Name: MetricOriginFailures, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http1", "http2", "h2c", "tcp", "websocket"}}, {Name: "reason", AllowedValues: []string{"refused", "timeout", "tls", "reset", "unavailable", "unknown"}}}},
	{Name: MetricProtocolUpgrades, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "from", AllowedValues: []string{"http1", "http2", "h2c", "tcp"}}, {Name: "to", AllowedValues: []string{"http2", "h2c", "websocket", "tcp"}}}},
	{Name: MetricHealthProbes, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "dimension", AllowedValues: []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}}, {Name: "outcome", AllowedValues: []string{"success", "failed", "timeout", "canceled"}}}},
	{Name: MetricDomainVerification, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "timeout"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 900}}},
	{Name: MetricDomainVerificationFails, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"dns", "conflict", "timeout", "provider", "unknown"}}}},

	// Certificate, process, preview and operation lifecycle.
	{Name: MetricCertificateExpiryHorizon, Kind: MetricGauge},
	{Name: MetricCertificateFailures, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "operation", AllowedValues: []string{"issue", "renew", "replace", "revoke"}}, {Name: "reason", AllowedValues: []string{"dns", "acme", "expired", "revoked", "distribution", "unknown"}}}},
	{Name: MetricServiceUptime, Kind: MetricGauge},
	{Name: MetricServiceRestarts, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"crash", "upgrade", "shutdown", "unknown"}}}},
	{Name: MetricWatchdogFailures, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"timeout", "crash", "unhealthy", "unknown"}}}},
	{Name: MetricCrashLoop, Kind: MetricGauge},
	{Name: MetricPreviewAllocations, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "canceled", "expired"}}}},
	{Name: MetricPreviewLeaseCleanup, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"stop", "expiry", "owner_lost", "edge_lost", "shutdown", "unknown"}}}},
	{Name: MetricOperationIdempotencyReuse, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "operation", AllowedValues: []string{"create", "update", "delete", "reconcile", "certificate", "access"}}}},
	{Name: MetricOperationConflicts, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "operation", AllowedValues: []string{"create", "update", "delete", "reconcile", "certificate", "access"}}}},
}

func MetricDescriptors() []MetricDescriptor {
	result := make([]MetricDescriptor, len(fixedMetricDescriptors))
	for index, descriptor := range fixedMetricDescriptors {
		result[index] = cloneDescriptor(descriptor)
	}
	return result
}

type MetricLabels map[string]string

type MetricLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MetricSample struct {
	Name    string            `json:"name"`
	Kind    MetricKind        `json:"kind"`
	Labels  []MetricLabel     `json:"labels"`
	Value   uint64            `json:"value,omitempty"`
	Count   uint64            `json:"count,omitempty"`
	Sum     float64           `json:"sum,omitempty"`
	Buckets []HistogramBucket `json:"buckets,omitempty"`
}

type HistogramBucket struct {
	UpperBound float64 `json:"upper_bound"`
	Count      uint64  `json:"count"`
}

type metricKey struct {
	name   string
	values string
}

type Metrics struct {
	mu          sync.RWMutex
	descriptors map[string]MetricDescriptor
	values      map[metricKey]metricValue
	maxSeries   int
}

type metricValue struct {
	value   uint64
	count   uint64
	sum     float64
	buckets []uint64
}

const defaultMaximumMetricSeries = 1024

func NewMetrics() *Metrics { return NewMetricsWithLimit(defaultMaximumMetricSeries) }

func NewMetricsWithLimit(maxSeries int) *Metrics {
	if maxSeries <= 0 {
		maxSeries = defaultMaximumMetricSeries
	}
	descriptors := make(map[string]MetricDescriptor, len(fixedMetricDescriptors))
	for _, descriptor := range fixedMetricDescriptors {
		descriptors[descriptor.Name] = cloneDescriptor(descriptor)
	}
	return &Metrics{descriptors: descriptors, values: make(map[metricKey]metricValue), maxSeries: maxSeries}
}

func (m *Metrics) AddCounter(name string, labels MetricLabels, delta uint64) error {
	return m.mutate(name, labels, MetricCounter, delta, true)
}

func (m *Metrics) IncCounter(name string, labels MetricLabels) error {
	return m.AddCounter(name, labels, 1)
}

func (m *Metrics) SetGauge(name string, labels MetricLabels, value uint64) error {
	return m.mutate(name, labels, MetricGauge, value, false)
}

func (m *Metrics) ObserveHistogram(name string, labels MetricLabels, observation float64) error {
	if math.IsNaN(observation) || math.IsInf(observation, 0) || observation < 0 {
		return newError(ErrorInvalidObservation, "record edge metric")
	}
	descriptor, key, err := m.prepare(name, labels, MetricHistogram)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, exists := m.values[key]
	if !exists {
		if len(m.values) >= m.maxSeries {
			return newError(ErrorMetricCardinality, "record edge metric")
		}
		value.buckets = make([]uint64, len(descriptor.Histogram.Buckets))
	}
	if value.count == ^uint64(0) {
		return newError(ErrorMetricOverflow, "record edge metric")
	}
	newSum := value.sum + observation
	if math.IsInf(newSum, 0) {
		return newError(ErrorMetricOverflow, "record edge metric")
	}
	value.count++
	value.sum = newSum
	for index, upper := range descriptor.Histogram.Buckets {
		if observation <= upper {
			if value.buckets[index] == ^uint64(0) {
				return newError(ErrorMetricOverflow, "record edge metric")
			}
			value.buckets[index]++
		}
	}
	m.values[key] = value
	return nil
}

func (m *Metrics) mutate(name string, labels MetricLabels, kind MetricKind, value uint64, add bool) error {
	_, key, err := m.prepare(name, labels, kind)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.values[key]
	if !exists && len(m.values) >= m.maxSeries {
		return newError(ErrorMetricCardinality, "record edge metric")
	}
	if add {
		if ^uint64(0)-current.value < value {
			return newError(ErrorMetricOverflow, "record edge metric")
		}
		current.value += value
	} else {
		current.value = value
	}
	m.values[key] = current
	return nil
}

func (m *Metrics) prepare(name string, labels MetricLabels, kind MetricKind) (MetricDescriptor, metricKey, error) {
	if m == nil {
		return MetricDescriptor{}, metricKey{}, newError(ErrorClosed, "record edge metric")
	}
	descriptor, ok := m.descriptors[name]
	if !ok {
		return MetricDescriptor{}, metricKey{}, newError(ErrorUnknownMetric, "record edge metric")
	}
	if descriptor.Kind != kind {
		return MetricDescriptor{}, metricKey{}, newError(ErrorMetricKindMismatch, "record edge metric")
	}
	key, err := validateMetricLabels(descriptor, labels)
	return descriptor, key, err
}

func (m *Metrics) Snapshot() []MetricSample {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	keys := make([]metricKey, 0, len(m.values))
	values := make(map[metricKey]metricValue, len(m.values))
	descriptors := make(map[string]MetricDescriptor, len(m.descriptors))
	for key, value := range m.values {
		keys = append(keys, key)
		value.buckets = append([]uint64(nil), value.buckets...)
		values[key] = value
	}
	for name, descriptor := range m.descriptors {
		descriptors[name] = descriptor
	}
	m.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].values < keys[j].values
	})
	result := make([]MetricSample, 0, len(keys))
	for _, key := range keys {
		descriptor := descriptors[key.name]
		valuesForLabels := strings.Split(key.values, "\x1f")
		labels := make([]MetricLabel, len(descriptor.Labels))
		for index, label := range descriptor.Labels {
			labels[index] = MetricLabel{Name: label.Name, Value: valuesForLabels[index]}
		}
		value := values[key]
		sample := MetricSample{Name: key.name, Kind: descriptor.Kind, Labels: labels, Value: value.value, Count: value.count, Sum: value.sum}
		if descriptor.Kind == MetricHistogram {
			sample.Buckets = make([]HistogramBucket, len(descriptor.Histogram.Buckets))
			for index, upper := range descriptor.Histogram.Buckets {
				sample.Buckets[index] = HistogramBucket{UpperBound: upper, Count: value.buckets[index]}
			}
		}
		result = append(result, sample)
	}
	return result
}

func (m *Metrics) JSON() ([]byte, error) { return json.Marshal(m.Snapshot()) }

func validateMetricLabels(descriptor MetricDescriptor, labels MetricLabels) (metricKey, error) {
	values := make([]string, len(descriptor.Labels))
	for index, label := range descriptor.Labels {
		value, ok := labels[label.Name]
		if !ok {
			return metricKey{}, newError(ErrorMissingLabel, "record edge metric")
		}
		if !containsString(label.AllowedValues, value) {
			return metricKey{}, newError(ErrorLabelValueRejected, "record edge metric")
		}
		values[index] = value
	}
	for name := range labels {
		if !descriptorHasLabel(descriptor, name) {
			return metricKey{}, newError(ErrorUnknownLabel, "record edge metric")
		}
	}
	return metricKey{name: descriptor.Name, values: strings.Join(values, "\x1f")}, nil
}

func descriptorHasLabel(descriptor MetricDescriptor, name string) bool {
	for _, label := range descriptor.Labels {
		if label.Name == name {
			return true
		}
	}
	return false
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneDescriptor(descriptor MetricDescriptor) MetricDescriptor {
	result := descriptor
	result.Labels = make([]LabelDescriptor, len(descriptor.Labels))
	for index, label := range descriptor.Labels {
		result.Labels[index] = LabelDescriptor{Name: label.Name, AllowedValues: append([]string(nil), label.AllowedValues...)}
	}
	if descriptor.Histogram != nil {
		result.Histogram = &HistogramDescriptor{Buckets: append([]float64(nil), descriptor.Histogram.Buckets...)}
	}
	return result
}
