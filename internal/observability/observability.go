package observability

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

type Kind string
type Result string

const (
	Admission Kind = "admission"
	Route     Kind = "route"
	Stream    Kind = "stream"
	Usage     Kind = "usage"
	Node      Kind = "node"
	Cleanup   Kind = "cleanup"

	Success  Result = "success"
	Rejected Result = "rejected"
	Failed   Result = "failed"
	Canceled Result = "canceled"
)

type Event struct {
	At                  time.Time `json:"at"`
	Kind                Kind      `json:"kind"`
	Result              Result    `json:"result"`
	NodeState           string    `json:"node_state,omitempty"`
	RouteKind           string    `json:"route_kind,omitempty"`
	Direction           string    `json:"direction,omitempty"`
	RejectionCode       string    `json:"rejection_code,omitempty"`
	ConnectorGeneration uint64    `json:"connector_generation,omitempty"`
	RouteRevision       uint64    `json:"route_revision,omitempty"`
	Bytes               uint64    `json:"bytes,omitempty"`
	Streams             uint32    `json:"streams,omitempty"`
}

func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

type SafeError struct {
	Code     string `json:"code"`
	Recovery string `json:"recovery,omitempty"`
}

func Error(err error) SafeError {
	if typed, ok := err.(*edgeerrors.Error); ok {
		return SafeError{Code: string(typed.Code), Recovery: typed.Recovery}
	}
	if code, ok := edgeerrors.CodeOf(err); ok {
		return SafeError{Code: string(code)}
	}
	return SafeError{Code: "internal_error", Recovery: "retry or inspect private diagnostics"}
}

type MetricKey struct {
	Kind                 Kind
	Result               Result
	RouteKind, Direction string
}

type Metrics struct {
	mu     sync.Mutex
	values map[MetricKey]uint64
}

func NewMetrics() *Metrics { return &Metrics{values: make(map[MetricKey]uint64)} }

func (m *Metrics) Add(key MetricKey, value uint64) bool {
	if !validKind(key.Kind) || !validResult(key.Result) || !validRouteKind(key.RouteKind) || !validDirection(key.Direction) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ^uint64(0)-m.values[key] < value {
		return false
	}
	m.values[key] += value
	return true
}

func (m *Metrics) Get(key MetricKey) uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.values[key] }

func (m *Metrics) Snapshot() map[MetricKey]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[MetricKey]uint64, len(m.values))
	for key, value := range m.values {
		result[key] = value
	}
	return result
}

func validKind(value Kind) bool {
	return value == Admission || value == Route || value == Stream || value == Usage || value == Node || value == Cleanup
}
func validResult(value Result) bool {
	return value == Success || value == Rejected || value == Failed || value == Canceled
}
func validRouteKind(value string) bool {
	return value == "" || value == "runtime_https_wss" || value == "preview_public_https_wss"
}
func validDirection(value string) bool { return value == "" || value == "ingress" || value == "egress" }

type Status string

const (
	Healthy     Status = "healthy"
	Degraded    Status = "degraded"
	Unavailable Status = "unavailable"
)

type Diagnostics struct {
	Control Status `json:"control"`
	Store   Status `json:"store"`
	FRP     Status `json:"frp"`
	Caddy   Status `json:"caddy"`
	Usage   Status `json:"usage"`
}

func (d Diagnostics) Ready() bool {
	return d.Control == Healthy && d.Store == Healthy && d.FRP == Healthy && d.Caddy == Healthy && d.Usage != Unavailable
}

type Sources struct {
	Node          func() node.Snapshot
	Manager       func() node.ManagerSnapshot
	Sessions      func() int
	SessionRoutes func() int
	ActiveStreams func() uint32
	RouteCount    func() int
	Usage         func() usage.QueueStats
	ControlErr    func() error
	RouteErr      func() error
	UsageErr      func() error
	FRPRunning    func() bool
	CaddyRunning  func() bool
	CaddyTLS      func() (time.Time, error)
	Events        func() map[MetricKey]uint64
	Traffic       func() []usage.CounterRecord
	Now           func() time.Time
}

type Snapshot struct {
	At                    time.Time            `json:"at"`
	Node                  node.Snapshot        `json:"node"`
	Control               Status               `json:"control"`
	Routes                Status               `json:"routes"`
	Usage                 Status               `json:"usage"`
	FRP                   Status               `json:"frp"`
	Caddy                 Status               `json:"caddy"`
	CertificateExpiresAt  time.Time            `json:"certificate_expires_at,omitempty"`
	Connectors            int                  `json:"connectors"`
	ActiveStreams         uint32               `json:"active_streams"`
	AttachedRoutes        int                  `json:"attached_routes"`
	RouteDrift            bool                 `json:"route_drift"`
	UsagePendingReports   int                  `json:"usage_pending_reports"`
	UsagePendingBytes     int                  `json:"usage_pending_bytes"`
	UsageOldestAgeSeconds int64                `json:"usage_oldest_age_seconds"`
	Capacity              uint32               `json:"connector_capacity"`
	FailureCodes          []string             `json:"failure_codes,omitempty"`
	Events                map[MetricKey]uint64 `json:"-"`
	TrafficIngressBytes   uint64               `json:"traffic_ingress_bytes"`
	TrafficEgressBytes    uint64               `json:"traffic_egress_bytes"`
}

func NewHandler(s Sources) (http.Handler, error) {
	if s.Node == nil || s.Manager == nil || s.Sessions == nil || s.SessionRoutes == nil || s.ActiveStreams == nil || s.RouteCount == nil || s.Usage == nil || s.ControlErr == nil || s.RouteErr == nil || s.UsageErr == nil || s.FRPRunning == nil || s.CaddyRunning == nil || s.CaddyTLS == nil || s.Events == nil || s.Traffic == nil {
		return nil, fmt.Errorf("observability sources are incomplete")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { writeSnapshot(w, snapshot(s), false) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { writeSnapshot(w, snapshot(s), true) })
	mux.HandleFunc("GET /diagnostics", func(w http.ResponseWriter, _ *http.Request) { writeSnapshot(w, snapshot(s), false) })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) { writeMetrics(w, snapshot(s)) })
	return mux, nil
}

func snapshot(s Sources) Snapshot {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	manager, pending := s.Manager(), s.Usage()
	routeErr := s.RouteErr()
	result := Snapshot{At: now, Node: s.Node(), Control: statusFor(s.ControlErr()), Routes: statusFor(routeErr), Usage: statusFor(s.UsageErr()), FRP: runningStatus(s.FRPRunning()), Caddy: runningStatus(s.CaddyRunning()), Connectors: s.Sessions(), ActiveStreams: s.ActiveStreams(), AttachedRoutes: s.RouteCount(), UsagePendingReports: pending.Reports, UsagePendingBytes: pending.Bytes, Capacity: manager.Capacity, Events: s.Events()}
	result.RouteDrift = s.SessionRoutes() != result.AttachedRoutes
	if result.RouteDrift {
		result.Routes = Degraded
	}
	if result.Caddy == Healthy {
		expires, err := s.CaddyTLS()
		result.CertificateExpiresAt = expires
		if err != nil {
			result.Caddy = Degraded
		}
	}
	if pending.Reports >= pending.MaxReports || pending.Bytes >= pending.MaxBytes {
		result.Usage = Unavailable
	}
	for _, record := range s.Traffic() {
		switch record.Key.Direction {
		case "ingress":
			result.TrafficIngressBytes += record.Bytes
		case "egress":
			result.TrafficEgressBytes += record.Bytes
		}
	}
	if !pending.OldestAt.IsZero() && now.After(pending.OldestAt) {
		result.UsageOldestAgeSeconds = int64(now.Sub(pending.OldestAt) / time.Second)
	}
	for name, status := range map[string]Status{"control_unavailable": result.Control, "usage_delivery_failed": result.Usage, "frps_unavailable": result.FRP} {
		if status != Healthy {
			result.FailureCodes = append(result.FailureCodes, name)
		}
	}
	if routeErr != nil {
		result.FailureCodes = append(result.FailureCodes, "route_reconciliation_failed")
	}
	if result.RouteDrift {
		result.FailureCodes = append(result.FailureCodes, "route_drift")
	}
	if result.Caddy == Unavailable {
		result.FailureCodes = append(result.FailureCodes, "caddy_unavailable")
	} else if result.Caddy == Degraded {
		result.FailureCodes = append(result.FailureCodes, "certificate_unavailable")
	}
	sort.Strings(result.FailureCodes)
	return result
}

func statusFor(err error) Status {
	if err != nil {
		return Degraded
	}
	return Healthy
}
func runningStatus(running bool) Status {
	if !running {
		return Unavailable
	}
	return Healthy
}

func (s Snapshot) ready() bool {
	return s.Node.Ready && s.Control == Healthy && s.Routes == Healthy && s.Usage != Unavailable && s.FRP == Healthy && s.Caddy == Healthy
}

func writeSnapshot(w http.ResponseWriter, value Snapshot, readiness bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if readiness && !value.ready() || !readiness && !value.Node.Live {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(value)
}

func writeMetrics(w http.ResponseWriter, s Snapshot) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	lines := []string{
		"paperboat_tunnel_live " + booleanMetric(s.Node.Live),
		"paperboat_tunnel_ready " + booleanMetric(s.ready()),
		"paperboat_tunnel_connectors " + strconv.Itoa(s.Connectors),
		"paperboat_tunnel_active_streams " + strconv.FormatUint(uint64(s.ActiveStreams), 10),
		"paperboat_tunnel_attached_routes " + strconv.Itoa(s.AttachedRoutes),
		"paperboat_tunnel_connector_capacity " + strconv.FormatUint(uint64(s.Capacity), 10),
		"paperboat_tunnel_usage_pending_reports " + strconv.Itoa(s.UsagePendingReports),
		"paperboat_tunnel_usage_pending_bytes " + strconv.Itoa(s.UsagePendingBytes),
		"paperboat_tunnel_usage_oldest_age_seconds " + strconv.FormatInt(s.UsageOldestAgeSeconds, 10),
		"paperboat_tunnel_traffic_ingress_bytes_total " + strconv.FormatUint(s.TrafficIngressBytes, 10),
		"paperboat_tunnel_traffic_egress_bytes_total " + strconv.FormatUint(s.TrafficEgressBytes, 10),
	}
	if !s.CertificateExpiresAt.IsZero() {
		lines = append(lines, "paperboat_tunnel_certificate_expiry_timestamp_seconds "+strconv.FormatInt(s.CertificateExpiresAt.Unix(), 10))
	}
	for _, dependency := range []struct {
		name   string
		status Status
	}{{"control", s.Control}, {"routes", s.Routes}, {"usage", s.Usage}, {"frps", s.FRP}, {"caddy", s.Caddy}} {
		lines = append(lines, `paperboat_tunnel_dependency_healthy{dependency="`+dependency.name+`"} `+booleanMetric(dependency.status == Healthy))
	}
	keys := make([]MetricKey, 0, len(s.Events))
	for key := range s.Events {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	for _, key := range keys {
		lines = append(lines, `paperboat_tunnel_events_total{kind="`+string(key.Kind)+`",result="`+string(key.Result)+`",route_kind="`+key.RouteKind+`",direction="`+key.Direction+`"} `+strconv.FormatUint(s.Events[key], 10))
	}
	_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
}

func booleanMetric(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
