package datacarrier

import (
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	edgetelemetry "github.com/pinksaucepasta/paperboat-tunnel/internal/telemetry"
)

// ErrInvalidCarrierTelemetry identifies an invalid producer input. Telemetry
// failures never change the result of an open or stream operation.
var ErrInvalidCarrierTelemetry = errors.New("invalid data-carrier telemetry")

const (
	carrierStreamOpenStarted   = "carrier_stream_open_started"
	carrierStreamOpened        = "carrier_stream_opened"
	carrierStreamOpenFailed    = "carrier_stream_open_failed"
	carrierStreamAcceptStarted = "carrier_stream_accept_started"
	carrierStreamAccepted      = "carrier_stream_accepted"
	carrierStreamAcceptFailed  = "carrier_stream_accept_failed"
	carrierStreamClosed        = "carrier_stream_closed"

	carrierMessageOpenStarted   = "Data-carrier stream open started."
	carrierMessageOpened        = "Data-carrier stream opened."
	carrierMessageOpenFailed    = "Data-carrier stream open failed."
	carrierMessageAcceptStarted = "Data-carrier stream accept started."
	carrierMessageAccepted      = "Data-carrier stream accepted."
	carrierMessageAcceptFailed  = "Data-carrier stream accept failed."
	carrierMessageClosed        = "Data-carrier stream closed."
)

var (
	carrierTelemetryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,127}$`)
	carrierRouteKinds         = map[string]struct{}{
		"preview_public_https_wss": {},
		"tunnel_https_wss":         {},
		"tunnel_tcp":               {},
		"tunnel_private_tcp":       {},
	}
	carrierQueueKinds = map[string]struct{}{
		"control":   {},
		"route":     {},
		"stream":    {},
		"usage":     {},
		"telemetry": {},
	}
	carrierDirections = map[string]struct{}{
		"ingress": {},
		"egress":  {},
	}
)

// StreamInfo contains only safe identity and fixed protocol dimensions for one
// data-carrier stream. It deliberately has no address, URL, header, body, or
// error fields.
type StreamInfo struct {
	IDs                edgetelemetry.SafeIDs
	Generations        edgetelemetry.Generations
	CorrelationID      string
	RouteKind          string
	Protocol           string
	Kind               string
	ReadDirection      string
	WriteDirection     string
	CancellationReason string
}

// CarrierTelemetryConfig wires the producer to bounded core telemetry. A
// single producer is normally shared by all streams for one edge process.
type CarrierTelemetryConfig struct {
	Metrics       *edgetelemetry.Metrics
	Events        *edgetelemetry.EventLog
	Clock         func() time.Time
	Info          StreamInfo
	IDs           edgetelemetry.SafeIDs
	Generations   edgetelemetry.Generations
	CorrelationID string
	RouteKind     string
}

// CarrierTelemetry observes stream lifecycle and byte flow around existing
// carrier operations. It owns no transport goroutines.
type CarrierTelemetry struct {
	metrics  *edgetelemetry.Metrics
	events   *edgetelemetry.EventLog
	clock    func() time.Time
	base     StreamInfo
	active   atomic.Int64
	activeMu sync.Mutex
}

// NewCarrierTelemetry constructs a producer that can be shared safely by
// concurrent open, accept, and stream operations.
func NewCarrierTelemetry(config CarrierTelemetryConfig) (*CarrierTelemetry, error) {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	base := config.Info
	if base.IDs == (edgetelemetry.SafeIDs{}) {
		base.IDs = config.IDs
	}
	if base.Generations == (edgetelemetry.Generations{}) {
		base.Generations = config.Generations
	}
	if base.CorrelationID == "" {
		base.CorrelationID = config.CorrelationID
	}
	if base.RouteKind == "" {
		base.RouteKind = config.RouteKind
	}
	return &CarrierTelemetry{metrics: config.Metrics, events: config.Events, clock: config.Clock, base: base}, nil
}

// NewTelemetry is a concise constructor for callers assembling edge
// telemetry producers.
func NewTelemetry(config CarrierTelemetryConfig) (*CarrierTelemetry, error) {
	return NewCarrierTelemetry(config)
}

// StreamOpenFunc is the narrow seam used to instrument either Server.OpenStream
// or Client.OpenStream without changing the carrier implementation.
type StreamOpenFunc func(context.Context) (io.ReadWriteCloser, error)

// Open invokes open and wraps a successful stream. The supplied context owns
// the lifetime of the returned stream as well as the open operation.
func (p *CarrierTelemetry) Open(ctx context.Context, info StreamInfo, open StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.open(ctx, info, open, false)
}

// OpenStream is an explicit alias for Open.
func (p *CarrierTelemetry) OpenStream(ctx context.Context, info StreamInfo, open StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.Open(ctx, info, open)
}

// TrackOpen is an explicit lifecycle-oriented alias for Open.
func (p *CarrierTelemetry) TrackOpen(ctx context.Context, info StreamInfo, open StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.Open(ctx, info, open)
}

// Accept invokes accept and wraps a successful stream. It is intended for the
// connector-facing accept loop and does not buffer the stream.
func (p *CarrierTelemetry) Accept(ctx context.Context, info StreamInfo, accept StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.open(ctx, info, accept, true)
}

// AcceptStream is an explicit alias for Accept.
func (p *CarrierTelemetry) AcceptStream(ctx context.Context, info StreamInfo, accept StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.Accept(ctx, info, accept)
}

// TrackAccept is an explicit lifecycle-oriented alias for Accept.
func (p *CarrierTelemetry) TrackAccept(ctx context.Context, info StreamInfo, accept StreamOpenFunc) (io.ReadWriteCloser, error) {
	return p.Accept(ctx, info, accept)
}

func (p *CarrierTelemetry) open(ctx context.Context, supplied StreamInfo, operation StreamOpenFunc, accepted bool) (io.ReadWriteCloser, error) {
	if operation == nil {
		return nil, ErrInvalidCarrierTelemetry
	}
	if ctx == nil {
		ctx = context.Background()
	}
	info := p.infoFor(supplied)
	started := time.Now()
	if p != nil {
		started = p.now()
	}
	startName, startMessage := carrierStreamOpenStarted, carrierMessageOpenStarted
	failName, failMessage := carrierStreamOpenFailed, carrierMessageOpenFailed
	if accepted {
		startName, startMessage = carrierStreamAcceptStarted, carrierMessageAcceptStarted
		failName, failMessage = carrierStreamAcceptFailed, carrierMessageAcceptFailed
	}
	if p != nil {
		p.emit(started, startName, edgetelemetry.SeverityDebug, edgetelemetry.OutcomeStateChange, startMessage, info)
	}
	if err := ctx.Err(); err != nil {
		if p != nil {
			p.recordOpenFailure(info, failName, failMessage, ctx, err)
		}
		return nil, err
	}
	stream, err := operation(ctx)
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		if err == nil {
			err = ErrInvalidCarrierTelemetry
		}
		if p != nil {
			p.recordOpenFailure(info, failName, failMessage, ctx, err)
		}
		return nil, err
	}
	wrapped := p.WrapStream(ctx, stream, info)
	if p != nil {
		name, message := carrierStreamOpened, carrierMessageOpened
		if accepted {
			name, message = carrierStreamAccepted, carrierMessageAccepted
		}
		p.emit(p.now(), name, edgetelemetry.SeverityDebug, edgetelemetry.OutcomeSuccess, message, wrapped.info)
	}
	return wrapped, nil
}

// WrapStream adds byte counters, context cancellation, duration, and exactly
// once close recording around an already admitted stream. It never reads ahead
// or copies application data into an intermediate buffer.
func (p *CarrierTelemetry) WrapStream(ctx context.Context, stream io.ReadWriteCloser, info StreamInfo) *TelemetryStream {
	if ctx == nil {
		ctx = context.Background()
	}
	prepared := info
	if p != nil {
		prepared = p.infoFor(info)
	}
	wrapped := &TelemetryStream{raw: stream, producer: p, ctx: ctx, info: prepared, started: time.Now()}
	if p != nil {
		wrapped.started = p.now()
		p.activeMu.Lock()
		p.active.Add(1)
		p.setActiveGauge()
		p.activeMu.Unlock()
	}
	wrapped.stop = context.AfterFunc(ctx, func() {
		wrapped.closeWithReason(contextCancellationReason(ctx))
	})
	return wrapped
}

// Stream is an explicit alias for WrapStream for callers that use a generic
// wrapper naming convention.
func (p *CarrierTelemetry) Stream(ctx context.Context, stream io.ReadWriteCloser, info StreamInfo) *TelemetryStream {
	return p.WrapStream(ctx, stream, info)
}

// ActiveStreams returns streams currently wrapped by this producer.
func (p *CarrierTelemetry) ActiveStreams() int {
	if p == nil {
		return 0
	}
	active := p.active.Load()
	if active < 0 {
		return 0
	}
	return int(active)
}

// SetQueueDepth records a bounded fixed-label queue gauge.
func (p *CarrierTelemetry) SetQueueDepth(queue string, depth int) error {
	if _, ok := carrierQueueKinds[queue]; !ok || depth < 0 {
		return ErrInvalidCarrierTelemetry
	}
	if p == nil || p.metrics == nil {
		return nil
	}
	return p.metrics.SetGauge(edgetelemetry.MetricQueueDepth, edgetelemetry.MetricLabels{"queue": queue}, uint64(depth))
}

// QueueDepth is an alias for SetQueueDepth.
func (p *CarrierTelemetry) QueueDepth(queue string, depth int) error {
	return p.SetQueueDepth(queue, depth)
}

// RecordFlowStall records a write/read backpressure signal using only the
// fixed ingress/egress direction labels.
func (p *CarrierTelemetry) RecordFlowStall(direction string) error {
	if _, ok := carrierDirections[direction]; !ok {
		return ErrInvalidCarrierTelemetry
	}
	if p == nil || p.metrics == nil {
		return nil
	}
	return p.metrics.IncCounter(edgetelemetry.MetricFlowControlStalls, edgetelemetry.MetricLabels{"direction": direction})
}

// FlowStall is an alias for RecordFlowStall.
func (p *CarrierTelemetry) FlowStall(direction string) error {
	return p.RecordFlowStall(direction)
}

func (p *CarrierTelemetry) infoFor(supplied StreamInfo) StreamInfo {
	info := p.base
	if supplied.IDs != (edgetelemetry.SafeIDs{}) {
		info.IDs = supplied.IDs
	}
	if supplied.Generations != (edgetelemetry.Generations{}) {
		info.Generations = supplied.Generations
	}
	if supplied.CorrelationID != "" {
		info.CorrelationID = supplied.CorrelationID
	}
	if supplied.RouteKind != "" {
		info.RouteKind = supplied.RouteKind
	}
	if supplied.Protocol != "" {
		info.Protocol = supplied.Protocol
	}
	if supplied.Kind != "" {
		info.Kind = supplied.Kind
	}
	if supplied.ReadDirection != "" {
		info.ReadDirection = supplied.ReadDirection
	}
	if supplied.WriteDirection != "" {
		info.WriteDirection = supplied.WriteDirection
	}
	if supplied.CancellationReason != "" {
		info.CancellationReason = supplied.CancellationReason
	}
	info.IDs = safeCarrierIDs(info.IDs)
	if _, ok := carrierRouteKinds[info.RouteKind]; !ok {
		info.RouteKind = ""
	}
	if !safeCarrierCorrelation(info.CorrelationID) {
		info.CorrelationID = ""
	}
	if _, ok := carrierDirections[info.ReadDirection]; !ok {
		info.ReadDirection = "ingress"
	}
	if _, ok := carrierDirections[info.WriteDirection]; !ok {
		info.WriteDirection = "egress"
	}
	if _, ok := carrierCancellationReasons[info.CancellationReason]; !ok {
		info.CancellationReason = ""
	}
	return info
}

var carrierCancellationReasons = map[string]struct{}{
	"client": {}, "origin": {}, "edge": {}, "timeout": {}, "shutdown": {}, "unknown": {},
}

func (p *CarrierTelemetry) emit(at time.Time, name string, severity edgetelemetry.EventSeverity, outcome edgetelemetry.EventOutcome, message string, info StreamInfo) {
	if p == nil || p.events == nil {
		return
	}
	_, _, _ = p.events.TryRecord(edgetelemetry.EventInput{
		At: at, Severity: severity, Component: edgetelemetry.DimensionEdge,
		Name: name, Code: name, Outcome: outcome, Message: message,
		CorrelationID: info.CorrelationID, IDs: safeCarrierIDs(info.IDs), Generations: info.Generations,
		Retry: edgetelemetry.RetryNone,
	})
}

func (p *CarrierTelemetry) recordOpenFailure(info StreamInfo, name, message string, ctx context.Context, err error) {
	outcome := edgetelemetry.OutcomeFailed
	severity := edgetelemetry.SeverityWarn
	if errors.Is(err, context.Canceled) || errors.Is(ctxErr(ctx), context.Canceled) || errors.Is(ctxErr(ctx), context.DeadlineExceeded) {
		outcome = edgetelemetry.OutcomeCanceled
	}
	p.emit(p.now(), name, severity, outcome, message, info)
	if outcome == edgetelemetry.OutcomeCanceled && p.metrics != nil {
		reason := contextCancellationReason(ctx)
		if reason == "" {
			reason = carrierCancellationReasonFromError(err)
		}
		_ = p.metrics.IncCounter(edgetelemetry.MetricStreamCancellations, edgetelemetry.MetricLabels{"reason": reason})
	}
}

func (p *CarrierTelemetry) setActiveGauge() {
	if p == nil || p.metrics == nil {
		return
	}
	active := p.active.Load()
	if active < 0 {
		active = 0
	}
	_ = p.metrics.SetGauge(edgetelemetry.MetricActiveStreams, nil, uint64(active))
}

func (p *CarrierTelemetry) now() time.Time {
	at := time.Now()
	if p != nil && p.clock != nil {
		at = p.clock()
	}
	if at.IsZero() {
		at = time.Now()
	}
	return at.UTC()
}

// TelemetryStream is a transparent read/write/close wrapper around a carrier
// stream. Optional deadline and stream-ID methods are forwarded when the
// underlying stream provides them.
type TelemetryStream struct {
	raw      io.ReadWriteCloser
	producer *CarrierTelemetry
	ctx      context.Context
	info     StreamInfo
	started  time.Time
	stop     func() bool
	once     sync.Once
	closeErr error
}

func (s *TelemetryStream) Read(payload []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrCarrierClosed
	}
	n, err := s.raw.Read(payload)
	if n > 0 && s.producer != nil {
		s.producer.addBytes(s.info.ReadDirection, uint64(n))
	}
	if err != nil && isTimeoutError(err) && s.producer != nil {
		_ = s.producer.RecordFlowStall(s.info.ReadDirection)
	}
	return n, err
}

func (s *TelemetryStream) Write(payload []byte) (int, error) {
	if s == nil || s.raw == nil {
		return 0, ErrCarrierClosed
	}
	n, err := s.raw.Write(payload)
	if n > 0 && s.producer != nil {
		s.producer.addBytes(s.info.WriteDirection, uint64(n))
	}
	if err != nil && isTimeoutError(err) && s.producer != nil {
		_ = s.producer.RecordFlowStall(s.info.WriteDirection)
	}
	return n, err
}

func (s *TelemetryStream) Close() error {
	return s.closeWithReason("")
}

// CloseWithReason lets a shutdown owner preserve a fixed cancellation reason
// while retaining the same exactly-once terminal recording.
func (s *TelemetryStream) CloseWithReason(reason string) error {
	return s.closeWithReason(reason)
}

func (s *TelemetryStream) closeWithReason(reason string) error {
	if s == nil || s.raw == nil {
		return nil
	}
	s.once.Do(func() {
		if s.stop != nil {
			s.stop()
		}
		s.closeErr = s.raw.Close()
		if s.producer != nil {
			s.producer.finishStream(s, reason, s.closeErr)
		}
	})
	return s.closeErr
}

func (s *TelemetryStream) SetDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	if setter, ok := s.raw.(interface{ SetDeadline(time.Time) error }); ok {
		return setter.SetDeadline(deadline)
	}
	return nil
}

func (s *TelemetryStream) SetReadDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	if setter, ok := s.raw.(interface{ SetReadDeadline(time.Time) error }); ok {
		return setter.SetReadDeadline(deadline)
	}
	return nil
}

func (s *TelemetryStream) SetWriteDeadline(deadline time.Time) error {
	if s == nil || s.raw == nil {
		return ErrCarrierClosed
	}
	if setter, ok := s.raw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return setter.SetWriteDeadline(deadline)
	}
	return nil
}

func (s *TelemetryStream) StreamID() uint32 {
	if s == nil || s.raw == nil {
		return 0
	}
	if identified, ok := s.raw.(interface{ StreamID() uint32 }); ok {
		return identified.StreamID()
	}
	return 0
}

func (p *CarrierTelemetry) addBytes(direction string, count uint64) {
	if p == nil || p.metrics == nil || count == 0 {
		return
	}
	_ = p.metrics.AddCounter(edgetelemetry.MetricTrafficBytes, edgetelemetry.MetricLabels{"direction": direction}, count)
}

func (p *CarrierTelemetry) finishStream(stream *TelemetryStream, reason string, closeErr error) {
	if p == nil || stream == nil {
		return
	}
	p.activeMu.Lock()
	active := p.active.Add(-1)
	if active < 0 {
		p.active.Store(0)
		active = 0
	}
	p.setActiveGauge()
	p.activeMu.Unlock()
	if p.metrics != nil && stream.info.RouteKind != "" {
		_ = p.metrics.ObserveHistogram(edgetelemetry.MetricStreamDuration, edgetelemetry.MetricLabels{"route_kind": stream.info.RouteKind}, stream.durationSeconds())
	}
	outcome := edgetelemetry.OutcomeSuccess
	if closeErr != nil && !isExpectedStreamClose(closeErr) {
		outcome = edgetelemetry.OutcomeFailed
	}
	reason = normalizeCarrierCancellationReason(reason)
	if reason == "" {
		reason = contextCancellationReason(stream.ctx)
		if reason != "" {
			if configured := normalizeCarrierCancellationReason(stream.info.CancellationReason); configured != "" {
				reason = configured
			}
		}
	}
	if reason != "" {
		outcome = edgetelemetry.OutcomeCanceled
		if p.metrics != nil {
			_ = p.metrics.IncCounter(edgetelemetry.MetricStreamCancellations, edgetelemetry.MetricLabels{"reason": reason})
		}
	}
	p.emit(p.now(), carrierStreamClosed, edgetelemetry.SeverityDebug, outcome, carrierMessageClosed, stream.info)
}

func (s *TelemetryStream) durationSeconds() float64 {
	duration := time.Since(s.started)
	if s.producer != nil {
		at := s.producer.now()
		if at.After(s.started) {
			duration = at.Sub(s.started)
		}
	}
	if duration < 0 {
		return 0
	}
	return duration.Seconds()
}

func isExpectedStreamClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func contextCancellationReason(ctx context.Context) string {
	switch {
	case errors.Is(ctxErr(ctx), context.DeadlineExceeded):
		return "timeout"
	case errors.Is(ctxErr(ctx), context.Canceled):
		return "client"
	default:
		return ""
	}
}

func carrierCancellationReasonFromError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "client"
	default:
		return "unknown"
	}
}

func normalizeCarrierCancellationReason(reason string) string {
	if _, ok := carrierCancellationReasons[reason]; !ok {
		return ""
	}
	return reason
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func safeCarrierCorrelation(value string) bool {
	return carrierTelemetryIDPattern.MatchString(value) && (strings.HasPrefix(value, "corr_") || strings.HasPrefix(value, "cor_") || strings.HasPrefix(value, "correlation_") || strings.HasPrefix(value, "request_") || strings.HasPrefix(value, "pb-"))
}

func safeCarrierIDs(ids edgetelemetry.SafeIDs) edgetelemetry.SafeIDs {
	ids.AccountID = safeCarrierID(ids.AccountID, "account_")
	ids.ActorID = safeCarrierID(ids.ActorID, "actor_")
	ids.TunnelID = safeCarrierID(ids.TunnelID, "tunnel_")
	ids.RouteID = safeCarrierID(ids.RouteID, "route_")
	ids.ConnectorID = safeCarrierID(ids.ConnectorID, "connector_")
	ids.DomainID = safeCarrierID(ids.DomainID, "domain_")
	ids.CertificateID = safeCarrierID(ids.CertificateID, "certificate_")
	ids.AssignmentID = safeCarrierID(ids.AssignmentID, "assignment_")
	ids.HostID = safeCarrierID(ids.HostID, "host_")
	ids.DeviceID = safeCarrierID(ids.DeviceID, "device_")
	ids.SessionID = safeCarrierID(ids.SessionID, "session_", "carrier_")
	ids.OperationID = safeCarrierID(ids.OperationID, "operation_", "op_")
	ids.RequestID = safeCarrierID(ids.RequestID, "request_", "req_")
	ids.EdgeNodeID = safeCarrierID(ids.EdgeNodeID, "edge_")
	return ids
}

func safeCarrierID(value string, prefixes ...string) string {
	if value == "" || !carrierTelemetryIDPattern.MatchString(value) {
		return ""
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return value
		}
	}
	return ""
}
