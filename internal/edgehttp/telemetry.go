package edgehttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	edgetelemetry "github.com/pinksaucepasta/paperboat-tunnel/internal/telemetry"
)

// ErrInvalidRequestTelemetry identifies an invalid wrapper or callback. The
// telemetry path never returns exporter or sink errors to a live request.
var ErrInvalidRequestTelemetry = errors.New("invalid edge request telemetry")

const (
	requestEventStarted   = "edge_request_started"
	requestEventCompleted = "edge_request_completed"
	requestEventFailed    = "edge_request_failed"
	requestEventCanceled  = "edge_request_canceled"
	requestEventRejected  = "edge_request_rejected"

	originEventConnected = "origin_connected"
	originEventFailed    = "origin_connect_failed"

	requestMessageStarted  = "Edge request forwarding started."
	requestMessageComplete = "Edge request forwarding completed."
	requestMessageFailed   = "Edge request forwarding failed."
	requestMessageCanceled = "Edge request forwarding was canceled."
	requestMessageRejected = "Edge request forwarding was rejected."
	originMessageConnected = "Origin connection established."
	originMessageFailed    = "Origin connection failed."
)

var (
	requestTelemetryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,127}$`)
	requestRouteKinds         = map[string]struct{}{
		"preview_public_https_wss": {},
		"tunnel_https_wss":         {},
		"tunnel_tcp":               {},
		"tunnel_private_tcp":       {},
	}
)

// RequestInfo is safe routing identity supplied by the owner of a request.
// It is intentionally separate from http.Request so hostnames, URLs, headers,
// and body data never enter telemetry by accident. Values with an unknown
// identifier prefix are discarded before an event is constructed.
type RequestInfo struct {
	IDs           edgetelemetry.SafeIDs
	Generations   edgetelemetry.Generations
	CorrelationID string
	RouteKind     string
	Protocol      string
}

// RequestTelemetryConfig wires the producer to the dependency-safe telemetry
// primitives. Metrics and events may independently be nil for composition in
// tests or in a process that only enables one sink.
type RequestTelemetryConfig struct {
	Metrics       *edgetelemetry.Metrics
	Events        *edgetelemetry.EventLog
	Clock         func() time.Time
	Info          RequestInfo
	IDs           edgetelemetry.SafeIDs
	Generations   edgetelemetry.Generations
	CorrelationID string
	RouteKind     string
}

// RequestTelemetry records terminal request/origin outcomes and wraps live
// HTTP forwarding without buffering request or response bodies.
type RequestTelemetry struct {
	metrics *edgetelemetry.Metrics
	events  *edgetelemetry.EventLog
	clock   func() time.Time
	base    RequestInfo
	seq     atomic.Uint64
}

// NewRequestTelemetry constructs a request producer. It never starts a
// goroutine and is safe to share between handlers and transports.
func NewRequestTelemetry(config RequestTelemetryConfig) (*RequestTelemetry, error) {
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
	return &RequestTelemetry{metrics: config.Metrics, events: config.Events, clock: config.Clock, base: base}, nil
}

// NewTelemetry is a concise constructor for callers that assemble several
// edge producers in one package.
func NewTelemetry(config RequestTelemetryConfig) (*RequestTelemetry, error) {
	return NewRequestTelemetry(config)
}

type requestInfoContextKey struct{}

// WithRequestTelemetryInfo associates safe route identity with a request. The
// wrapper copies only this typed value and never serializes the context.
func WithRequestTelemetryInfo(ctx context.Context, info RequestInfo) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestInfoContextKey{}, info)
}

// RequestTelemetryInfo returns the typed request identity, if one was set.
func RequestTelemetryInfo(ctx context.Context) (RequestInfo, bool) {
	if ctx == nil {
		return RequestInfo{}, false
	}
	info, ok := ctx.Value(requestInfoContextKey{}).(RequestInfo)
	return info, ok
}

// Handler wraps an inbound edge handler. It preserves request context,
// streaming writes, trailers, flushing, hijacking, and response interfaces.
func (p *RequestTelemetry) Handler(next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if p == nil || request == nil {
			next.ServeHTTP(writer, request)
			return
		}
		info := p.infoFor(request.Context())
		lifecycle := p.startRequest(request.Context(), info, requestProtocol(request), isWebSocketUpgrade(request.Header))
		wrappedWriter := &requestResponseWriter{ResponseWriter: writer, lifecycle: lifecycle}
		wrappedRequest := request.Clone(request.Context())
		if request.Body != nil {
			wrappedRequest.Body = &requestBody{ReadCloser: request.Body, add: lifecycle.addIngress}
		}
		hijacked := false
		defer func() {
			if wrappedWriter.hijacked.Load() {
				hijacked = true
			}
			if !hijacked {
				lifecycle.finish()
			}
		}()
		next.ServeHTTP(wrappedWriter, wrappedRequest)
	})
}

// WrapHandler is an explicit alias for Handler for assembly code that uses
// Wrap* names for both HTTP sides.
func (p *RequestTelemetry) WrapHandler(next http.Handler) http.Handler {
	return p.Handler(next)
}

// RoundTripper wraps a forwarding transport. It observes request and response
// bytes as they are read, and closes the response lifecycle on EOF, Close, or
// request-context cancellation.
func (p *RequestTelemetry) RoundTripper(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		//paperboat:allow-source-policy default-http owner=edgehttp reason=explicit-roundtripper-fallback
		next = http.DefaultTransport
	}
	return requestRoundTripper{producer: p, next: next}
}

// WrapRoundTripper is an explicit alias for RoundTripper.
func (p *RequestTelemetry) WrapRoundTripper(next http.RoundTripper) http.RoundTripper {
	return p.RoundTripper(next)
}

type requestRoundTripper struct {
	producer *RequestTelemetry
	next     http.RoundTripper
}

func (t requestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.next == nil {
		return nil, ErrInvalidRequestTelemetry
	}
	if request == nil {
		return nil, ErrInvalidRequestTelemetry
	}
	if t.producer == nil {
		return t.next.RoundTrip(request)
	}
	info := t.producer.infoFor(request.Context())
	protocol := requestProtocol(request)
	lifecycle := t.producer.startRequest(request.Context(), info, protocol, isWebSocketUpgrade(request.Header))
	lifecycle.route = info.RouteKind
	if request.Body != nil && request.Body != http.NoBody {
		request = request.Clone(request.Context())
		request.Body = &requestBody{ReadCloser: request.Body, add: lifecycle.addIngress}
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		t.producer.recordOriginFailure(request.Context(), info, protocol, err)
		lifecycle.finishWith(err)
		return nil, err
	}
	originProtocol := responseProtocol(request, response)
	t.producer.recordOriginConnected(info, originProtocol)
	t.producer.recordProtocolUpgrade(request, response, protocol, originProtocol)
	if response == nil {
		lifecycle.finish()
		return nil, nil
	}
	lifecycle.setStatus(response.StatusCode)
	if response.Body == nil {
		response.Body = http.NoBody
	}
	response.Body = newResponseBody(request.Context(), response.Body, lifecycle)
	return response, nil
}

func (p *RequestTelemetry) infoFor(ctx context.Context) RequestInfo {
	info := p.base
	if contextInfo, ok := RequestTelemetryInfo(ctx); ok {
		if contextInfo.IDs != (edgetelemetry.SafeIDs{}) {
			info.IDs = contextInfo.IDs
		}
		if contextInfo.Generations != (edgetelemetry.Generations{}) {
			info.Generations = contextInfo.Generations
		}
		if contextInfo.CorrelationID != "" {
			info.CorrelationID = contextInfo.CorrelationID
		}
		if contextInfo.RouteKind != "" {
			info.RouteKind = contextInfo.RouteKind
		}
		if contextInfo.Protocol != "" {
			info.Protocol = contextInfo.Protocol
		}
	}
	info.IDs = safeRequestIDs(info.IDs)
	if _, ok := requestRouteKinds[info.RouteKind]; !ok {
		info.RouteKind = ""
	}
	if !safeRequestCorrelation(info.CorrelationID) {
		info.CorrelationID = ""
	}
	return info
}

func (p *RequestTelemetry) startRequest(ctx context.Context, info RequestInfo, protocol string, upgraded bool) *requestLifecycle {
	if p == nil {
		return &requestLifecycle{ctx: ctx, protocol: protocol, started: time.Now(), upgraded: upgraded}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if protocol == "" {
		protocol = "http"
	}
	if info.CorrelationID == "" {
		sequence := p.seq.Add(1)
		info.CorrelationID = "corr_edge_request_" + itoa(sequence)
	}
	if info.IDs.RequestID == "" {
		sequence := p.seq.Add(1)
		info.IDs.RequestID = "request_edge_" + itoa(sequence)
	}
	started := p.now()
	lifecycle := &requestLifecycle{producer: p, ctx: ctx, info: info, protocol: protocol, started: started, upgraded: upgraded}
	p.emit(started, requestEventStarted, edgetelemetry.SeverityDebug, edgetelemetry.OutcomeStateChange, requestMessageStarted, info)
	return lifecycle
}

func (p *RequestTelemetry) now() time.Time {
	at := time.Now()
	if p != nil && p.clock != nil {
		at = p.clock()
	}
	if at.IsZero() {
		at = time.Now()
	}
	return at.UTC()
}

func (p *RequestTelemetry) emit(at time.Time, name string, severity edgetelemetry.EventSeverity, outcome edgetelemetry.EventOutcome, message string, info RequestInfo) {
	if p == nil || p.events == nil {
		return
	}
	_, _, _ = p.events.TryRecord(edgetelemetry.EventInput{
		At: at, Severity: severity, Component: edgetelemetry.DimensionEdge,
		Name: name, Code: name, Outcome: outcome, Message: message,
		CorrelationID: info.CorrelationID, IDs: safeRequestIDs(info.IDs), Generations: info.Generations,
		Retry: edgetelemetry.RetryNone,
	})
}

func (p *RequestTelemetry) emitOrigin(at time.Time, name string, severity edgetelemetry.EventSeverity, outcome edgetelemetry.EventOutcome, message string, info RequestInfo) {
	if p == nil || p.events == nil {
		return
	}
	_, _, _ = p.events.TryRecord(edgetelemetry.EventInput{
		At: at, Severity: severity, Component: edgetelemetry.DimensionOrigin,
		Name: name, Code: name, Outcome: outcome, Message: message,
		CorrelationID: info.CorrelationID, IDs: safeRequestIDs(info.IDs), Generations: info.Generations,
		Retry: edgetelemetry.RetryNone,
	})
}

func (p *RequestTelemetry) recordOriginConnected(info RequestInfo, protocol string) {
	if p == nil {
		return
	}
	protocol = normalizeOriginProtocol(protocol)
	if p.metrics != nil {
		_ = p.metrics.IncCounter(edgetelemetry.MetricOriginConnections, edgetelemetry.MetricLabels{
			"protocol": protocol, "outcome": "success",
		})
	}
	p.emitOrigin(p.now(), originEventConnected, edgetelemetry.SeverityDebug, edgetelemetry.OutcomeSuccess, originMessageConnected, info)
}

func (p *RequestTelemetry) recordOriginFailure(ctx context.Context, info RequestInfo, protocol string, err error) {
	if p == nil {
		return
	}
	reason := originFailureReason(err)
	outcome := "failed"
	eventOutcome := edgetelemetry.OutcomeFailed
	severity := edgetelemetry.SeverityWarn
	if errors.Is(err, context.Canceled) || errors.Is(ctxErr(ctx), context.Canceled) {
		outcome = "canceled"
		eventOutcome = edgetelemetry.OutcomeCanceled
	} else if reason == "timeout" {
		outcome = "timeout"
	}
	if p.metrics != nil {
		_ = p.metrics.IncCounter(edgetelemetry.MetricOriginConnections, edgetelemetry.MetricLabels{
			"protocol": normalizeOriginProtocol(protocol), "outcome": outcome,
		})
		if outcome != "canceled" {
			_ = p.metrics.IncCounter(edgetelemetry.MetricOriginFailures, edgetelemetry.MetricLabels{
				"protocol": normalizeOriginProtocol(protocol), "reason": reason,
			})
		}
	}
	p.emitOrigin(p.now(), originEventFailed, severity, eventOutcome, originMessageFailed, info)
}

func (p *RequestTelemetry) recordProtocolUpgrade(request *http.Request, response *http.Response, from, to string) {
	if p == nil || p.metrics == nil {
		return
	}
	if request != nil && isWebSocketUpgrade(request.Header) && response != nil && response.StatusCode == http.StatusSwitchingProtocols {
		from = upgradeFromRequest(request, from)
		if from != "" {
			_ = p.metrics.IncCounter(edgetelemetry.MetricProtocolUpgrades, edgetelemetry.MetricLabels{"from": from, "to": "websocket"})
		}
		return
	}
	from = normalizeUpgradeFrom(from)
	to = normalizeUpgradeTo(to)
	if from == "" || to == "" || from == to {
		return
	}
	_ = p.metrics.IncCounter(edgetelemetry.MetricProtocolUpgrades, edgetelemetry.MetricLabels{"from": from, "to": to})
}

func (p *RequestTelemetry) recordInboundUpgrade(info RequestInfo, request *http.Request) {
	if p == nil || p.metrics == nil || request == nil {
		return
	}
	from := normalizeUpgradeFrom(requestProtocol(request))
	if from == "" {
		from = "http1"
	}
	_ = p.metrics.IncCounter(edgetelemetry.MetricProtocolUpgrades, edgetelemetry.MetricLabels{"from": from, "to": "websocket"})
}

func upgradeFromRequest(request *http.Request, fallback string) string {
	if request != nil {
		if request.ProtoMajor >= 2 {
			return "http2"
		}
		return "http1"
	}
	if fallback == "websocket" {
		return "http1"
	}
	return normalizeUpgradeFrom(fallback)
}

func (p *RequestTelemetry) incrementBytes(direction string, count uint64) {
	if p == nil || p.metrics == nil || count == 0 {
		return
	}
	_ = p.metrics.AddCounter(edgetelemetry.MetricTrafficBytes, edgetelemetry.MetricLabels{"direction": direction}, count)
}

type requestLifecycle struct {
	producer *RequestTelemetry
	ctx      context.Context
	info     RequestInfo
	protocol string
	route    string
	started  time.Time
	upgraded bool
	status   atomic.Int32
	once     sync.Once
}

func (l *requestLifecycle) addIngress(count int) {
	if count > 0 && l != nil && l.producer != nil {
		l.producer.incrementBytes("ingress", uint64(count))
	}
}

func (l *requestLifecycle) addEgress(count int) {
	if count > 0 && l != nil && l.producer != nil {
		l.producer.incrementBytes("egress", uint64(count))
	}
}

func (l *requestLifecycle) setStatus(status int) {
	if l != nil && status > 0 {
		l.status.Store(int32(status))
	}
}

func (l *requestLifecycle) finish() { l.finishWith(nil) }

func (l *requestLifecycle) finishWith(cause error) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		outcome := edgetelemetry.OutcomeSuccess
		name := requestEventCompleted
		severity := edgetelemetry.SeverityDebug
		message := requestMessageComplete
		if ctxErr(l.ctx) != nil || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
			outcome = edgetelemetry.OutcomeCanceled
			name = requestEventCanceled
			severity = edgetelemetry.SeverityWarn
			message = requestMessageCanceled
		} else if cause != nil && !errors.Is(cause, io.EOF) {
			outcome = edgetelemetry.OutcomeFailed
			name = requestEventFailed
			severity = edgetelemetry.SeverityWarn
			message = requestMessageFailed
		} else if status := int(l.status.Load()); status >= http.StatusBadRequest && status < http.StatusInternalServerError {
			outcome = edgetelemetry.OutcomeRejected
			name = requestEventRejected
			severity = edgetelemetry.SeverityWarn
			message = requestMessageRejected
		} else if status := int(l.status.Load()); status >= http.StatusInternalServerError {
			outcome = edgetelemetry.OutcomeFailed
			name = requestEventFailed
			severity = edgetelemetry.SeverityWarn
			message = requestMessageFailed
		}
		if l.producer != nil {
			if l.producer.metrics != nil {
				if l.route != "" {
					_ = l.producer.metrics.IncCounter(edgetelemetry.MetricRouteRequests, edgetelemetry.MetricLabels{
						"route_kind": l.route, "outcome": string(outcome),
					})
					_ = l.producer.metrics.ObserveHistogram(edgetelemetry.MetricStreamDuration, edgetelemetry.MetricLabels{"route_kind": l.info.RouteKind}, l.durationSeconds())
				} else {
					_ = l.producer.metrics.IncCounter(edgetelemetry.MetricEdgeRequests, edgetelemetry.MetricLabels{
						"protocol": normalizeEdgeProtocol(l.protocol), "outcome": string(outcome),
					})
				}
				if outcome == edgetelemetry.OutcomeCanceled {
					_ = l.producer.metrics.IncCounter(edgetelemetry.MetricStreamCancellations, edgetelemetry.MetricLabels{"reason": cancellationReason(l.ctx, cause)})
				}
			}
			l.producer.emit(l.producer.now(), name, severity, outcome, message, l.info)
		}
	})
}

func (l *requestLifecycle) durationSeconds() float64 {
	duration := time.Since(l.started)
	if l.producer != nil {
		at := l.producer.now()
		if at.After(l.started) {
			duration = at.Sub(l.started)
		}
	}
	if duration < 0 {
		return 0
	}
	return duration.Seconds()
}

type requestBody struct {
	io.ReadCloser
	add func(int)
}

func (b *requestBody) Read(payload []byte) (int, error) {
	if b == nil || b.ReadCloser == nil {
		return 0, io.EOF
	}
	n, err := b.ReadCloser.Read(payload)
	if n > 0 && b.add != nil {
		b.add(n)
	}
	return n, err
}

type responseBody struct {
	body      io.ReadCloser
	lifecycle *requestLifecycle
	stop      func() bool
	once      sync.Once
	err       error
}

func newResponseBody(ctx context.Context, body io.ReadCloser, lifecycle *requestLifecycle) io.ReadCloser {
	wrapped := &responseBody{body: body, lifecycle: lifecycle}
	if ctx == nil {
		ctx = context.Background()
	}
	wrapped.stop = context.AfterFunc(ctx, func() {
		if wrapped.lifecycle != nil {
			wrapped.lifecycle.finishWith(ctx.Err())
		}
		_ = wrapped.Close()
	})
	return wrapped
}

func (b *responseBody) Read(payload []byte) (int, error) {
	if b == nil || b.body == nil {
		return 0, io.EOF
	}
	n, err := b.body.Read(payload)
	if b.lifecycle != nil {
		b.lifecycle.addEgress(n)
	}
	if err != nil {
		b.finish(err)
	}
	return n, err
}

func (b *responseBody) WriteTo(writer io.Writer) (int64, error) {
	if b == nil || b.body == nil {
		return 0, io.EOF
	}
	counting := responseCountingWriter{Writer: writer, lifecycle: b.lifecycle}
	var n int64
	var err error
	if source, ok := b.body.(io.WriterTo); ok {
		n, err = source.WriteTo(&counting)
	} else {
		n, err = io.Copy(&counting, b.body)
	}
	if err != nil {
		b.finish(err)
	} else {
		b.finish(nil)
	}
	return n, err
}

func (b *responseBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		if b.stop != nil {
			b.stop()
		}
		if b.body != nil {
			b.err = b.body.Close()
		}
		b.finish(b.err)
	})
	return b.err
}

func (b *responseBody) finish(err error) {
	if b == nil || b.lifecycle == nil {
		return
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	b.lifecycle.finishWith(err)
}

type responseCountingWriter struct {
	io.Writer
	lifecycle *requestLifecycle
}

func (w *responseCountingWriter) Write(payload []byte) (int, error) {
	if w == nil || w.Writer == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := w.Writer.Write(payload)
	if w.lifecycle != nil {
		w.lifecycle.addEgress(n)
	}
	return n, err
}

type requestResponseWriter struct {
	http.ResponseWriter
	lifecycle *requestLifecycle
	hijacked  atomic.Bool
	wroteHead atomic.Bool
}

func (w *requestResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *requestResponseWriter) WriteHeader(status int) {
	if w == nil || w.ResponseWriter == nil {
		return
	}
	if w.wroteHead.CompareAndSwap(false, true) {
		if w.lifecycle != nil {
			w.lifecycle.setStatus(status)
		}
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *requestResponseWriter) Write(payload []byte) (int, error) {
	if w == nil || w.ResponseWriter == nil {
		return 0, io.ErrClosedPipe
	}
	if !w.wroteHead.Load() {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(payload)
	if w.lifecycle != nil {
		w.lifecycle.addEgress(n)
		if err != nil {
			w.lifecycle.finishWith(err)
		}
	}
	return n, err
}

func (w *requestResponseWriter) Flush() {
	_ = w.FlushError()
}

func (w *requestResponseWriter) FlushError() error {
	if !w.wroteHead.Load() {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(interface{ FlushError() error }); ok {
		return flusher.FlushError()
	}
	flusher, ok := w.ResponseWriter.(http.Flusher)
	if !ok {
		return http.ErrNotSupported
	}
	flusher.Flush()
	return nil
}

func (w *requestResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.hijacked.Store(true)
	if w.lifecycle != nil {
		w.lifecycle.setStatus(http.StatusSwitchingProtocols)
		if w.lifecycle.producer != nil && w.lifecycle.upgraded {
			w.lifecycle.producer.recordInboundUpgrade(w.lifecycle.info, nil)
		}
	}
	return &trackedConn{Conn: connection, lifecycle: w.lifecycle}, buffered, nil
}

func (w *requestResponseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *requestResponseWriter) ReadFrom(source io.Reader) (int64, error) {
	if !w.wroteHead.Load() {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		counting := requestCountingReader{Reader: source, lifecycle: w.lifecycle}
		n, err := readerFrom.ReadFrom(&counting)
		if err != nil && w.lifecycle != nil {
			w.lifecycle.finishWith(err)
		}
		return n, err
	}
	return io.Copy(w, source)
}

func (w *requestResponseWriter) EnableFullDuplex() error {
	if duplex, ok := w.ResponseWriter.(interface{ EnableFullDuplex() error }); ok {
		return duplex.EnableFullDuplex()
	}
	return nil
}

func (w *requestResponseWriter) Unwrap() http.ResponseWriter {
	if w == nil {
		return nil
	}
	return w.ResponseWriter
}

type requestCountingReader struct {
	io.Reader
	lifecycle *requestLifecycle
}

func (r *requestCountingReader) Read(payload []byte) (int, error) {
	n, err := r.Reader.Read(payload)
	if r.lifecycle != nil {
		r.lifecycle.addEgress(n)
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	lifecycle *requestLifecycle
	once      sync.Once
	closeErr  error
}

func (c *trackedConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if c.lifecycle != nil {
		c.lifecycle.addIngress(n)
		if err != nil {
			c.lifecycle.finishWith(err)
		}
	}
	return n, err
}

func (c *trackedConn) Write(payload []byte) (int, error) {
	n, err := c.Conn.Write(payload)
	if c.lifecycle != nil {
		c.lifecycle.addEgress(n)
		if err != nil {
			c.lifecycle.finishWith(err)
		}
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		if c.lifecycle != nil {
			c.lifecycle.finishWith(c.closeErr)
		}
	})
	return c.closeErr
}

func requestProtocol(request *http.Request) string {
	if request == nil {
		return "http"
	}
	if isWebSocketUpgrade(request.Header) {
		return "websocket"
	}
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func responseProtocol(request *http.Request, response *http.Response) string {
	if request != nil && isWebSocketUpgrade(request.Header) && response != nil && response.StatusCode == http.StatusSwitchingProtocols {
		return "websocket"
	}
	if response != nil && response.ProtoMajor >= 2 {
		if request != nil && request.URL != nil && strings.EqualFold(request.URL.Scheme, "http") {
			return "h2c"
		}
		return "http2"
	}
	return "http1"
}

func normalizeEdgeProtocol(protocol string) string {
	switch protocol {
	case "http", "https", "tcp", "websocket":
		return protocol
	default:
		return "http"
	}
}

func normalizeOriginProtocol(protocol string) string {
	switch protocol {
	case "http1", "http2", "h2c", "tcp", "websocket":
		return protocol
	default:
		return "http1"
	}
}

func normalizeUpgradeFrom(protocol string) string {
	switch protocol {
	case "http1", "http2", "h2c", "tcp":
		return protocol
	case "http", "https":
		return "http1"
	default:
		return ""
	}
}

func normalizeUpgradeTo(protocol string) string {
	switch protocol {
	case "http2", "h2c", "websocket", "tcp":
		return protocol
	default:
		return ""
	}
}

func originFailureReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	var tlsError *tls.CertificateVerificationError
	if errors.As(err, &tlsError) {
		return "tls"
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) && operationError.Op == "crypto/tls" {
		return "tls"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "reset"
	}
	if err == nil {
		return "unknown"
	}
	return "unavailable"
}

func cancellationReason(ctx context.Context, cause error) string {
	switch {
	case errors.Is(ctxErr(ctx), context.DeadlineExceeded):
		return "timeout"
	case errors.Is(ctxErr(ctx), context.Canceled):
		return "client"
	case errors.Is(cause, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(cause, context.Canceled):
		return "client"
	default:
		return "unknown"
	}
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func safeRequestCorrelation(value string) bool {
	return requestTelemetryIDPattern.MatchString(value) && (strings.HasPrefix(value, "corr_") || strings.HasPrefix(value, "cor_") || strings.HasPrefix(value, "correlation_") || strings.HasPrefix(value, "request_") || strings.HasPrefix(value, "pb-"))
}

func safeRequestIDs(ids edgetelemetry.SafeIDs) edgetelemetry.SafeIDs {
	ids.AccountID = safeRequestID(ids.AccountID, "account_")
	ids.ActorID = safeRequestID(ids.ActorID, "actor_")
	ids.TunnelID = safeRequestID(ids.TunnelID, "tunnel_")
	ids.RouteID = safeRequestID(ids.RouteID, "route_")
	ids.ConnectorID = safeRequestID(ids.ConnectorID, "connector_")
	ids.DomainID = safeRequestID(ids.DomainID, "domain_")
	ids.CertificateID = safeRequestID(ids.CertificateID, "certificate_")
	ids.AssignmentID = safeRequestID(ids.AssignmentID, "assignment_")
	ids.HostID = safeRequestID(ids.HostID, "host_")
	ids.DeviceID = safeRequestID(ids.DeviceID, "device_")
	ids.SessionID = safeRequestID(ids.SessionID, "session_", "carrier_")
	ids.OperationID = safeRequestID(ids.OperationID, "operation_", "op_")
	ids.RequestID = safeRequestID(ids.RequestID, "request_", "req_")
	ids.EdgeNodeID = safeRequestID(ids.EdgeNodeID, "edge_")
	return ids
}

func safeRequestID(value string, prefixes ...string) string {
	if value == "" || !requestTelemetryIDPattern.MatchString(value) {
		return ""
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return value
		}
	}
	return ""
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
