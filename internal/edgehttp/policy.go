package edgehttp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- required by RFC 6455 for the WebSocket handshake.
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
	"github.com/realclientip/realclientip-go"
)

// RouteMatcher is the live edge route boundary. Implementations must return
// a generation-fenced match and a lease that remains valid for the request's
// lifetime.
type RouteMatcher interface {
	Match(string, string) (route.RouteMatch, error)
	Acquire(context.Context, string, string) (*route.StreamLease, route.RouteMatch, error)
}

type Config struct {
	PreviewBaseDomain        string
	TunnelBaseDomain         string
	RuntimeBaseDomain        string
	TrustedProxies           []*net.IPNet
	MaxHeaderBytes           int64
	MaxBodyBytes             int64
	Routes                   RouteMatcher
	PrivateAccessToken       string
	PrivateAccessConnections *PrivateAccessConnectionRegistry
	RequestID                func() string
	Readiness                interface {
		RouteState(string) (string, string, string, bool)
	}
	HelperAccess interface {
		VerifyHelperAccess(context.Context, string) (admission.Claims, error)
	}
	Revocations interface {
		Revoked(context.Context, admission.Claims) (bool, error)
	}
	RevocationCheckInterval time.Duration
}

type routeMatchContextKey struct{}

// RouteMatchFromContext returns the generation-fenced match selected by the
// edge policy, if this request passed through a configured route matcher.
func RouteMatchFromContext(ctx context.Context) (route.RouteMatch, bool) {
	if ctx == nil {
		return route.RouteMatch{}, false
	}
	match, ok := ctx.Value(routeMatchContextKey{}).(route.RouteMatch)
	return match, ok
}

type Policy struct {
	config         Config
	next           http.Handler
	clientStrategy realclientip.Strategy
}

func New(config Config, next http.Handler) (*Policy, error) {
	if next == nil || config.PreviewBaseDomain == "" || config.TunnelBaseDomain == "" || config.RuntimeBaseDomain == "" || config.MaxHeaderBytes < 1024 || config.MaxBodyBytes < 1 || config.PrivateAccessToken != "" && (len(config.PrivateAccessToken) < 32 || len(config.PrivateAccessToken) > 256 || strings.TrimSpace(config.PrivateAccessToken) != config.PrivateAccessToken || strings.ContainsAny(config.PrivateAccessToken, "\r\n\x00")) {
		return nil, http.ErrNotSupported
	}
	trusted := make([]net.IPNet, 0, len(config.TrustedProxies))
	for _, network := range config.TrustedProxies {
		if network == nil {
			return nil, http.ErrNotSupported
		}
		trusted = append(trusted, *network)
	}
	strategy, err := realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", trusted)
	if err != nil {
		return nil, err
	}
	return &Policy{config: config, next: next, clientStrategy: strategy}, nil
}

// NewGateway builds the live public-preview gate. The target is the private
// frps vhost; this handler never contacts the control plane or carries policy
// data outside the edge process.
func NewGateway(config Config, privateUpstream string) (*Policy, error) {
	return NewGatewayWithTransport(config, privateUpstream, nil)
}

func NewGatewayWithTransport(config Config, privateUpstream string, previewTransport http.RoundTripper) (*Policy, error) {
	return NewGatewayWithTransports(config, privateUpstream, previewTransport, nil)
}

// NewGatewayWithTransports installs the route-kind-specific forwarding
// boundaries. Durable connector-v1 routes use canonicalTransport, while
// preview routes use previewTransport and retained helper routes use the
// private legacy upstream. A matched durable route is never silently sent to
// the legacy or preview transport when its canonical transport is absent.
func NewGatewayWithTransports(config Config, privateUpstream string, previewTransport, canonicalTransport http.RoundTripper) (*Policy, error) {
	target, err := url.Parse("http://" + privateUpstream)
	if err != nil {
		return nil, err
	}
	legacy := httputil.NewSingleHostReverseProxy(target)
	legacy.FlushInterval = -1
	legacy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("X-Robots-Tag")
		return nil
	}
	var canonical http.Handler
	if canonicalTransport != nil {
		canonical = &httputil.ReverseProxy{
			Transport:     canonicalTransport,
			FlushInterval: -1,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.Out.URL.Scheme = "http"
				request.Out.URL.Host = request.In.Host
			},
			ModifyResponse: legacy.ModifyResponse,
		}
	}
	var next http.Handler = legacy
	if previewTransport != nil || canonicalTransport != nil {
		var preview http.Handler
		if previewTransport != nil {
			preview = &httputil.ReverseProxy{
				Transport:     retryPreviewTransport{next: previewTransport},
				FlushInterval: -1,
				Rewrite: func(request *httputil.ProxyRequest) {
					request.Out.URL.Scheme = "http"
					request.Out.URL.Host = request.In.Host
				},
				ModifyResponse: legacy.ModifyResponse,
			}
		}
		next = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if match, ok := RouteMatchFromContext(request.Context()); ok {
				switch match.Rule.Kind {
				case route.TunnelHTTPSWSS:
					if canonical == nil {
						http.NotFound(writer, request)
						return
					}
					canonical.ServeHTTP(writer, request)
					return
				case route.PreviewHTTPSWSS, route.Kind(dataCarrierPreviewPrivateRouteKind):
					if preview != nil {
						preview.ServeHTTP(writer, request)
						return
					}
				}
			}
			if preview != nil && strings.HasSuffix(strings.ToLower(request.Host), "."+strings.ToLower(config.PreviewBaseDomain)) {
				preview.ServeHTTP(writer, request)
				return
			}
			legacy.ServeHTTP(writer, request)
		})
	}
	return New(config, next)
}

type retryPreviewTransport struct{ next http.RoundTripper }

func (t retryPreviewTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err == nil || !retryablePreviewRequest(request) || !retryablePreviewTransportError(err) {
		return response, err
	}
	return t.next.RoundTrip(request.Clone(request.Context()))
}

func retryablePreviewRequest(request *http.Request) bool {
	if request == nil || request.Body != nil && request.Body != http.NoBody || isWebSocketUpgrade(request.Header) {
		return false
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func retryablePreviewTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func ParseTrustedProxies(values []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		result = append(result, network)
	}
	return result, nil
}

func (p *Policy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, expectedKind, ok := p.allowedHost(r.Host)
	var matched route.RouteMatch
	var lease *route.StreamLease
	if p.config.Routes != nil {
		ok = false
		candidateHost, valid := dispatchHost(r.Host)
		if !valid {
			http.NotFound(w, r)
			return
		}
		candidateLease, acquired, acquireErr := p.config.Routes.Acquire(r.Context(), candidateHost, r.URL.Path)
		if acquireErr != nil {
			http.NotFound(w, r)
			return
		}
		matched, lease = acquired, candidateLease
		host, expectedKind, ok = matched.Host, string(matched.Rule.Kind), true
		if expectedKind == string(route.TunnelHTTPSWSS) && (matched.Rule.MatchType == route.MatchManagedExact || strings.HasSuffix(host, "."+strings.ToLower(p.config.TunnelBaseDomain))) && !route.ValidManagedTunnelHostname(host, p.config.TunnelBaseDomain) {
			http.NotFound(w, r)
			return
		}
		r = r.WithContext(context.WithValue(lease.Context(), routeMatchContextKey{}, matched))
		defer lease.Close()
	}
	if !ok || !normalizeRequestTarget(r, host) || headerBytes(r.Header) > p.config.MaxHeaderBytes {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > p.config.MaxBodyBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	clientIP := p.clientIP(r)
	websocket := isWebSocketUpgrade(r.Header)
	stripHopByHop(r.Header)
	if websocket {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
	}
	privateRoute := matched.Rule.AccessMode == "private" && (expectedKind == dataCarrierPreviewPrivateRouteKind || expectedKind == string(route.TunnelHTTPSWSS))
	if privateRoute {
		// Private routes are reachable only through stable hostd's authenticated
		// client-initiated carrier stream. Public edge requests never become
		// private access based on browser cookies, Authorization, or custom
		// headers.
		connectionID := r.Header.Get("X-Paperboat-Private-Connection")
		if !p.consumePrivateCarrierToken(r.Header) {
			stripPrivate(r.Header, expectedKind)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		r.Header.Del("X-Paperboat-Private-Connection")
		if p.config.PrivateAccessConnections == nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		status, allowed := p.config.PrivateAccessConnections.Authorize(connectionID, matched)
		if !allowed {
			http.Error(w, http.StatusText(status), status)
			return
		}
	}
	stripPrivate(r.Header, expectedKind)
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Proto", "https")
	requestID, requestIDErr := p.trustedRequestID()
	if requestIDErr != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	r.Header.Set("Forwarded", formatForwarded(clientIP, host))
	r.Header.Set("X-Request-ID", requestID)
	if matched.Rule.HostOverride != "" {
		r.Host = matched.Rule.HostOverride
	}
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxBodyBytes)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if p.config.Readiness != nil || matched.Rule.ID != "" {
		kind, state, reason, found := "", "", "", false
		if matched.Rule.ID != "" && matched.Rule.ObservedState != "" {
			kind, state, reason, found = string(matched.Rule.Kind), matched.Rule.ObservedState, matched.Rule.Reason, true
		} else if p.config.Readiness != nil {
			kind, state, reason, found = p.config.Readiness.RouteState(host)
		} else if matched.Rule.ID != "" {
			kind, state, found = string(matched.Rule.Kind), "ready", true
		}
		if !found || kind != expectedKind {
			http.NotFound(w, r)
			return
		}
		if kind == "runtime_https_wss" && state != "ready" {
			w.Header().Set("Retry-After", "5")
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if (kind == "preview_public_https_wss" || kind == dataCarrierPreviewPrivateRouteKind) && state != "ready" {
			status, retry := PreviewHTTPStatus(state, reason)
			if retry {
				w.Header().Set("Retry-After", "5")
			}
			if websocket && retry && closeRetryableWebSocket(w, r) {
				return
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
	}
	if expectedKind == "runtime_https_wss" && !helperPublicPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if expectedKind == "runtime_https_wss" && helperAccessPath(r.URL.Path) {
		claims, ok := p.authorizeHelperAccess(w, r)
		if !ok {
			return
		}
		if !credentialAllowsHelperPath(claims.CredentialClass, r.URL.Path) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		r = r.WithContext(ctx)
		go p.cancelWhenAccessRevoked(ctx, cancel, claims)
	}
	p.next.ServeHTTP(w, r)
}

func (p *Policy) consumePrivateCarrierToken(headers http.Header) bool {
	if p == nil || headers == nil {
		return false
	}
	values := headers.Values("X-Paperboat-Private-Carrier")
	headers.Del("X-Paperboat-Private-Carrier")
	if len(values) != 1 || len(values[0]) != len(p.config.PrivateAccessToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(values[0]), []byte(p.config.PrivateAccessToken)) == 1
}

func normalizeRequestTarget(r *http.Request, canonicalHost string) bool {
	if !r.URL.IsAbs() {
		return true
	}
	absoluteHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Host), "."))
	if parsed, _, err := net.SplitHostPort(absoluteHost); err == nil {
		absoluteHost = parsed
	}
	if !strings.EqualFold(r.URL.Scheme, "https") || absoluteHost != canonicalHost || r.URL.User != nil {
		return false
	}
	r.URL.Scheme = ""
	r.URL.Host = ""
	return true
}

func helperPublicPath(path string) bool {
	return path == "/healthz" || helperAccessPath(path)
}

func (p *Policy) authorizeHelperAccess(w http.ResponseWriter, r *http.Request) (admission.Claims, bool) {
	if p.config.HelperAccess == nil || p.config.Revocations == nil || p.config.RevocationCheckInterval <= 0 {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return admission.Claims{}, false
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) != token || token == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return admission.Claims{}, false
	}
	claims, err := p.config.HelperAccess.VerifyHelperAccess(r.Context(), token)
	if err != nil || claims.Revoked {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return admission.Claims{}, false
	}
	return claims, true
}

func (p *Policy) cancelWhenAccessRevoked(ctx context.Context, cancel context.CancelFunc, claims admission.Claims) {
	ticker := time.NewTicker(p.config.RevocationCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			revoked, err := p.config.Revocations.Revoked(ctx, claims)
			if err != nil || revoked {
				cancel()
				return
			}
		}
	}
}

func helperAccessPath(path string) bool {
	return path == "/v1/runtime" || path == "/v1/preview-launches" || path == "/v1/file-transfers" || strings.HasPrefix(path, "/v1/file-transfers/")
}

func credentialAllowsHelperPath(class, path string) bool {
	switch {
	case path == "/v1/runtime":
		return class == "terminal_operation"
	case path == "/v1/preview-launches":
		return class == "preview_launch"
	case path == "/v1/file-transfers" || strings.HasPrefix(path, "/v1/file-transfers/"):
		return class == "file_transfer"
	default:
		return false
	}
}

func closeRetryableWebSocket(w http.ResponseWriter, r *http.Request) bool {
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return false
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return false
	}
	defer connection.Close()
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- mandated by RFC 6455.
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\nX-Robots-Tag: noindex, nofollow, noarchive\r\n\r\n"); err != nil {
		return true
	}
	payload := make([]byte, 2+len("Try Again Later"))
	binary.BigEndian.PutUint16(payload, 1013)
	copy(payload[2:], "Try Again Later")
	_ = writeWebSocketClose(buffer, payload)
	return true
}

func writeWebSocketClose(writer *bufio.ReadWriter, payload []byte) error {
	if err := writer.WriteByte(0x88); err != nil {
		return err
	}
	if err := writer.WriteByte(byte(len(payload))); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}

func PreviewHTTPStatus(state, reason string) (int, bool) {
	switch state {
	case "registering":
		return http.StatusServiceUnavailable, true
	case "degraded":
		if reason == "target_unhealthy" {
			return http.StatusBadGateway, false
		}
		return http.StatusServiceUnavailable, true
	case "offline":
		return http.StatusServiceUnavailable, true
	case "expired":
		return http.StatusGone, false
	case "removed", "":
		return http.StatusNotFound, false
	case "ready":
		return http.StatusOK, false
	default:
		return http.StatusNotFound, false
	}
}

func (p *Policy) allowedHost(value string) (string, string, bool) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	for _, candidate := range []struct{ domain, kind string }{
		{p.config.PreviewBaseDomain, "preview_public_https_wss"},
		{p.config.RuntimeBaseDomain, "runtime_https_wss"},
	} {
		suffix := "." + strings.ToLower(candidate.domain)
		prefix, ok := strings.CutSuffix(host, suffix)
		if ok && prefix != "" && !strings.Contains(prefix, ".") && net.ParseIP(host) == nil {
			return host, candidate.kind, true
		}
	}
	return host, "", false
}

func dispatchHost(value string) (string, bool) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host == "" || strings.ContainsAny(host, "\r\n\x00 /?") {
		return "", false
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else if strings.Contains(host, ":") {
		return "", false
	}
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}
	return host, true
}

func (p *Policy) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remote := net.ParseIP(remoteHost)
	if remote == nil || !p.trusted(remote) {
		return remoteHost
	}
	if client := p.clientStrategy.ClientIP(r.Header, r.RemoteAddr); client != "" {
		return client
	}
	return remote.String()
}

func (p *Policy) trustedRequestID() (string, error) {
	if p.config.RequestID != nil {
		if value := p.config.RequestID(); validRequestID(value) {
			return value, nil
		}
	}
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.:", character)) {
			return false
		}
	}
	return true
}

func formatForwarded(clientIP, host string) string {
	forValue := "_"
	if parsed := net.ParseIP(strings.TrimSpace(clientIP)); parsed != nil {
		forValue = parsed.String()
		if parsed.To4() == nil {
			forValue = "\"[" + forValue + "]\""
		}
	}
	if host == "" || strings.ContainsAny(host, "\r\n\x00;,") {
		host = "_"
	}
	return "for=" + forValue + ";proto=https;host=" + host
}

func (p *Policy) trusted(ip net.IP) bool {
	for _, network := range p.config.TrustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func headerBytes(headers http.Header) int64 {
	var size int64
	for name, values := range headers {
		size += int64(len(name))
		for _, value := range values {
			size += int64(len(value))
		}
	}
	return size
}

func stripHopByHop(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Request-ID"} {
		headers.Del(name)
	}
}

var helperOperationHeaders = map[string]struct{}{
	"x-paperboat-request-id":   {},
	"x-paperboat-operation-id": {},
	"x-paperboat-deadline-ms":  {},
	"x-paperboat-file-name":    {},
	"x-paperboat-file-mime":    {},
	"x-paperboat-file-size":    {},
	"x-paperboat-file-sha256":  {},
}

func stripPrivate(headers http.Header, routeKind string) {
	for name := range headers {
		normalized := strings.ToLower(name)
		if !strings.HasPrefix(normalized, "x-paperboat-") {
			continue
		}
		_, helperOperationHeader := helperOperationHeaders[normalized]
		if routeKind != "runtime_https_wss" || !helperOperationHeader {
			headers.Del(name)
		}
	}
}

func isWebSocketUpgrade(headers http.Header) bool {
	if !strings.EqualFold(strings.TrimSpace(headers.Get("Upgrade")), "websocket") {
		return false
	}
	for _, value := range strings.Split(headers.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(value), "upgrade") {
			return true
		}
	}
	return false
}
