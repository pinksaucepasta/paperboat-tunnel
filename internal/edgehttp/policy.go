package edgehttp

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- required by RFC 6455 for the WebSocket handshake.
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

type Config struct {
	PreviewBaseDomain string
	HelperBaseDomain  string
	TrustedProxies    []*net.IPNet
	MaxHeaderBytes    int64
	MaxBodyBytes      int64
	Readiness         interface {
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

type Policy struct {
	config Config
	next   http.Handler
}

func New(config Config, next http.Handler) (*Policy, error) {
	if next == nil || config.PreviewBaseDomain == "" || config.HelperBaseDomain == "" || config.MaxHeaderBytes < 1024 || config.MaxBodyBytes < 1 {
		return nil, http.ErrNotSupported
	}
	return &Policy{config: config, next: next}, nil
}

// NewGateway builds the live public-preview gate. The target is the private
// frps vhost; this handler never contacts the control plane or carries policy
// data outside the edge process.
func NewGateway(config Config, privateUpstream string) (*Policy, error) {
	target, err := url.Parse("http://" + privateUpstream)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("X-Robots-Tag")
		return nil
	}
	return New(config, proxy)
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
	if !ok || r.URL.IsAbs() || headerBytes(r.Header) > p.config.MaxHeaderBytes {
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
	stripPrivate(r.Header, expectedKind)
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxBodyBytes)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if p.config.Readiness != nil {
		kind, state, reason, found := p.config.Readiness.RouteState(host)
		if !found || kind != expectedKind {
			http.NotFound(w, r)
			return
		}
		if kind == "runtime_https_wss" && state != "ready" {
			w.Header().Set("Retry-After", "5")
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if kind == "preview_public_https_wss" && state != "ready" {
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
	return path == "/v1/runtime" || path == "/v1/preview-launches" || path == "/v1/file-transfers" || strings.HasPrefix(path, "/v1/file-transfers/") || codexSessionPath(path)
}

func credentialAllowsHelperPath(class, path string) bool {
	switch {
	case path == "/v1/runtime":
		return class == "terminal_operation"
	case path == "/v1/preview-launches":
		return class == "preview_launch"
	case path == "/v1/file-transfers" || strings.HasPrefix(path, "/v1/file-transfers/"):
		return class == "file_transfer"
	case codexSessionPath(path):
		return class == "codex_connect" || class == "codex_manage"
	default:
		return false
	}
}

func codexSessionPath(path string) bool {
	const prefix = "/v1/codex-sessions/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	remainder := strings.TrimPrefix(path, prefix)
	parts := strings.Split(remainder, "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	return parts[1] == "ws" || parts[1] == "renew" || parts[1] == "directories"
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
		{p.config.HelperBaseDomain, "runtime_https_wss"},
	} {
		suffix := "." + strings.ToLower(candidate.domain)
		prefix, ok := strings.CutSuffix(host, suffix)
		if ok && prefix != "" && !strings.Contains(prefix, ".") && net.ParseIP(host) == nil {
			return host, candidate.kind, true
		}
	}
	return host, "", false
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
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate != nil && !p.trusted(candidate) {
			return candidate.String()
		}
	}
	return remote.String()
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
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
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
