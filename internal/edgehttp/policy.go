package edgehttp

import (
	"net"
	"net/http"
	"strings"
)

type Config struct {
	WildcardHost   string
	TrustedProxies []*net.IPNet
	MaxHeaderBytes int64
	MaxBodyBytes   int64
}

type Policy struct {
	config Config
	next   http.Handler
}

func New(config Config, next http.Handler) (*Policy, error) {
	if next == nil || !strings.HasPrefix(config.WildcardHost, "*.") || config.MaxHeaderBytes < 1024 || config.MaxBodyBytes < 1 {
		return nil, http.ErrNotSupported
	}
	return &Policy{config: config, next: next}, nil
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
	host, ok := p.allowedHost(r.Host)
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
	stripPrivate(r.Header)
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxBodyBytes)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	p.next.ServeHTTP(w, r)
}

func (p *Policy) allowedHost(value string) (string, bool) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	suffix := strings.TrimPrefix(strings.ToLower(p.config.WildcardHost), "*")
	prefix, ok := strings.CutSuffix(host, suffix)
	return host, ok && prefix != "" && !strings.Contains(prefix, ".") && net.ParseIP(host) == nil
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

func stripPrivate(headers http.Header) {
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-paperboat-") {
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
