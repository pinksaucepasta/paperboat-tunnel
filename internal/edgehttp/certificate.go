package edgehttp

import (
	"net"
	"net/http"
	"strings"
)

type routeState interface {
	RouteState(string) (string, string, string, bool)
}

func WithCertificateAsk(next http.Handler, routes routeState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/private/certificate-ask" {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if r.Method != http.MethodGet || routes == nil || err != nil || !net.ParseIP(host).IsLoopback() {
			http.NotFound(w, r)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		kind, _, _, found := routes.RouteState(domain)
		if !found || (kind != "runtime_https_wss" && kind != "preview_public_https_wss") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
