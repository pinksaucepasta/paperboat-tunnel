package edgehttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

const browserCallbackPath = "/.paperboat/access/callback"
const browserEdgeCookie = "__Host-pb-edge"
const browserHandoffCookie = "__Host-pb-handoff"

type BrowserAuthority interface {
	Begin(context.Context, string, string) (control.BrowserBegin, error)
	Redeem(context.Context, string, string, string, string) (control.BrowserSession, error)
	Authorize(context.Context, control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error)
}

type LazyAuthority interface {
	Activate(context.Context, control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error)
}

// BrowserAccess is installed only after the managed hostname isolation gate.
// Tests use isolated HTTPS origins; insecure development is not a rollout mode.
type BrowserAccess struct {
	Authority     BrowserAuthority
	LazyAuthority LazyAuthority
	LoginOrigin   string
}
type browserDecisionKey struct{}

func reservedBrowserCookie(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "__host-pb-") || strings.HasPrefix(n, "pb-dev-") || strings.HasPrefix(n, "paperboat_")
}
func stripBrowserRequestCredentials(h http.Header) {
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "paperboat-") {
			h.Del(name)
		}
	}
	var cookies []string
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && !reservedBrowserCookie(name) {
				cookies = append(cookies, strings.TrimSpace(part))
			}
		}
	}
	h.Del("Cookie")
	if len(cookies) > 0 {
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
}
func stripBrowserResponseCredentials(h http.Header) {
	values := h.Values("Set-Cookie")
	h.Del("Set-Cookie")
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if ok && !reservedBrowserCookie(strings.TrimSpace(name)) {
			h.Add("Set-Cookie", value)
		}
	}
	for name := range h {
		n := strings.ToLower(name)
		if strings.HasPrefix(n, "paperboat-") || strings.HasPrefix(n, "x-paperboat-") {
			h.Del(name)
		}
	}
}

func (b *BrowserAccess) validate() bool {
	if b == nil || b.Authority == nil {
		return false
	}
	u, err := url.Parse(b.LoginOrigin)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.String() == b.LoginOrigin
}

func browserCookie(r *http.Request, name string) (string, bool) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			count++
			value = c.Value
		}
	}
	return value, count == 1 && value != ""
}
func browserReservedDuplicates(r *http.Request) bool {
	seen := map[string]bool{}
	for _, c := range r.Cookies() {
		if strings.HasPrefix(strings.ToLower(c.Name), "__host-pb-") {
			if seen[c.Name] {
				return true
			}
			seen[c.Name] = true
		}
	}
	return false
}
func browserSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func clearBrowserHandoff(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: browserHandoffCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, MaxAge: -1})
}

// callback runs before route readiness or acquisition and never reaches an app.
func (b *BrowserAccess) callback(w http.ResponseWriter, r *http.Request) {
	browserSecurityHeaders(w)
	if !b.validate() {
		http.Error(w, "Browser access unavailable", 503)
		return
	}
	if r.Method != http.MethodPost || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != b.LoginOrigin || browserReservedDuplicates(r) {
		http.Error(w, "Invalid login return", 403)
		return
	}
	state, ok := browserCookie(r, browserHandoffCookie)
	if !ok {
		http.Error(w, "Login transaction expired", 401)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || len(r.PostForm) != 2 || len(r.PostForm["transaction_id"]) != 1 || len(r.PostForm["handoff"]) != 1 {
		http.Error(w, "Invalid login return", 400)
		return
	}
	transaction, nonce, found := strings.Cut(state, ".")
	if !found || transaction != r.PostForm.Get("transaction_id") {
		http.Error(w, "Invalid login return", 403)
		return
	}
	host, valid := dispatchHost(r.Host)
	if !valid || r.Host != host {
		http.Error(w, "Invalid login return", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	session, err := b.Authority.Redeem(ctx, transaction, nonce, r.PostForm.Get("handoff"), host)
	clearBrowserHandoff(w)
	if err != nil {
		browserError(w, r, err)
		return
	}
	if session.Token == "" || !session.ExpiresAt.After(time.Now()) || !safeBrowserReturn(session.ReturnPath) {
		http.Error(w, "Browser access unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: browserEdgeCookie, Value: session.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
	http.Redirect(w, r, session.ReturnPath, http.StatusSeeOther)
}
func safeBrowserReturn(path string) bool {
	if len(path) == 0 || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n\x00") {
		return false
	}
	u, err := url.ParseRequestURI(path)
	return err == nil && !u.IsAbs() && u.Host == "" && u.User == nil && !strings.HasPrefix(u.Path, "//") && !strings.ContainsAny(u.Path, "\\\r\n\x00")
}
func browserNavigation(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document" && !isWebSocketUpgrade(r.Header)
}
func browserError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, control.ErrBrowserUnauthenticated):
		http.Error(w, "Authentication required", 401)
	case errors.Is(err, control.ErrBrowserDenied):
		http.NotFound(w, r)
	default:
		http.Error(w, "Browser authorization unavailable", 503)
	}
}

func lazyActivationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, control.ErrBrowserUnauthenticated):
		http.Error(w, "Authentication required", http.StatusUnauthorized)
	case errors.Is(err, control.ErrBrowserDenied):
		http.NotFound(w, r)
	case errors.Is(err, control.ErrLazyGenerationConflict):
		http.Error(w, "Preview policy generation changed", http.StatusConflict)
	case errors.Is(err, control.ErrLazyCapacity):
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Lazy preview activation capacity exceeded", http.StatusTooManyRequests)
	case errors.Is(err, control.ErrLazyForwardingFailed):
		http.Error(w, "Preview forwarding failed; no request was replayed", http.StatusServiceUnavailable)
	case errors.Is(err, control.ErrLazyCooldown):
		w.Header().Set("Retry-After", "2")
		http.Error(w, "Preview activation recently failed; retry after two seconds", http.StatusServiceUnavailable)
	case errors.Is(err, control.ErrLazyHostOffline):
		http.Error(w, "Preview host is offline", http.StatusServiceUnavailable)
	case errors.Is(err, control.ErrLazyOriginUnavailable):
		http.Error(w, "Preview origin is unavailable", http.StatusServiceUnavailable)
	case errors.Is(err, control.ErrLazyActivationTimeout), errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "Preview activation timed out", http.StatusGatewayTimeout)
	default:
		http.Error(w, "Preview activation unavailable", http.StatusServiceUnavailable)
	}
}

func (b *BrowserAccess) lazyAuthority() LazyAuthority {
	if b == nil {
		return nil
	}
	if b.LazyAuthority != nil {
		return b.LazyAuthority
	}
	authority, _ := b.Authority.(LazyAuthority)
	return authority
}

func (b *BrowserAccess) activateLazy(ctx context.Context, host, token string, machine bool) error {
	authority := b.lazyAuthority()
	if authority == nil {
		return control.ErrControlUnavailable
	}
	input := control.BrowserAuthorizeRequest{Token: token, Host: host, ResourceKind: "lazy_policy"}
	if machine {
		input.CredentialKind = "machine"
	}
	_, err := authority.Activate(ctx, input)
	return err
}
func (b *BrowserAccess) begin(w http.ResponseWriter, r *http.Request, host string) {
	browserSecurityHeaders(w)
	if !browserNavigation(r) {
		http.Error(w, "Authentication required", 401)
		return
	}
	path := r.URL.RequestURI()
	if !safeBrowserReturn(path) {
		http.Error(w, "Invalid return path", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	tx, err := b.Authority.Begin(ctx, host, path)
	if err != nil {
		browserError(w, r, err)
		return
	}
	if tx.TransactionID == "" || tx.State == "" || strings.Contains(tx.TransactionID, ".") || !tx.ExpiresAt.After(time.Now()) {
		http.Error(w, "Browser authorization unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: browserHandoffCookie, Value: tx.TransactionID + "." + tx.State, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, Expires: tx.ExpiresAt})
	http.Redirect(w, r, b.LoginOrigin+"/.paperboat/access/login?transaction_id="+url.QueryEscape(tx.TransactionID), http.StatusSeeOther)
}

func browserDecisionMatches(d connectorprotocol.IngressDecision, m route.RouteMatch) bool {
	r := m.Rule
	id := r.RouteID
	if id == "" {
		id = r.ID
	}
	generation := r.RouteGeneration
	if generation == 0 {
		generation = r.Revision
	}
	return d.Validate(time.Now().UTC()) == nil && d.Binding.Hostname == m.Host && d.Binding.RouteID == id && d.Binding.RouteGeneration == generation && d.Binding.AccountID == r.AccountID && ((r.ResourceKind == "preview" && d.Binding.PublicationID == r.TunnelID) || (r.ResourceKind != "preview" && d.Binding.TunnelID == r.TunnelID)) && d.Binding.Audience == r.AccessMode && d.EdgeNodeID == r.Node && d.EdgeProcessEpoch == r.EdgeProcessEpoch && d.ConnectorID == r.ConnectorID && d.SessionID == r.ConnectorSessionID && d.ProcessGeneration == r.ConnectorProcessGeneration && d.ConfigGeneration == r.ConfigGeneration
}

// authorize owns one request's refresh loop. Context cancellation closes the
// transport's body and upgraded stream; permission is never cached across users.
func (b *BrowserAccess) authorize(w http.ResponseWriter, r *http.Request, m route.RouteMatch) (*http.Request, func(), bool) {
	if !b.validate() {
		http.Error(w, "Browser access unavailable", 503)
		return r, func() {}, false
	}
	if browserReservedDuplicates(r) {
		http.Error(w, "Invalid access cookie", 401)
		return r, func() {}, false
	}
	token, ok := browserCookie(r, browserEdgeCookie)
	machine := false
	if values := r.Header.Values("Paperboat-Access-Token"); len(values) > 0 {
		if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
			http.Error(w, "Invalid access credential", 401)
			return r, func() {}, false
		}
		token, ok, machine = values[0], true, true
	}
	if !ok {
		b.begin(w, r, m.Host)
		return r, func() {}, false
	}
	if !machine && (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions || isWebSocketUpgrade(r.Header)) {
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != "https://"+m.Host {
			http.Error(w, "Origin is not authorized", 403)
			return r, func() {}, false
		}
	}
	kind := m.Rule.ResourceKind
	if kind == "" {
		kind = "tunnel"
		if m.Rule.Kind == route.PreviewHTTPSWSS || string(m.Rule.Kind) == dataCarrierPreviewPrivateRouteKind {
			kind = "preview"
		}
	}
	id := m.Rule.RouteID
	if id == "" {
		id = m.Rule.ID
	}
	input := control.BrowserAuthorizeRequest{Token: token, Host: m.Host, ResourceKind: kind, ResourceID: m.Rule.TunnelID, RouteID: id}
	if machine {
		input.CredentialKind = "machine"
	}
	started := time.Now()
	lookup, stop := context.WithTimeout(r.Context(), 2*time.Second)
	d, err := b.Authority.Authorize(lookup, input)
	stop()
	if err != nil {
		browserError(w, r, err)
		return r, func() {}, false
	}
	if !browserDecisionMatches(d, m) {
		http.NotFound(w, r)
		return r, func() {}, false
	}
	ctx, cancel := context.WithCancel(r.Context())
	ctx = context.WithValue(ctx, browserDecisionKey{}, d)
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := started.Add(d.ExpiresAt.Sub(d.IssuedAt))
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		tick := time.NewTicker(connectorprotocol.IngressRefreshInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				cancel()
				return
			case <-tick.C:
				start := time.Now()
				refresh, stop := context.WithDeadline(ctx, deadline)
				next, e := b.Authority.Authorize(refresh, input)
				stop()
				prior := d
				prior.IssuedAt, prior.ExpiresAt, prior.DecisionID = next.IssuedAt, next.ExpiresAt, next.DecisionID
				if e != nil || !browserDecisionMatches(next, m) || prior != next {
					cancel()
					return
				}
				d = next
				deadline = start.Add(next.ExpiresAt.Sub(next.IssuedAt))
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(time.Until(deadline))
			}
		}
	}()
	return r.WithContext(ctx), func() { cancel(); <-done }, true
}

func hasBrowserDecision(ctx context.Context, m route.RouteMatch) bool {
	d, ok := ctx.Value(browserDecisionKey{}).(connectorprotocol.IngressDecision)
	return ok && browserDecisionMatches(d, m)
}
