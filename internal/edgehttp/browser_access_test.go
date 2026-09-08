package edgehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type browserAuthorityTest struct {
	calls    atomic.Int32
	decision connectorprotocol.IngressDecision
	failure  error
}

func (a *browserAuthorityTest) Begin(context.Context, string, string) (control.BrowserBegin, error) {
	a.calls.Add(1)
	return control.BrowserBegin{TransactionID: "bat_test", State: "nonce", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (a *browserAuthorityTest) Redeem(_ context.Context, tx, state, handoff, host string) (control.BrowserSession, error) {
	a.calls.Add(1)
	if tx != "bat_test" || state != "nonce" || handoff != "bah_test" || host != "app.example.test" {
		return control.BrowserSession{}, control.ErrBrowserDenied
	}
	return control.BrowserSession{Token: "session", ReturnPath: "/app?q=1", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (a *browserAuthorityTest) Authorize(context.Context, control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	a.calls.Add(1)
	return a.decision, a.failure
}

func TestBrowserCallbackRejectsForgedReturnBeforeRedemption(t *testing.T) {
	for _, tc := range []struct {
		name, origin, cookie, body string
		status, calls              int
	}{
		{"valid", "https://login.example.test", "__Host-pb-handoff=bat_test.nonce", "transaction_id=bat_test&handoff=bah_test", 303, 1},
		{"sibling", "https://evil.example.test", "__Host-pb-handoff=bat_test.nonce", "transaction_id=bat_test&handoff=bah_test", 403, 0},
		{"duplicate cookie", "https://login.example.test", "__Host-pb-handoff=bat_test.nonce; __Host-pb-handoff=bat_test.evil", "transaction_id=bat_test&handoff=bah_test", 403, 0},
		{"wrong transaction", "https://login.example.test", "__Host-pb-handoff=bat_other.nonce", "transaction_id=bat_test&handoff=bah_test", 403, 0},
		{"duplicate field", "https://login.example.test", "__Host-pb-handoff=bat_test.nonce", "transaction_id=bat_test&handoff=bah_test&handoff=evil", 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &browserAuthorityTest{}
			b := BrowserAccess{Authority: a, LoginOrigin: "https://login.example.test"}
			r := httptest.NewRequest("POST", "https://app.example.test"+browserCallbackPath, strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Cookie", tc.cookie)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			b.callback(w, r)
			if w.Code != tc.status || int(a.calls.Load()) != tc.calls {
				t.Fatalf("status=%d calls=%d", w.Code, a.calls.Load())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("callback cacheable")
			}
			if tc.status == 303 {
				if w.Header().Get("Location") != "/app?q=1" {
					t.Fatal("return path changed")
				}
				for _, c := range w.Result().Cookies() {
					if c.Name == browserEdgeCookie && (!c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" || c.SameSite != http.SameSiteLaxMode) {
						t.Fatal("unsafe edge cookie")
					}
				}
			}
		})
	}
}

func TestBrowserNavigationAndWebhookSemantics(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS", "GET"} {
		a := &browserAuthorityTest{}
		b := BrowserAccess{Authority: a, LoginOrigin: "https://login.example.test"}
		r := httptest.NewRequest(method, "https://app.example.test/hook", nil)
		w := httptest.NewRecorder()
		b.begin(w, r, "app.example.test")
		if w.Code != 401 || a.calls.Load() != 0 || w.Header().Get("Location") != "" {
			t.Fatalf("%s redirected non-navigation", method)
		}
	}
	a := &browserAuthorityTest{}
	b := BrowserAccess{Authority: a, LoginOrigin: "https://login.example.test"}
	r := httptest.NewRequest("GET", "https://app.example.test/app?q=1", nil)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	b.begin(w, r, "app.example.test")
	u, e := url.Parse(w.Header().Get("Location"))
	if e != nil || w.Code != 303 || u.Host != "login.example.test" || u.Query().Get("transaction_id") != "bat_test" || len(u.Query()) != 1 {
		t.Fatal("untrusted login redirect")
	}
	if strings.Contains(w.Header().Get("Location"), "nonce") {
		t.Fatal("state in URL")
	}
}
func TestBrowserReturnAndApplicationCredentialIsolation(t *testing.T) {
	for _, p := range []string{"//evil.test/x", "/%2fexample.test", "/%5cevil.test", "/a\r\nb", "https://evil.test", "/" + strings.Repeat("x", 2048)} {
		if safeBrowserReturn(p) {
			t.Fatalf("unsafe return accepted: %q", p)
		}
	}
	h := http.Header{"Cookie": []string{"app_session=keep; __Host-pb-edge=secret; __Host-pb-session=secret; pb-dev-session=secret"}, "Authorization": []string{"Bearer application"}, "Paperboat-Token": []string{"secret"}}
	stripBrowserRequestCredentials(h)
	if h.Get("Cookie") != "app_session=keep" || h.Get("Authorization") != "Bearer application" || h.Get("Paperboat-Token") != "" {
		t.Fatal("application/auth credential separation failed")
	}
	h = http.Header{"Set-Cookie": []string{"__Host-pb-edge=forged; Secure; Path=/", "app=keep; Path=/"}}
	stripBrowserResponseCredentials(h)
	if len(h.Values("Set-Cookie")) != 1 || h.Get("Set-Cookie") != "app=keep; Path=/" {
		t.Fatal("origin set access cookie")
	}
}
func browserTestMatch() (route.RouteMatch, connectorprotocol.IngressDecision) {
	d := publicTCPDecision(time.Now().UTC(), 4001)
	d.Binding.Protocol = "http"
	d.Binding.OriginScheme = "http"
	d.Binding.PathPrefix = "/"
	d.Binding.ListenerID = ""
	d.Binding.PublicPort = 0
	d.Binding.Audience = "private"
	d.PrincipalID = "viewer"
	d.GrantID = "grant"
	d.GrantGeneration = 1
	d.IssuedAt = time.Now().UTC()
	d.ExpiresAt = d.IssuedAt.Add(150 * time.Millisecond)
	b := d.Binding
	m := route.RouteMatch{Host: b.Hostname, Rule: route.RouteRule{ID: b.RouteID, RouteID: b.RouteID, Revision: b.RouteGeneration, RouteGeneration: b.RouteGeneration, AccountID: b.AccountID, TunnelID: b.TunnelID, AccessMode: b.Audience, Node: d.EdgeNodeID, EdgeProcessEpoch: d.EdgeProcessEpoch, ConnectorID: d.ConnectorID, ConnectorSessionID: d.SessionID, ConnectorProcessGeneration: d.ProcessGeneration, ConfigGeneration: d.ConfigGeneration, Kind: route.TunnelHTTPSWSS}}
	return m, d
}
func TestBrowserAuthorizationExpiresAndDeniesBeforeForward(t *testing.T) {
	m, d := browserTestMatch()
	a := &browserAuthorityTest{decision: d}
	b := BrowserAccess{Authority: a, LoginOrigin: "https://login.example.test"}
	r := httptest.NewRequest("GET", "https://"+m.Host+"/", nil)
	r.AddCookie(&http.Cookie{Name: browserEdgeCookie, Value: "token"})
	w := httptest.NewRecorder()
	allowed, finish, ok := b.authorize(w, r, m)
	if !ok {
		t.Fatalf("authorize status=%d", w.Code)
	}
	defer finish()
	select {
	case <-allowed.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("expired authority retained")
	}
	a.failure = control.ErrBrowserDenied
	w = httptest.NewRecorder()
	_, finish, ok = b.authorize(w, r, m)
	finish()
	if ok || w.Code != 404 {
		t.Fatal("denial forwarded")
	}
	a.failure = errors.New("control lost")
	w = httptest.NewRecorder()
	_, finish, ok = b.authorize(w, r, m)
	finish()
	if ok || w.Code != 503 {
		t.Fatal("control loss forwarded")
	}
}
