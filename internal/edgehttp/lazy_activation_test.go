package edgehttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type lazyBodyProbe struct{ reads atomic.Int32 }

func (b *lazyBodyProbe) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (*lazyBodyProbe) Close() error               { return nil }

type lazyAuthorityFixture struct {
	browserAuthorityTest
	activate func(context.Context, control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error)
	calls    atomic.Int32
}

func (a *lazyAuthorityFixture) Activate(ctx context.Context, in control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
	a.calls.Add(1)
	return a.activate(ctx, in)
}

func lazyRuleAndDecision(host string) (route.RouteRule, connectorprotocol.IngressDecision) {
	_, decision := browserTestMatch()
	decision.Binding.Hostname = host
	decision.Binding.Audience = "private"
	decision.IssuedAt = time.Now().UTC()
	decision.ExpiresAt = decision.IssuedAt.Add(time.Second)
	rule := route.RouteRule{
		ID: decision.Binding.RouteID, RouteID: decision.Binding.RouteID, Revision: decision.Binding.RouteGeneration, RouteGeneration: decision.Binding.RouteGeneration,
		AccountID: decision.Binding.AccountID, TunnelID: decision.Binding.TunnelID, AccessMode: "private", ResourceKind: "tunnel",
		Node: decision.EdgeNodeID, EdgeProcessEpoch: decision.EdgeProcessEpoch, ConnectorID: decision.ConnectorID, ConnectorSessionID: decision.SessionID,
		ConnectorProcessGeneration: decision.ProcessGeneration, ConfigGeneration: decision.ConfigGeneration, Kind: route.TunnelHTTPSWSS,
		MatchType: route.MatchExact, Hostname: host, PathPrefix: "/", Target: "route_binding_lazy", Protocol: "http", ObservedState: "ready",
	}
	return rule, decision
}

func newLazyPolicy(t *testing.T, registry *route.GenerationRegistry, authority *lazyAuthorityFixture, next http.Handler) *Policy {
	t.Helper()
	p, err := New(Config{BrowserAccess: &BrowserAccess{Authority: authority, LazyAuthority: authority, LoginOrigin: "https://login.example.test"}, PreviewBaseDomain: "preview.example.test", TunnelBaseDomain: "tunnels.example.test", RuntimeBaseDomain: "runtime.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 4096, Routes: registry, RequestID: func() string { return "request_lazy" }}, next)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLazyActivationBeforeBodyReadAndSingleAcquireRetry(t *testing.T) {
	host := "p3000-abcdefghijklmnop.preview.example.test"
	rule, decision := lazyRuleAndDecision(host)
	registry := route.NewGenerationRegistry(4)
	body := &lazyBodyProbe{}
	authority := &lazyAuthorityFixture{}
	authority.decision = decision
	authority.activate = func(_ context.Context, input control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
		if body.reads.Load() != 0 {
			t.Fatal("application body read before activation")
		}
		if input.Host != host || input.Token != "browser-token" || input.ResourceKind != "lazy_policy" || input.ResourceID != "" || input.RouteID != "" {
			t.Fatalf("activation input=%#v", input)
		}
		if err := registry.ApplyGeneration(context.Background(), 1, []route.RouteRule{rule}, func(context.Context, []route.RouteRule) error { return nil }, time.Second); err != nil {
			t.Fatal(err)
		}
		return decision, nil
	}
	forwarded := atomic.Bool{}
	p := newLazyPolicy(t, registry, authority, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/submit", body)
	r.Host = host
	r.AddCookie(&http.Cookie{Name: browserEdgeCookie, Value: "browser-token"})
	r.Header.Set("Origin", "https://"+host)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || !forwarded.Load() || authority.calls.Load() != 1 || body.reads.Load() != 0 {
		t.Fatalf("status=%d forwarded=%v activations=%d body_reads=%d", w.Code, forwarded.Load(), authority.calls.Load(), body.reads.Load())
	}
}

func TestLazyActivationRequiresCredentialAndCanonicalHostname(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		credential bool
	}{
		{"anonymous", "p3000-abcdefghijklmnop.preview.example.test", false},
		{"ordinary preview", "ordinary.preview.example.test", true},
		{"noncanonical host", "P3000-abcdefghijklmnop.preview.example.test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := &lazyAuthorityFixture{activate: func(context.Context, control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
				t.Fatal("unexpected activation")
				return connectorprotocol.IngressDecision{}, nil
			}}
			p := newLazyPolicy(t, route.NewGenerationRegistry(1), authority, http.NotFoundHandler())
			r := httptest.NewRequest(http.MethodPost, "https://"+tc.host+"/", nil)
			r.Host = tc.host
			if tc.credential {
				r.Header.Set("Paperboat-Access-Token", "machine-token")
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if authority.calls.Load() != 0 {
				t.Fatalf("activations=%d", authority.calls.Load())
			}
		})
	}
}

func TestLazyActivationCancellationLeavesBodyUnread(t *testing.T) {
	host := "p3000-abcdefghijklmnop.preview.example.test"
	body := &lazyBodyProbe{}
	authority := &lazyAuthorityFixture{activate: func(ctx context.Context, _ control.BrowserAuthorizeRequest) (connectorprotocol.IngressDecision, error) {
		<-ctx.Done()
		return connectorprotocol.IngressDecision{}, ctx.Err()
	}}
	p := newLazyPolicy(t, route.NewGenerationRegistry(1), authority, http.NotFoundHandler())
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/", body).WithContext(ctx)
	r.Host = host
	r.Header.Set("Paperboat-Access-Token", "machine-token")
	done := make(chan struct{})
	go func() { p.ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	for authority.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("activation ignored cancellation")
	}
	if body.reads.Load() != 0 {
		t.Fatal("application body read while activation canceled")
	}
}

func TestLazyActivationErrorResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		retry  string
	}{
		{"offline", control.ErrLazyHostOffline, 503, ""},
		{"origin", control.ErrLazyOriginUnavailable, 503, ""},
		{"timeout", control.ErrLazyActivationTimeout, 504, ""},
		{"generation", control.ErrLazyGenerationConflict, 409, ""},
		{"capacity", control.ErrLazyCapacity, 429, "1"},
		{"forwarding", control.ErrLazyForwardingFailed, 503, ""},
		{"cooldown", control.ErrLazyCooldown, 503, "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil)
			w := httptest.NewRecorder()
			lazyActivationError(w, r, tc.err)
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("status=%d retry=%q", w.Code, w.Header().Get("Retry-After"))
			}
		})
	}
}
