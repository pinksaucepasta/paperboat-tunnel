package edgehttp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

type readinessFunc func(string) (string, string, bool)

func (f readinessFunc) PreviewState(host string) (string, string, bool) { return f(host) }
func (f readinessFunc) RouteState(host string) (string, string, string, bool) {
	state, reason, found := f(host)
	return "preview_public_https_wss", state, reason, found
}

type routeReadinessFunc func(string) (string, string, string, bool)

func (f routeReadinessFunc) RouteState(host string) (string, string, string, bool) { return f(host) }

type helperAccessFunc func(context.Context, string) (admission.Claims, error)

func (f helperAccessFunc) VerifyHelperAccess(ctx context.Context, token string) (admission.Claims, error) {
	return f(ctx, token)
}

type revocationFunc func(context.Context, admission.Claims) (bool, error)

func (f revocationFunc) Revoked(ctx context.Context, claims admission.Claims) (bool, error) {
	return f(ctx, claims)
}

func previewConfig() Config {
	return Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 1024}
}

func TestRouteKindMustMatchTypedDomain(t *testing.T) {
	for _, test := range []struct {
		host, kind string
	}{
		{host: "terminal.preview.example.test", kind: "helper_https_wss"},
		{host: "web.helper.example.test", kind: "preview_public_https_wss"},
	} {
		called := false
		config := previewConfig()
		config.Readiness = routeReadinessFunc(func(string) (string, string, string, bool) { return test.kind, "ready", "", true })
		policy, err := New(config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://"+test.host+"/", nil)
		request.Host = test.host
		recorder := httptest.NewRecorder()
		policy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || called {
			t.Fatalf("host=%s kind=%s status=%d called=%v", test.host, test.kind, recorder.Code, called)
		}
	}
}

func TestHelperRequiresRegisteredConnectorReadiness(t *testing.T) {
	called := false
	config := previewConfig()
	config.Readiness = routeReadinessFunc(func(string) (string, string, string, bool) {
		return "helper_https_wss", "offline", "connector_unavailable", true
	})
	policy, err := New(config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "terminal.helper.example.test"
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "5" || called {
		t.Fatalf("status=%d retry=%q called=%v", recorder.Code, recorder.Header().Get("Retry-After"), called)
	}
}

func TestRetryableWebSocketUpgradesThenClosesWith1013(t *testing.T) {
	policy, err := New(Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 1024, Readiness: readinessFunc(func(string) (string, string, bool) { return "offline", "", true })}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("offline preview reached proxy") }))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(policy)
	defer server.Close()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: app.preview.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n")
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("X-Robots-Tag") != "noindex, nofollow, noarchive" {
		t.Fatalf("response = %d %v", response.StatusCode, response.Header)
	}
	frame := make([]byte, 2+2+len("Try Again Later"))
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal(err)
	}
	if frame[0] != 0x88 || binary.BigEndian.Uint16(frame[2:4]) != 1013 {
		t.Fatalf("close frame = %x", frame)
	}
}

func TestUnknownPreviewDoesNotReachPrivateUpstream(t *testing.T) {
	nextCalled := false
	policy, err := New(Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 1024, Readiness: readinessFunc(func(string) (string, string, bool) { return "", "", false })}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "unknown.preview.example.test"
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound || nextCalled {
		t.Fatalf("status=%d next=%v", recorder.Code, nextCalled)
	}
}

func TestGatewayForwardsReadyPreviewToPrivateUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.preview.example.test" || r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Fatalf("forwarded request host=%q headers=%v", r.Host, r.Header)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Robots-Tag", "index")
		_, _ = io.WriteString(w, "data: ready\n\n")
	}))
	defer upstream.Close()
	gateway, err := NewGateway(Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 1024, Readiness: readinessFunc(func(string) (string, string, bool) { return "ready", "", true })}, strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request.Host = "app.preview.example.test"
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "data: ready\n\n" || recorder.Header().Get("X-Robots-Tag") != "noindex, nofollow, noarchive" || len(recorder.Header().Values("X-Robots-Tag")) != 1 {
		t.Fatalf("response status=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func policyFor(t *testing.T, next http.Handler) *Policy {
	t.Helper()
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := New(Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", TrustedProxies: trusted, MaxHeaderBytes: 4096, MaxBodyBytes: 1024, HelperAccess: helperAccessFunc(func(context.Context, string) (admission.Claims, error) {
		return admission.Claims{JTI: "jti_test", EnvironmentID: "env_test", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}), Revocations: revocationFunc(func(context.Context, admission.Claims) (bool, error) { return false, nil }), RevocationCheckInterval: time.Millisecond}, next)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPreservesRequestAndSanitizesHeaders(t *testing.T) {
	var seen *http.Request
	var body string
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusCreated)
	}))
	request := httptest.NewRequest(http.MethodPatch, "/a/b?q=one%20two", strings.NewReader("payload"))
	request.Host = "App.Preview.Example.Test."
	request.RemoteAddr = "10.0.0.2:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.4, 10.1.1.1")
	request.Header.Set("Forwarded", "for=secret")
	request.Header.Set("X-Paperboat-Environment", "other")
	request.Header.Set("Connection", "X-Remove")
	request.Header.Set("X-Remove", "value")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d", recorder.Code)
	}
	if seen.Method != http.MethodPatch || seen.URL.EscapedPath() != "/a/b" || seen.URL.RawQuery != "q=one%20two" || body != "payload" {
		t.Fatalf("request changed: %+v, body=%q", seen, body)
	}
	if seen.Header.Get("X-Forwarded-For") != "198.51.100.4" || seen.Header.Get("X-Forwarded-Proto") != "https" || seen.Header.Get("X-Forwarded-Host") != "app.preview.example.test" {
		t.Fatalf("forwarded headers = %v", seen.Header)
	}
	for _, name := range []string{"Forwarded", "X-Paperboat-Environment", "X-Remove", "Connection"} {
		if seen.Header.Get(name) != "" {
			t.Fatalf("header %s retained", name)
		}
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("safety headers missing")
	}
}

func TestRetiredUploadRouteIsRejectedBeforeUpstream(t *testing.T) {
	seen := false
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		w.WriteHeader(http.StatusCreated)
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/uploads", strings.NewReader("payload"))
	request.Host = "environment.helper.example.test"
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound || seen {
		t.Fatalf("status=%d upstream_seen=%t", recorder.Code, seen)
	}
}

func TestFileTransferRoutesRequireAccessAndPreserveResumeHeaders(t *testing.T) {
	var seen *http.Request
	config := previewConfig()
	config.HelperAccess = helperAccessFunc(func(_ context.Context, token string) (admission.Claims, error) {
		if token != "signed-test-credential" {
			return admission.Claims{}, errors.New("invalid")
		}
		return admission.Claims{JTI: "jti_transfer", EnvironmentID: "env_1", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	config.Revocations = revocationFunc(func(context.Context, admission.Claims) (bool, error) { return false, nil })
	config.RevocationCheckInterval = time.Second
	policy, err := New(config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/v1/file-transfers/ft_1/content", strings.NewReader("chunk"))
	request.Host = "environment.helper.example.test"
	request.Header.Set("Authorization", "Bearer signed-test-credential")
	request.Header.Set("Content-Type", "application/offset+octet-stream")
	request.Header.Set("Upload-Offset", "17")
	request.Header.Set("If-Match", `"sha256:abc"`)
	request.Header.Set("Range", "bytes=17-")
	request.Header.Set("X-Paperboat-Request-ID", "req_transfer")
	request.Header.Set("X-Paperboat-Operation-ID", "op_transfer")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || seen == nil {
		t.Fatalf("status=%d seen=%v", recorder.Code, seen)
	}
	for name, want := range map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": "17", "If-Match": `"sha256:abc"`, "Range": "bytes=17-", "X-Paperboat-Request-ID": "req_transfer", "X-Paperboat-Operation-ID": "op_transfer"} {
		if got := seen.Header.Get(name); got != want {
			t.Fatalf("%s=%q want=%q", name, got, want)
		}
	}
	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/file-transfers/pending", nil)
	unauthorized.Host = request.Host
	recorder = httptest.NewRecorder()
	policy.ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", recorder.Code)
	}
}

func TestHelperAccessRequiresCredentialAndCancelsWhenRevoked(t *testing.T) {
	var revoked atomic.Bool
	config := previewConfig()
	config.HelperAccess = helperAccessFunc(func(_ context.Context, token string) (admission.Claims, error) {
		if token != "signed-test-credential" {
			return admission.Claims{}, errors.New("invalid")
		}
		return admission.Claims{JTI: "jti_stream", EnvironmentID: "env_stream", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	config.Revocations = revocationFunc(func(context.Context, admission.Claims) (bool, error) { return revoked.Load(), nil })
	config.RevocationCheckInterval = time.Millisecond
	cancelled := make(chan struct{})
	policy, err := New(config, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(cancelled)
	}))
	if err != nil {
		t.Fatal(err)
	}
	missing := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	missing.Host = "environment.helper.example.test"
	missingRecorder := httptest.NewRecorder()
	policy.ServeHTTP(missingRecorder, missing)
	if missingRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential status=%d", missingRecorder.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	request.Host = "environment.helper.example.test"
	request.Header.Set("Authorization", "Bearer signed-test-credential")
	done := make(chan struct{})
	go func() {
		policy.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	revoked.Store(true)
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("revoked helper stream was not cancelled")
	}
	<-done
}

func TestEstablishedHelperAccessSurvivesCredentialExpiry(t *testing.T) {
	var revoked atomic.Bool
	config := previewConfig()
	config.HelperAccess = helperAccessFunc(func(context.Context, string) (admission.Claims, error) {
		return admission.Claims{JTI: "jti_expiring_stream", EnvironmentID: "env_stream", ExpiresAt: time.Now().Add(5 * time.Millisecond)}, nil
	})
	config.Revocations = revocationFunc(func(context.Context, admission.Claims) (bool, error) { return revoked.Load(), nil })
	config.RevocationCheckInterval = time.Millisecond
	cancelled := make(chan struct{})
	policy, err := New(config, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(cancelled)
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	request.Host = "environment.helper.example.test"
	request.Header.Set("Authorization", "Bearer signed-test-credential")
	done := make(chan struct{})
	go func() {
		policy.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	select {
	case <-cancelled:
		t.Fatal("established helper stream was cancelled at credential expiry")
	default:
	}
	revoked.Store(true)
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("established helper stream was not cancelled after revocation")
	}
	<-done
}

func TestGatewayClosesUpgradedHelperConnectionWhenRevoked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err := buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(io.Discard, connection)
	}))
	defer upstream.Close()

	var revoked atomic.Bool
	config := previewConfig()
	config.Readiness = routeReadinessFunc(func(string) (string, string, string, bool) {
		return "helper_https_wss", "ready", "", true
	})
	config.HelperAccess = helperAccessFunc(func(_ context.Context, token string) (admission.Claims, error) {
		if token != "signed-test-credential" {
			return admission.Claims{}, errors.New("invalid")
		}
		return admission.Claims{JTI: "jti_stream", EnvironmentID: "env_stream", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	config.Revocations = revocationFunc(func(context.Context, admission.Claims) (bool, error) {
		return revoked.Load(), nil
	})
	config.RevocationCheckInterval = time.Millisecond
	gateway, err := NewGateway(config, strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET /v1/runtime HTTP/1.1\r\nHost: environment.helper.example.test\r\nAuthorization: Bearer signed-test-credential\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", response.StatusCode)
	}
	revoked.Store(true)
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("revoked upgraded helper connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("revoked upgraded helper connection did not close before deadline")
	}
}

func TestPreviewRouteStripsHelperOperationHeaders(t *testing.T) {
	var seen http.Header
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "app.preview.example.test"
	request.Header.Set("X-Paperboat-Request-ID", "req_1")
	request.Header.Set("X-Paperboat-Operation-ID", "upload_1")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if seen.Get("X-Paperboat-Request-ID") != "" || seen.Get("X-Paperboat-Operation-ID") != "" {
		t.Fatalf("helper operation headers reached preview target: %v", seen)
	}
}

func TestRejectsHostConfusionAbsoluteFormAndLimits(t *testing.T) {
	called := false
	policy := policyFor(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	tests := []struct {
		host, target string
		header       bool
		body         int
		want         int
	}{
		{"preview.example.test", "/", false, 0, http.StatusNotFound},
		{"a.b.preview.example.test", "/", false, 0, http.StatusNotFound},
		{"evilpreview.example.test", "/", false, 0, http.StatusNotFound},
		{"app.preview.example.test", "http://other.test/", false, 0, http.StatusNotFound},
		{"app.preview.example.test", "/", true, 0, http.StatusNotFound},
		{"app.preview.example.test", "/", false, 2048, http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(strings.Repeat("x", test.body)))
		request.Host = test.host
		if test.header {
			request.Header.Set("X-Large", strings.Repeat("x", 5000))
		}
		recorder := httptest.NewRecorder()
		policy.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Fatalf("%s status = %d, want %d", test.host, recorder.Code, test.want)
		}
	}
	if called {
		t.Fatal("rejected request reached target")
	}
}

func TestCancellationAndStreamingInterfacesPassThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !errors.Is(r.Context().Err(), context.Canceled) {
			t.Fatalf("context = %v", r.Context().Err())
		}
		if _, ok := w.(http.Flusher); !ok {
			t.Fatal("flusher unavailable")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: ready\n\n"))
		w.(http.Flusher).Flush()
	}))
	request := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	request.Host = "app.preview.example.test"
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Body.String() != "data: ready\n\n" || !recorder.Flushed {
		t.Fatalf("stream = %q flushed=%v", recorder.Body.String(), recorder.Flushed)
	}
}

func TestWebSocketUpgradeIsPreserved(t *testing.T) {
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" {
			t.Fatalf("upgrade headers = %v", r.Header)
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	request := httptest.NewRequest(http.MethodGet, "/socket", nil)
	request.Host = "app.preview.example.test"
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", "websocket")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestPreviewReadinessResponses(t *testing.T) {
	for _, tc := range []struct {
		state, reason string
		status        int
		retry         bool
	}{
		{"registering", "", http.StatusServiceUnavailable, true},
		{"degraded", "target_unhealthy", http.StatusBadGateway, false},
		{"offline", "", http.StatusServiceUnavailable, true},
		{"expired", "", http.StatusGone, false},
		{"removed", "", http.StatusNotFound, false},
	} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("readiness failure reached proxy") })
		policy, err := New(Config{PreviewBaseDomain: "preview.example.test", HelperBaseDomain: "helper.example.test", MaxHeaderBytes: 4096, MaxBodyBytes: 1024, Readiness: readinessFunc(func(string) (string, string, bool) { return tc.state, tc.reason, true })}, next)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "app.preview.example.test"
		policy.ServeHTTP(rec, req)
		if rec.Code != tc.status || rec.Header().Get("X-Robots-Tag") != "noindex, nofollow, noarchive" {
			t.Fatalf("%s/%s status=%d headers=%v", tc.state, tc.reason, rec.Code, rec.Header())
		}
		if tc.retry != (rec.Header().Get("Retry-After") != "") {
			t.Fatalf("%s retry header=%q", tc.state, rec.Header().Get("Retry-After"))
		}
	}
}

func TestChunkedBodyLimitAndUntrustedForwarding(t *testing.T) {
	policy := policyFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "192.0.2.1" {
			t.Fatalf("spoofed client IP trusted: %s", r.Header.Get("X-Forwarded-For"))
		}
		_, err := io.ReadAll(r.Body)
		var tooLarge *http.MaxBytesError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("body error = %v", err)
		}
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 2048)))
	request.Host = "app.preview.example.test"
	request.ContentLength = -1
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	recorder := httptest.NewRecorder()
	policy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", recorder.Code)
	}
}
