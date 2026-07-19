package edgehttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func policyFor(t *testing.T, next http.Handler) *Policy {
	t.Helper()
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := New(Config{WildcardHost: "*.preview.example.test", TrustedProxies: trusted, MaxHeaderBytes: 4096, MaxBodyBytes: 1024}, next)
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
