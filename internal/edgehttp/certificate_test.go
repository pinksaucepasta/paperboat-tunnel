package edgehttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type certificateRoutes map[string][2]string

func (r certificateRoutes) RouteState(host string) (string, string, string, bool) {
	value, ok := r[host]
	return value[0], value[1], "", ok
}

func TestCertificateAskAuthorizesOnlyCurrentRoutes(t *testing.T) {
	handler := WithCertificateAsk(http.NotFoundHandler(), certificateRoutes{
		"ready.helper.example.test":     {"runtime_https_wss", "ready"},
		"degraded.preview.example.test": {"preview_public_https_wss", "degraded"},
	})
	for _, test := range []struct {
		target string
		want   int
	}{
		{"/private/certificate-ask?domain=ready.helper.example.test", http.StatusNoContent},
		{"/private/certificate-ask?domain=degraded.preview.example.test", http.StatusNoContent},
		{"/private/certificate-ask?domain=unknown.helper.example.test", http.StatusNotFound},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, test.target, nil)
		request.Host = "127.0.0.1:18085"
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Fatalf("%s: status = %d, want %d", test.target, recorder.Code, test.want)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/private/certificate-ask?domain=ready.helper.example.test", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("public certificate ask status = %d", recorder.Code)
	}
}
