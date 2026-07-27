package edgefrp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

func TestHookRequiresPrivatePathAndValidVersion(t *testing.T) {
	hook := Hook{Path: "/private/hook-secret", Handle: func(_ context.Context, op string, content json.RawMessage) (json.RawMessage, error) {
		return content, nil
	}}
	tests := []struct {
		name, path, method, contentType, body string
		status                                int
	}{
		{"wrong path", "/wrong", http.MethodPost, "application/json", `{}`, http.StatusNotFound},
		{"wrong method", hook.Path, http.MethodGet, "application/json", `{}`, http.StatusNotFound},
		{"wrong content type", hook.Path, http.MethodPost, "text/plain", `{}`, http.StatusNotFound},
		{"wrong version", hook.Path, http.MethodPost, "application/json", `{"version":"9","op":"Login","content":{}}`, http.StatusBadRequest},
		{"unsupported op", hook.Path, http.MethodPost, "application/json", `{"version":"0.1.0","op":"NewVisitorConn","content":{}}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
			request.Header.Set("Content-Type", test.contentType)
			hook.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestHookRejectsWithoutLeakingErrorContent(t *testing.T) {
	hook := Hook{Path: "/hook", Handle: func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("credential=secret-token body=private")
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewBufferString(`{"version":"0.1.0","op":"Login","content":{}}`))
	request.Header.Set("Content-Type", "application/json")
	hook.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("secret-token")) || bytes.Contains(recorder.Body.Bytes(), []byte("private")) {
		t.Fatalf("response leaks error: %s", recorder.Body.String())
	}
	var response wireResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Reject || response.RejectReason != "request rejected" {
		t.Fatalf("response = %+v", response)
	}
}

func TestHookReportsBoundedTypedErrorCode(t *testing.T) {
	hook := Hook{Path: "/hook", Handle: func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return nil, edgeerrors.Wrap(edgeerrors.CodeCredentialExpired, "credential=secret-token", "request a fresh admission", errors.New("private cause"))
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewBufferString(`{"version":"0.1.0","op":"Login","content":{}}`))
	request.Header.Set("Content-Type", "application/json")
	hook.ServeHTTP(recorder, request)
	var response wireResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.RejectReason != "request rejected:credential_expired" {
		t.Fatalf("reject reason = %q", response.RejectReason)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("secret-token")) || bytes.Contains(recorder.Body.Bytes(), []byte("private cause")) {
		t.Fatalf("response leaks error: %s", recorder.Body.String())
	}
}

func TestHookReturnsSessionKeyOnlyAfterAcceptedLogin(t *testing.T) {
	hook := Hook{
		Path: "/hook",
		Handle: func(_ context.Context, _ string, content json.RawMessage) (json.RawMessage, error) {
			return content, nil
		},
		SessionKey: func(_ context.Context, op string, _ json.RawMessage) (string, error) {
			if op != "Login" {
				t.Fatalf("operation = %q", op)
			}
			return "connector-session-key", nil
		},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewBufferString(`{"version":"0.1.0","op":"Login","content":{}}`))
	request.Header.Set("Content-Type", "application/json")
	hook.ServeHTTP(recorder, request)
	var response wireResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Reject || response.SessionKey != "connector-session-key" {
		t.Fatalf("response = %+v", response)
	}
}
