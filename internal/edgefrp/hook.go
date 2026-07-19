package edgefrp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const APIVersion = "0.1.0"

type Hook struct {
	Path       string
	Handle     func(context.Context, string, json.RawMessage) (json.RawMessage, error)
	SessionKey func(context.Context, string, json.RawMessage) (string, error)
	Reject     func(operation, reason string)
	Observe    func(operation string, rejected bool)
}

type wireRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type wireResponse struct {
	Reject       bool            `json:"reject"`
	RejectReason string          `json:"reject_reason,omitempty"`
	Unchange     bool            `json:"unchange,omitempty"`
	Content      json.RawMessage `json:"content,omitempty"`
	SessionKey   string          `json:"session_key,omitempty"`
}

var supportedOps = map[string]struct{}{
	"Login": {}, "NewProxy": {}, "CloseProxy": {}, "Ping": {}, "NewWorkConn": {}, "NewUserConn": {}, "CloseUserConn": {}, "Traffic": {},
}

func (h Hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Handle == nil || h.Path == "" || r.URL.Path != h.Path || r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
		return
	}
	var request wireRequest
	if err := json.Unmarshal(body, &request); err != nil || request.Version != APIVersion {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if _, ok := supportedOps[request.Op]; !ok {
		http.Error(w, "unsupported operation", http.StatusBadRequest)
		return
	}
	content, err := h.Handle(r.Context(), request.Op, request.Content)
	response := wireResponse{Content: content}
	if err == nil && h.SessionKey != nil {
		response.SessionKey, err = h.SessionKey(r.Context(), request.Op, request.Content)
	}
	if err != nil {
		response.Reject = true
		response.RejectReason = safeReason(err)
		if h.Reject != nil {
			h.Reject(request.Op, response.RejectReason)
		}
	}
	if h.Observe != nil {
		h.Observe(request.Op, err != nil)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func safeReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	if safe, ok := err.(interface{ SafeReason() string }); ok {
		return safe.SafeReason()
	}
	return "request rejected"
}
