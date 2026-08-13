// Package peersignalinghttp exposes authenticated peer signaling over WSS.
package peersignalinghttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
)

const (
	Subprotocol    = "paperboat.peer-signaling.v1"
	MaximumMessage = 16 << 10
)

type Handler struct {
	Path         string
	Service      *peersignaling.Service
	ObserveError func(error)
}

var errMessageType = errors.New("peer signaling requires binary WebSocket messages")

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h.Service == nil || h.Path == "" || request.Method != http.MethodGet || request.URL.Path != h.Path || request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	protocols := request.Header.Values("Sec-WebSocket-Protocol")
	if hasSubprotocol(protocols, SubstrateSubprotocol) {
		h.serveSubstrate(writer, request)
		return
	}
	if !hasSubprotocol(protocols, Subprotocol) {
		http.NotFound(writer, request)
		return
	}
	credential, ok := bearer(request.Header.Get("Authorization"))
	if !ok {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	attachment, err := h.Service.Attach(request.Context(), credential)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		_ = attachment.Close()
		return
	}
	connection.SetReadLimit(MaximumMessage)
	runCtx, cancel := context.WithCancel(request.Context())
	defer cancel()
	type result struct{ graceful bool }
	done := make(chan result, 2)
	go func() {
		outcome := result{}
		defer func() { done <- outcome }()
		for {
			messageType, raw, readErr := connection.Read(runCtx)
			if readErr != nil {
				if websocket.CloseStatus(readErr) == websocket.StatusNormalClosure {
					outcome.graceful = true
					return
				}
				h.observe(readErr)
				return
			}
			if messageType != websocket.MessageBinary {
				h.observe(errMessageType)
				return
			}
			if sendErr := attachment.Send(runCtx, raw); sendErr != nil {
				h.observe(sendErr)
				return
			}
		}
	}()
	go func() {
		defer func() { done <- result{} }()
		for {
			raw, receiveErr := attachment.Receive(runCtx)
			if receiveErr != nil {
				h.observe(receiveErr)
				return
			}
			if writeErr := connection.Write(runCtx, websocket.MessageBinary, raw); writeErr != nil {
				h.observe(writeErr)
				return
			}
		}
	}()
	first := <-done
	cancel()
	if first.graceful {
		_ = attachment.Complete()
	} else {
		_ = attachment.Close()
	}
	_ = connection.CloseNow()
	<-done
}

func (h Handler) observe(err error) {
	if err != nil && h.ObserveError != nil {
		h.ObserveError(err)
	}
}

func bearer(value string) (string, bool) {
	if strings.TrimSpace(value) != value {
		return "", false
	}
	scheme, credential, found := strings.Cut(value, " ")
	return credential, found && strings.EqualFold(scheme, "Bearer") && credential != "" && strings.TrimSpace(credential) == credential
}

func hasSubprotocol(values []string, expected string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if strings.TrimSpace(item) == expected {
				return true
			}
		}
	}
	return false
}
