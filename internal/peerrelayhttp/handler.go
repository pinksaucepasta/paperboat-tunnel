// Package peerrelayhttp exposes authenticated opaque peer relay streams over WSS.
package peerrelayhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
)

const (
	Subprotocol  = "paperboat.peer-relay.v1"
	maximumFrame = 128 << 10
)

var relayQUICRequestPreface = [...]byte{'P', 'B', 'R', 'Q', 1}

type Attachment struct {
	StreamHandle [16]byte
	EndpointID   string
	Role         peerrelay.Role
	Carrier      peerrelay.Carrier
}

type Authenticator interface {
	AuthenticateRelay(context.Context, string, Attachment) (peerrelay.Admission, error)
}

type Manager interface {
	Attach(context.Context, peerrelay.Admission, io.ReadWriteCloser) (peerrelay.Usage, error)
}

type Handler struct {
	Path          string
	Authenticator Authenticator
	Manager       Manager
	ObserveAttach func(Attachment)
	ObserveError  func(error)
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h.Authenticator == nil || h.Manager == nil || h.Path == "" || request.URL.Path != h.Path || request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	wss := request.Method == http.MethodGet && hasSubprotocol(request.Header.Values("Sec-WebSocket-Protocol"), Subprotocol)
	// Caddy terminates HTTP/3 and overwrites the carrier header before
	// forwarding the request to this loopback-only handler over HTTP/1.1.
	quic := request.Method == http.MethodPost && request.Header.Get("Content-Type") == "application/octet-stream" && request.Header.Get("X-Paperboat-Relay-Carrier") == "HTTP/3.0"
	if !wss && !quic {
		http.NotFound(writer, request)
		return
	}
	credential, ok := bearer(request.Header.Get("Authorization"))
	attachment, attachmentOK := parseAttachment(request, quic)
	if !ok || !attachmentOK {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	admission, err := h.Authenticator.AuthenticateRelay(request.Context(), credential, attachment)
	if err != nil {
		h.observe(err)
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if h.ObserveAttach != nil {
		h.ObserveAttach(attachment)
	}
	if quic {
		var preface [len(relayQUICRequestPreface)]byte
		if _, err := io.ReadFull(request.Body, preface[:]); err != nil || preface != relayQUICRequestPreface {
			h.observe(err)
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		controller := http.NewResponseController(writer)
		if err := controller.EnableFullDuplex(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			h.observe(err)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			h.observe(err)
			return
		}
		_, err = h.Manager.Attach(request.Context(), admission, &httpDuplexStream{reader: request.Body, writer: writer, flush: controller.Flush})
		h.observe(err)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		h.observe(err)
		return
	}
	connection.SetReadLimit(maximumFrame)
	stream := websocket.NetConn(request.Context(), connection, websocket.MessageBinary)
	_, err = h.Manager.Attach(request.Context(), admission, stream)
	h.observe(err)
}

func (h Handler) observe(err error) {
	if err != nil && h.ObserveError != nil {
		h.ObserveError(err)
	}
}

func parseAttachment(request *http.Request, quic bool) (Attachment, bool) {
	var result Attachment
	handle := request.Header.Get("X-Paperboat-Stream-Handle")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(handle)
	if err != nil || len(decoded) != len(result.StreamHandle) || base64.RawURLEncoding.EncodeToString(decoded) != handle {
		return Attachment{}, false
	}
	copy(result.StreamHandle[:], decoded)
	result.EndpointID = request.Header.Get("X-Paperboat-Endpoint-Id")
	if !boundedID(result.EndpointID) {
		return Attachment{}, false
	}
	switch request.Header.Get("X-Paperboat-Relay-Role") {
	case "initiator":
		result.Role = peerrelay.RoleInitiator
	case "responder":
		result.Role = peerrelay.RoleHost
	default:
		return Attachment{}, false
	}
	result.Carrier = peerrelay.CarrierWSS
	if quic {
		result.Carrier = peerrelay.CarrierQUIC
	}
	return result, true
}

type httpDuplexStream struct {
	reader io.ReadCloser
	writer io.Writer
	flush  func() error
	mu     sync.Mutex
}

func (s *httpDuplexStream) Read(target []byte) (int, error) { return s.reader.Read(target) }
func (s *httpDuplexStream) Write(value []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written, err := s.writer.Write(value)
	if err == nil {
		err = s.flush()
	}
	return written, err
}
func (s *httpDuplexStream) Close() error { return s.reader.Close() }

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

func boundedID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' || character == ' ' {
			return false
		}
	}
	return true
}
