package peerrelayhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peerrelay"
)

type authenticatorFunc func(context.Context, string, Attachment) (peerrelay.Admission, error)

func (f authenticatorFunc) AuthenticateRelay(ctx context.Context, credential string, attachment Attachment) (peerrelay.Admission, error) {
	return f(ctx, credential, attachment)
}

type managerFunc func(context.Context, peerrelay.Admission, io.ReadWriteCloser) (peerrelay.Usage, error)

func (f managerFunc) Attach(ctx context.Context, admission peerrelay.Admission, stream io.ReadWriteCloser) (peerrelay.Usage, error) {
	return f(ctx, admission, stream)
}

func TestHandlerAuthenticatesStrictAttachmentBeforeBinaryRelay(t *testing.T) {
	var handle [16]byte
	copy(handle[:], []byte("stream-handle-001"))
	server := httptest.NewServer(Handler{Path: "/v1/peer-relay", Authenticator: authenticatorFunc(func(_ context.Context, credential string, attachment Attachment) (peerrelay.Admission, error) {
		if credential != "route.token.signature" || attachment.StreamHandle != handle || attachment.EndpointID != "endpoint_cli" || attachment.Role != peerrelay.RoleInitiator || attachment.Carrier != peerrelay.CarrierWSS {
			t.Fatalf("credential=%q attachment=%+v", credential, attachment)
		}
		return peerrelay.Admission{Role: attachment.Role, Carrier: attachment.Carrier}, nil
	}), Manager: managerFunc(func(_ context.Context, admission peerrelay.Admission, stream io.ReadWriteCloser) (peerrelay.Usage, error) {
		defer stream.Close()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return peerrelay.Usage{}, err
		}
		_, err := stream.Write(payload)
		return peerrelay.Usage{}, err
	})})
	defer server.Close()
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/peer-relay", &websocket.DialOptions{Subprotocols: []string{Subprotocol}, HTTPHeader: http.Header{"Authorization": []string{"Bearer route.token.signature"}, "X-Paperboat-Stream-Handle": []string{base64.RawURLEncoding.EncodeToString(handle[:])}, "X-Paperboat-Endpoint-Id": []string{"endpoint_cli"}, "X-Paperboat-Relay-Role": []string{"initiator"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), websocket.MessageBinary, []byte("test")); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := connection.Read(context.Background())
	if err != nil || messageType != websocket.MessageBinary || string(payload) != "test" {
		t.Fatalf("type=%v payload=%q err=%v", messageType, payload, err)
	}
}

func TestHandlerRejectsMalformedAttachmentBeforeAuthentication(t *testing.T) {
	called := false
	handler := Handler{Path: "/v1/peer-relay", Authenticator: authenticatorFunc(func(context.Context, string, Attachment) (peerrelay.Admission, error) {
		called = true
		return peerrelay.Admission{}, errors.New("unexpected")
	}), Manager: managerFunc(func(context.Context, peerrelay.Admission, io.ReadWriteCloser) (peerrelay.Usage, error) {
		return peerrelay.Usage{}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "http://relay.test/v1/peer-relay", nil)
	request.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("X-Paperboat-Stream-Handle", "not-canonical")
	request.Header.Set("X-Paperboat-Endpoint-Id", "endpoint_cli")
	request.Header.Set("X-Paperboat-Relay-Role", "initiator")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d authenticated=%t", response.Code, called)
	}
}

type duplexRecorder struct {
	*httptest.ResponseRecorder
	enabled bool
}

func (r *duplexRecorder) EnableFullDuplex() error {
	r.enabled = true
	return nil
}

func TestHandlerCarriesAuthenticatedHTTP3RelayStream(t *testing.T) {
	var handle [16]byte
	copy(handle[:], []byte("stream-handle-001"))
	var observed Attachment
	handler := Handler{Path: "/v1/peer-relay", Authenticator: authenticatorFunc(func(_ context.Context, credential string, attachment Attachment) (peerrelay.Admission, error) {
		if credential != "route.token.signature" || attachment.StreamHandle != handle || attachment.Carrier != peerrelay.CarrierQUIC {
			t.Fatalf("credential=%q attachment=%+v", credential, attachment)
		}
		return peerrelay.Admission{Role: attachment.Role, Carrier: attachment.Carrier}, nil
	}), ObserveAttach: func(attachment Attachment) { observed = attachment }, Manager: managerFunc(func(_ context.Context, _ peerrelay.Admission, stream io.ReadWriteCloser) (peerrelay.Usage, error) {
		defer stream.Close()
		payload, err := io.ReadAll(stream)
		if err != nil {
			return peerrelay.Usage{}, err
		}
		_, err = stream.Write(payload)
		return peerrelay.Usage{}, err
	})}
	request := httptest.NewRequest(http.MethodPost, "http://relay.test/v1/peer-relay", io.MultiReader(bytes.NewReader(relayQUICRequestPreface[:]), strings.NewReader("opaque-record")))
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request.ProtoMinor = 1
	request.Header.Set("Authorization", "Bearer route.token.signature")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Paperboat-Relay-Carrier", "HTTP/3.0")
	request.Header.Set("X-Paperboat-Stream-Handle", base64.RawURLEncoding.EncodeToString(handle[:]))
	request.Header.Set("X-Paperboat-Endpoint-Id", "endpoint_cli")
	request.Header.Set("X-Paperboat-Relay-Role", "initiator")
	response := &duplexRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "opaque-record" || !response.enabled {
		t.Fatalf("status=%d body=%q full_duplex=%t", response.Code, response.Body.String(), response.enabled)
	}
	if observed.StreamHandle != handle || observed.EndpointID != "endpoint_cli" || observed.Role != peerrelay.RoleInitiator || observed.Carrier != peerrelay.CarrierQUIC {
		t.Fatalf("observed attachment=%+v", observed)
	}
}
