package peersignalinghttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
)

type authenticator map[string]peersignaling.Admission

func (a authenticator) Authenticate(_ context.Context, credential string) (peersignaling.Admission, error) {
	value, found := a[credential]
	if !found {
		return peersignaling.Admission{}, errors.New("rejected")
	}
	return value, nil
}

type validators struct{}

func (validators) NewValidator(peersignaling.Binding) (peersignaling.Validator, error) {
	return validator{}, nil
}

type validator struct{}

func (validator) Accept([]byte) (bool, error) { return true, nil }

func TestHandlerForwardsBinaryMessagesAndCleansUp(t *testing.T) {
	now := time.Now().UTC()
	service, err := peersignaling.New(peersignaling.Config{Authenticator: authenticator{
		"left":  admission(now, "left", "right", peersignaling.RoleControlling),
		"right": admission(now, "right", "left", peersignaling.RoleControlled),
	}, Validators: validators{}, MaximumSessions: 1, QueueDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(Handler{Path: "/v1/peer-signaling", Service: service})
	defer server.Close()
	left := dial(t, server.URL, "left")
	defer left.CloseNow()
	if err := left.Write(context.Background(), websocket.MessageBinary, []byte("candidate-one")); err != nil {
		t.Fatal(err)
	}
	right := dial(t, server.URL, "right")
	defer right.CloseNow()
	messageType, raw, err := right.Read(context.Background())
	if err != nil || messageType != websocket.MessageBinary || string(raw) != "candidate-one" {
		t.Fatalf("type=%v raw=%q error=%v", messageType, raw, err)
	}
	if err := right.Write(context.Background(), websocket.MessageBinary, []byte("candidate-two")); err != nil {
		t.Fatal(err)
	}
	messageType, raw, err = left.Read(context.Background())
	if err != nil || messageType != websocket.MessageBinary || string(raw) != "candidate-two" {
		t.Fatalf("type=%v raw=%q error=%v", messageType, raw, err)
	}
	if err := left.CloseNow(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for service.Stats().Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := service.Stats(); stats.Sessions != 0 || stats.Attachments != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestHandlerRejectsInvalidAdmissionProtocolAndTextFrames(t *testing.T) {
	now := time.Now().UTC()
	service, err := peersignaling.New(peersignaling.Config{Authenticator: authenticator{"left": admission(now, "left", "right", peersignaling.RoleControlling)}, Validators: validators{}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(Handler{Path: "/v1/peer-signaling", Service: service})
	defer server.Close()
	for _, options := range []*websocket.DialOptions{
		{Subprotocols: []string{Subprotocol}},
		{HTTPHeader: http.Header{"Authorization": []string{"Bearer left"}}},
	} {
		_, response, dialErr := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/peer-signaling", options)
		if dialErr == nil || response == nil || response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusNotFound {
			t.Fatalf("response=%v error=%v", response, dialErr)
		}
	}
	connection := dial(t, server.URL, "left")
	if err := connection.Write(context.Background(), websocket.MessageText, []byte("not-binary")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("text frame did not close signaling attachment")
	}
}

func TestHandlerMultiplexesIndependentlyAuthorizedSubstrateChannels(t *testing.T) {
	now := time.Now().UTC()
	service, err := peersignaling.New(peersignaling.Config{Authenticator: authenticator{
		"left":  admission(now, "left", "right", peersignaling.RoleControlling),
		"right": admission(now, "right", "left", peersignaling.RoleControlled),
	}, Validators: validators{}, MaximumSessions: 1, QueueDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(Handler{Path: "/v1/peer-signaling", Service: service})
	defer server.Close()
	left := dialSubstrate(t, server.URL)
	defer left.CloseNow()
	right := dialSubstrate(t, server.URL)
	defer right.CloseNow()
	writeSubstrate(t, left, substrateFrame{kind: substrateAttach, channel: 11, body: []byte("left")})
	readSubstrateKind(t, left, 11, substrateReady)
	writeSubstrate(t, right, substrateFrame{kind: substrateAttach, channel: 22, body: []byte("right")})
	readSubstrateKind(t, right, 22, substrateReady)
	writeSubstrate(t, left, substrateFrame{kind: substrateData, channel: 11, body: []byte("candidate-one")})
	frame := readSubstrateKind(t, right, 22, substrateData)
	if string(frame.body) != "candidate-one" {
		t.Fatalf("payload=%q", frame.body)
	}
	writeSubstrate(t, right, substrateFrame{kind: substrateData, channel: 22, body: []byte("candidate-two")})
	frame = readSubstrateKind(t, left, 11, substrateData)
	if string(frame.body) != "candidate-two" {
		t.Fatalf("payload=%q", frame.body)
	}
	writeSubstrate(t, left, substrateFrame{kind: substrateComplete, channel: 11})
	writeSubstrate(t, right, substrateFrame{kind: substrateComplete, channel: 22})
}

func dialSubstrate(t *testing.T, baseURL string) *websocket.Conn {
	t.Helper()
	connection, response, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(baseURL, "http")+"/v1/peer-signaling", &websocket.DialOptions{Subprotocols: []string{SubstrateSubprotocol}})
	if err != nil {
		if response != nil {
			t.Fatalf("dial status=%d error=%v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	return connection
}

func writeSubstrate(t *testing.T, connection *websocket.Conn, frame substrateFrame) {
	t.Helper()
	raw, err := encodeSubstrate(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), websocket.MessageBinary, raw); err != nil {
		t.Fatal(err)
	}
}

func readSubstrateKind(t *testing.T, connection *websocket.Conn, channel uint64, kind substrateKind) substrateFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	messageType, raw, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary {
		t.Fatalf("type=%v error=%v", messageType, err)
	}
	frame, err := decodeSubstrate(raw)
	if err != nil || frame.channel != channel || frame.kind != kind {
		t.Fatalf("frame=%+v error=%v", frame, err)
	}
	return frame
}

func dial(t *testing.T, baseURL, credential string) *websocket.Conn {
	t.Helper()
	connection, response, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(baseURL, "http")+"/v1/peer-signaling", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + credential}}, Subprotocols: []string{Subprotocol}})
	if err != nil {
		if response != nil {
			t.Fatalf("dial status=%d error=%v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	if connection.Subprotocol() != Subprotocol {
		t.Fatalf("subprotocol=%q", connection.Subprotocol())
	}
	return connection
}

func admission(now time.Time, endpoint, peer string, role peersignaling.Role) peersignaling.Admission {
	return peersignaling.Admission{CredentialID: "credential_" + endpoint, EnvironmentID: "environment_1", NodeID: "node_1", IntentID: "intent_1", EndpointID: endpoint, PeerEndpointID: peer, AttemptGeneration: 2, NetworkGeneration: 4, Role: role, ExpiresAt: now.Add(time.Minute)}
}
