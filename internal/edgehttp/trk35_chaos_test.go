package edgehttp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

func TestTRK35PrivateAccessProofRevocationAndExpiryFailClosed(t *testing.T) {
	wireNow := time.Now().UTC().Truncate(time.Second)
	clockNow := wireNow
	identity := testEdgePreviewIdentity(2, 3)
	server, client := testEdgePreviewCarrierPair(t, identity)
	authorizer := &trk35PrivateAccessAuthorizer{}
	var targetCalls atomic.Int32
	bridge, err := NewPrivateAccessStreamBridge(PrivateAccessStreamBridgeConfig{
		Authorizer: authorizer,
		Target: PrivateAccessTargetFunc(func(context.Context, connectorprotocol.PrivateAccessRequest) (io.ReadWriteCloser, error) {
			targetCalls.Add(1)
			return nil, errors.New("target must not receive rejected access")
		}),
		Clock: func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- bridge.Serve(serveContext, server) }()

	openRequest := func(request connectorprotocol.PrivateAccessRequest, malformed bool) int {
		t.Helper()
		metadata := connectorprotocol.StreamOpen{
			Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion,
			AccountID: request.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID,
			SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration,
			Generation: identity.Generation, RouteID: request.RouteID, RequestID: request.RequestID,
			Kind: connectorprotocol.PrivateAccessHTTP,
		}
		stream, err := client.OpenStream(context.Background(), metadata)
		if err != nil {
			t.Fatal(err)
		}
		if malformed {
			bad := connectorprotocol.PrivateAccessOpen{
				Schema: "paperboat.preview-tunnel/forged", Kind: connectorprotocol.PrivateAccessKind,
				Grant: "forged-grant", Request: request,
			}
			if err := trk35WritePrivateAccessFrame(stream, bad); err != nil {
				t.Fatal(err)
			}
		} else if err := connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{
			Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind,
			Grant: "signed-grant", Request: request,
		}); err != nil {
			t.Fatal(err)
		}
		result, err := connectorprotocol.ReadPrivateAccessResult(stream, time.Now().UTC())
		if err != nil {
			t.Fatalf("private access result: %v", err)
		}
		_ = stream.Close()
		return result.Status
	}

	request := edgePrivateAccessRequest(wireNow)
	request.AccountID = identity.AccountID
	request.DeviceID = identity.HostID
	request.CarrierSessionID = identity.SessionID
	request.ProcessGeneration = identity.ProcessGeneration
	request.ConfigGeneration = identity.Generation
	request.ExpiresAt = wireNow.Add(time.Hour)

	authorizer.set(nil, control.PrivateAccessGrantDecision{})
	if got := openRequest(request, true); got != http.StatusUnauthorized {
		t.Fatalf("forged proof status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := authorizer.calls.Load(); got != 0 {
		t.Fatalf("forged proof reached authorizer %d times", got)
	}

	// The wire envelope is valid at send time, but an injected edge clock sees
	// it as expired before authorization. No grant or target access is leaked.
	clockNow = wireNow.Add(2 * time.Hour)
	request.RequestID = "request_expired"
	request.CorrelationID = "correlation_expired"
	if got := openRequest(request, false); got != http.StatusUnauthorized {
		t.Fatalf("expired request status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := authorizer.calls.Load(); got != 0 {
		t.Fatalf("expired request reached authorizer %d times", got)
	}

	clockNow = wireNow
	request.RequestID = "request_revoked"
	request.CorrelationID = "correlation_revoked"
	authorizer.set(control.ErrPrivateAccessGrantForbidden, control.PrivateAccessGrantDecision{})
	if got := openRequest(request, false); got != http.StatusForbidden {
		t.Fatalf("revoked grant status = %d, want %d", got, http.StatusForbidden)
	}
	if got := authorizer.calls.Load(); got != 1 {
		t.Fatalf("revoked grant authorizer calls = %d, want 1", got)
	}

	request.RequestID = "request_decision_expired"
	request.CorrelationID = "correlation_decision_expired"
	authorizer.set(nil, control.PrivateAccessGrantDecision{Allowed: true, ExpiresAt: clockNow})
	if got := openRequest(request, false); got != http.StatusForbidden {
		t.Fatalf("expired decision status = %d, want %d", got, http.StatusForbidden)
	}
	if got := targetCalls.Load(); got != 0 {
		t.Fatalf("rejected private access disclosed target resource %d times", got)
	}

	cancelServe()
	_ = server.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("private access bridge did not stop")
	}
}

func TestTRK35UnsafePreviewReplayFailsClosedWithoutResourceDisclosure(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			var bodies []string
			var mu sync.Mutex
			transport := retryPreviewTransport{next: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				body, err := io.ReadAll(request.Body)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				bodies = append(bodies, string(body))
				mu.Unlock()
				return nil, io.EOF
			})}
			request := httptest.NewRequest(method, "http://app.preview.example.test/private", strings.NewReader("credential-bearing-payload"))
			if _, err := transport.RoundTrip(request); !errors.Is(err, io.EOF) {
				t.Fatalf("unsafe replay error = %v, want io.EOF", err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("unsafe method was replayed %d times", got)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 1 || bodies[0] != "credential-bearing-payload" {
				t.Fatalf("unsafe request body observations = %q", bodies)
			}
		})
	}
}

type trk35PrivateAccessAuthorizer struct {
	mu       sync.Mutex
	err      error
	decision control.PrivateAccessGrantDecision
	calls    atomic.Int32
}

func (a *trk35PrivateAccessAuthorizer) set(err error, decision control.PrivateAccessGrantDecision) {
	a.mu.Lock()
	a.err = err
	a.decision = decision
	a.mu.Unlock()
}

func (a *trk35PrivateAccessAuthorizer) AuthorizePrivateAccessGrant(context.Context, string, connectorprotocol.PrivateAccessRequest) (control.PrivateAccessGrantDecision, error) {
	a.calls.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.decision, a.err
}

func trk35WritePrivateAccessFrame(writer io.Writer, value connectorprotocol.PrivateAccessOpen) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > connectorprotocol.MaxPrivateAccessFrameBytes-4 {
		return errors.New("private access frame exceeds test bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := trk35WriteAll(writer, header[:]); err != nil {
		return err
	}
	return trk35WriteAll(writer, payload)
}

func trk35WriteAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
