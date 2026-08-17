package publicpreviewrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/operation"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type verifierFunc func(context.Context, string) (admission.Claims, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (admission.Claims, error) {
	return f(ctx, token)
}

type authorizerFunc func(context.Context, string, string, string) (admission.Current, error)

func (f authorizerFunc) Current(ctx context.Context, environment, machine, connector string) (admission.Current, error) {
	return f(ctx, environment, machine, connector)
}

func relayFixture(t *testing.T) (*Manager, admission.Request, admission.Response) {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	registry := route.NewRegistry("preview.test", "runtime.test")
	attachment := route.Attachment{ID: "route_1", Revision: 1, Environment: "env_1", Node: "edge_1", Generation: 3, Kind: route.PreviewHTTPSWSS, Host: "demo.preview.test", Target: "127.0.0.1:3000"}
	if _, err := registry.Attach(attachment); err != nil {
		t.Fatal(err)
	}
	journal, err := operation.NewJournal(8)
	if err != nil {
		t.Fatal(err)
	}
	routes := []admission.Route{{RouteID: "route_1", Revision: 1, Kind: "preview_public_https_wss", PublicHost: "demo.preview.test", ProxyName: "preview_1", TargetHost: "127.0.0.1", TargetPort: 3000}}
	claims := admission.Claims{Issuer: "https://api.test", Audience: "paperboat-edge", JTI: "jti_1", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: "env_1", MachineID: "machine_1", ConnectorID: "preview", ConnectorGeneration: 3, EdgePool: "default", EdgeNodeID: "edge_1", RouteBinding: routeBinding(routes), ExpiresAt: now.Add(time.Minute)}
	service := &admission.Service{
		Issuer: "https://api.test", Now: func() time.Time { return now }, Journal: journal,
		Verifier: verifierFunc(func(context.Context, string) (admission.Claims, error) { return claims, nil }),
		Authorizer: authorizerFunc(func(context.Context, string, string, string) (admission.Current, error) {
			return admission.Current{Generation: 3, EdgePool: "default", EdgeNode: "edge_1"}, nil
		}),
		NewRunID: func(generation uint64, expiry time.Time) (admission.RunID, error) {
			return admission.RunID{Value: "run_1", Generation: generation, ExpiresAt: expiry}, nil
		},
	}
	manager, err := New(service, registry)
	if err != nil {
		t.Fatal(err)
	}
	request := admission.Request{OperationID: "operation_1", Credential: "credential", Environment: "env_1", Machine: "machine_1", Connector: "preview", Generation: 3, EdgePool: "default", EdgeNode: "edge_1", Routes: routes}
	response, err := manager.Admit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return manager, request, response
}

func TestManagerRequiresAdmissionAndCurrentRouteBeforePublication(t *testing.T) {
	manager, request, _ := relayFixture(t)
	if _, err := manager.DialContext(context.Background(), "tcp", "demo.preview.test:443"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unattached dial error = %v", err)
	}
	if err := manager.Routes.Detach("route_1", 1); err != nil {
		t.Fatal(err)
	}
	tampered := request
	tampered.Routes = append([]admission.Route(nil), request.Routes...)
	tampered.Routes[0].TargetPort++
	if routeBinding(tampered.Routes) == routeBinding(request.Routes) {
		t.Fatal("tampered route retained signed binding")
	}
}

func TestManagerMultiplexesAndFencesCarrierLifecycle(t *testing.T) {
	manager, _, response := relayFixture(t)
	edge, host := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attachDone := make(chan error, 1)
	go func() { attachDone <- manager.Attach(ctx, response, edge) }()
	hostMux, err := yamux.Client(host, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer hostMux.Close()
	deadline := time.Now().Add(time.Second)
	for {
		_, state, _, _ := manager.RouteState("demo.preview.test")
		if state == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("carrier was not published")
		}
		time.Sleep(time.Millisecond)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			stream, acceptErr := hostMux.AcceptStream()
			if acceptErr != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}(stream)
		}
	}()

	payloads := [][]byte{{0, 1, 2, 255}, []byte("concurrent-stream")}
	errorsByStream := make(chan error, len(payloads))
	var streams sync.WaitGroup
	for _, payload := range payloads {
		payload := append([]byte(nil), payload...)
		streams.Add(1)
		go func() {
			defer streams.Done()
			stream, dialErr := manager.DialContext(context.Background(), "tcp", "demo.preview.test:443")
			if dialErr != nil {
				errorsByStream <- dialErr
				return
			}
			defer stream.Close()
			if _, dialErr = stream.Write(payload); dialErr != nil {
				errorsByStream <- dialErr
				return
			}
			echoed := make([]byte, len(payload))
			if _, dialErr = io.ReadFull(stream, echoed); dialErr != nil || string(echoed) != string(payload) {
				errorsByStream <- errors.Join(errors.New("echo mismatch"), dialErr)
			}
		}()
	}
	streams.Wait()
	close(errorsByStream)
	for streamErr := range errorsByStream {
		t.Fatal(streamErr)
	}

	if err := hostMux.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-attachDone:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("carrier close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier close did not terminate attachment")
	}
	if err := manager.Routes.Detach("route_1", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.DialContext(context.Background(), "tcp", "demo.preview.test:443"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked carrier remained available: %v", err)
	}
	<-serverDone
}

func TestManagerWaitsForAuthenticatedReplacementCarrier(t *testing.T) {
	manager, _, response := relayFixture(t)
	attach := func() (*yamux.Session, <-chan error) {
		edge, host := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		done := make(chan error, 1)
		go func() { done <- manager.Attach(ctx, response, edge) }()
		mux, err := yamux.Client(host, yamux.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		return mux, done
	}
	first, firstDone := attach()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first carrier did not disconnect")
	}

	result := make(chan net.Conn, 1)
	errorsOut := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() {
		connection, err := manager.DialContext(ctx, "tcp", "demo.preview.test:443")
		if err != nil {
			errorsOut <- err
			return
		}
		result <- connection
	}()
	select {
	case err := <-errorsOut:
		t.Fatalf("request escaped replacement window: %v", err)
	case <-result:
		t.Fatal("request completed before replacement attached")
	case <-time.After(20 * time.Millisecond):
	}

	replacement, _ := attach()
	defer replacement.Close()
	serverDone := make(chan error, 1)
	go func() {
		stream, err := replacement.AcceptStream()
		if err == nil {
			_, err = io.Copy(stream, stream)
			_ = stream.Close()
		}
		serverDone <- err
	}()
	var connection net.Conn
	select {
	case connection = <-result:
	case err := <-errorsOut:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("waiting request did not use replacement")
	}
	payload := []byte("replacement-carrier")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("replacement payload=%q err=%v", got, err)
	}
	_ = connection.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("replacement stream did not close")
	}
}

func TestManagerReplacementWaitStopsOnCancellationAndRevocation(t *testing.T) {
	for _, test := range []struct {
		name string
		stop func(*Manager, context.CancelFunc)
		want error
	}{
		{name: "cancellation", stop: func(_ *Manager, cancel context.CancelFunc) { cancel() }, want: context.Canceled},
		{name: "revocation", stop: func(manager *Manager, _ context.CancelFunc) {
			if err := manager.Routes.Detach("route_1", 1); err != nil {
				t.Fatal(err)
			}
		}, want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, _, response := relayFixture(t)
			edge, host := net.Pipe()
			attachDone := make(chan error, 1)
			go func() { attachDone <- manager.Attach(t.Context(), response, edge) }()
			mux, err := yamux.Client(host, yamux.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			if err := mux.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-attachDone:
			case <-time.After(time.Second):
				t.Fatal("carrier did not disconnect")
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := manager.DialContext(ctx, "tcp", "demo.preview.test:443")
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("request did not wait: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			test.stop(manager, cancel)
			select {
			case err := <-done:
				if !errors.Is(err, test.want) {
					t.Fatalf("error=%v, want %v", err, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting request did not stop")
			}
		})
	}
}

func TestManagerUnrelatedRouteChangeDoesNotWakeReplacementWaiter(t *testing.T) {
	manager, _, response := relayFixture(t)
	edge, host := net.Pipe()
	attachDone := make(chan error, 1)
	go func() { attachDone <- manager.Attach(t.Context(), response, edge) }()
	mux, err := yamux.Client(host, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	_ = mux.Close()
	<-attachDone

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := manager.DialContext(ctx, "tcp", "demo.preview.test:443")
		done <- err
	}()
	unrelated := route.Attachment{ID: "route_2", Revision: 1, Environment: "env_1", Node: "edge_1", Generation: 3, Kind: route.PreviewHTTPSWSS, Host: "other.preview.test", Target: "127.0.0.1:3001"}
	if _, err := manager.Routes.Attach(unrelated); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("unrelated route woke waiter: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestManagerReplacementServesConcurrentWaiters(t *testing.T) {
	manager, _, response := relayFixture(t)
	edge, host := net.Pipe()
	attachDone := make(chan error, 1)
	go func() { attachDone <- manager.Attach(t.Context(), response, edge) }()
	first, err := yamux.Client(host, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	<-attachDone

	const count = 8
	connections := make(chan net.Conn, count)
	errorsOut := make(chan error, count)
	for range count {
		go func() {
			connection, dialErr := manager.DialContext(t.Context(), "tcp", "demo.preview.test:443")
			if dialErr != nil {
				errorsOut <- dialErr
				return
			}
			connections <- connection
		}()
	}
	select {
	case err := <-errorsOut:
		t.Fatalf("waiter escaped replacement window: %v", err)
	case <-connections:
		t.Fatal("waiter completed before replacement attached")
	case <-time.After(20 * time.Millisecond):
	}

	replacementEdge, replacementHost := net.Pipe()
	go func() { _ = manager.Attach(t.Context(), response, replacementEdge) }()
	replacement, err := yamux.Client(replacementHost, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	accepted := make(chan net.Conn, count)
	go func() {
		for range count {
			stream, acceptErr := replacement.AcceptStream()
			if acceptErr != nil {
				errorsOut <- acceptErr
				return
			}
			accepted <- stream
		}
	}()
	for range count {
		select {
		case err := <-errorsOut:
			t.Fatal(err)
		case connection := <-connections:
			_ = connection.Close()
		case <-time.After(time.Second):
			t.Fatal("concurrent waiter did not use replacement")
		}
		select {
		case stream := <-accepted:
			_ = stream.Close()
		case err := <-errorsOut:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("replacement did not receive concurrent stream")
		}
	}
}

func TestManagerAuthenticatedReplacementClosesActiveRetiredStreams(t *testing.T) {
	manager, _, response := relayFixture(t)
	firstEdge, firstHost := net.Pipe()
	go func() { _ = manager.Attach(t.Context(), response, firstEdge) }()
	firstMux, err := yamux.Client(firstHost, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, state, _, _ := manager.RouteState("demo.preview.test")
		if state == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first carrier was not published")
		}
		time.Sleep(time.Millisecond)
	}
	connection, err := manager.DialContext(t.Context(), "tcp", "demo.preview.test:443")
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := firstMux.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()

	replacementEdge, replacementHost := net.Pipe()
	go func() { _ = manager.Attach(t.Context(), response, replacementEdge) }()
	replacementMux, err := yamux.Client(replacementHost, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer replacementMux.Close()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("active stream on retired carrier remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("retired carrier was not closed promptly")
	}
	_ = connection.Close()
}

func TestHandlerDoesNotObserveRejectedAttachment(t *testing.T) {
	manager, _, _ := relayFixture(t)
	observed := false
	handler := Handler{Manager: manager, ObserveAttach: func(string) { observed = true }}
	request := httptest.NewRequest(http.MethodPost, Path, nil)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Paperboat-Relay-Carrier", "HTTP/3.0")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || observed {
		t.Fatalf("status=%d observed=%t", response.Code, observed)
	}
}
