package datacarrier

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func testCarrierIdentity() Identity {
	return Identity{
		AccountID:         "account-a",
		HostID:            "host-a",
		TunnelID:          "tunnel-a",
		ConnectorID:       "connector-a",
		SessionID:         "session-a",
		ProcessGeneration: 7,
		Generation:        11,
	}
}

func testCarrierConfig(maximumStreams int) Config {
	return Config{
		MaximumStreams:       maximumStreams,
		AcceptBacklog:        maximumStreams,
		QueueDepth:           4,
		StreamWindow:         256 << 10,
		KeepAliveInterval:    20 * time.Millisecond,
		ConnectionWriteLimit: time.Second,
		StreamOpenLimit:      time.Second,
		StreamCloseLimit:     time.Second,
		Identity:             testCarrierIdentity(),
		Authorize: AuthorizerFunc(func(_ context.Context, _ Identity, open StreamOpen) error {
			if open.RouteID != "route-a" {
				return ErrRouteDenied
			}
			return nil
		}),
	}
}

func testStreamOpen(routeID, requestID string) StreamOpen {
	identity := testCarrierIdentity()
	return StreamOpen{
		Protocol:          connectorprotocol.ProtocolName,
		Version:           connectorprotocol.ProtocolVersion,
		AccountID:         identity.AccountID,
		TunnelID:          identity.TunnelID,
		ConnectorID:       identity.ConnectorID,
		SessionID:         identity.SessionID,
		ProcessGeneration: identity.ProcessGeneration,
		Generation:        identity.Generation,
		RouteID:           routeID,
		RequestID:         requestID,
		Kind:              "http",
	}
}

func TestDataCarrierEdgeOpenConnectorAcceptStreamingBody(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	open := testStreamOpen("route-a", "request-a")
	edgeStream, err := edge.OpenStream(context.Background(), open)
	if err != nil {
		t.Fatalf("edge open stream: %v", err)
	}
	connectorStream, metadata, err := connector.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("connector accept stream: %v", err)
	}
	if metadata != open || connectorStream.Open != open {
		t.Fatalf("metadata = %+v, stream metadata = %+v, want %+v", metadata, connectorStream.Open, open)
	}
	const bodySize = 2 << 20
	payload := bytes.Repeat([]byte("edge-stream-body-"), bodySize/len("edge-stream-body-"))
	payload = append(payload, bytes.Repeat([]byte("x"), bodySize-len(payload))...)
	readDone := make(chan struct{})
	var received []byte
	go func() {
		received, _ = io.ReadAll(connectorStream)
		close(readDone)
	}()
	if err := writeAll(edgeStream, payload); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := edgeStream.Close(); err != nil {
		t.Fatalf("close edge stream: %v", err)
	}
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading stream body")
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("received %d bytes, want %d", len(received), len(payload))
	}
	if err := connectorStream.Close(); err != nil {
		t.Fatalf("close connector stream: %v", err)
	}
	if !waitForCarrier(func() bool { return edge.ActiveStreams() == 0 && connector.ActiveStreams() == 0 }) {
		t.Fatalf("stream permit leaked: edge=%d connector=%d", edge.ActiveStreams(), connector.ActiveStreams())
	}
}

func TestDataCarrierRejectsWrongSessionGenerationAndRoute(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	wrongSession := testStreamOpen("route-a", "request-session")
	wrongSession.SessionID = "session-other"
	if _, err := edge.OpenStream(context.Background(), wrongSession); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong session error = %v, want identity mismatch", err)
	}
	wrongGeneration := testStreamOpen("route-a", "request-generation")
	wrongGeneration.Generation++
	if _, err := edge.OpenStream(context.Background(), wrongGeneration); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong generation error = %v, want identity mismatch", err)
	}
	wrongRoute := testStreamOpen("route-other", "request-route")
	if _, err := edge.OpenStream(context.Background(), wrongRoute); !errors.Is(err, ErrRouteDenied) {
		t.Fatalf("wrong route error = %v, want route denied", err)
	}

	// Exercise connector-side admission independently of the edge helper. A
	// compromised or stale edge cannot bypass exact identity and route checks
	// by writing directly to the authenticated yamux session.
	for _, candidate := range []struct {
		name string
		open StreamOpen
		want error
	}{
		{name: "session", open: wrongSession, want: ErrIdentityMismatch},
		{name: "generation", open: wrongGeneration, want: ErrIdentityMismatch},
		{name: "route", open: wrongRoute, want: ErrRouteDenied},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			raw, err := edge.session.OpenStream(context.Background())
			if err != nil {
				t.Fatalf("open raw stream: %v", err)
			}
			if err := connectorprotocol.WriteStreamOpen(raw, candidate.open); err != nil {
				t.Fatalf("write stream preface: %v", err)
			}
			_, _, err = connector.AcceptStream(context.Background())
			if !errors.Is(err, candidate.want) {
				t.Fatalf("accept error = %v, want %v", err, candidate.want)
			}
			_ = raw.Close()
		})
	}
}

func TestDataCarrierRejectsOversizedPreface(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	raw, err := edge.session.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open raw stream: %v", err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], connectorprotocol.MaxStreamOpenBytes)
	if err := writeAll(raw, header[:]); err != nil {
		t.Fatalf("write oversized preface: %v", err)
	}
	_, _, err = connector.AcceptStream(context.Background())
	if !errors.Is(err, connectorprotocol.ErrFrameTooLarge) {
		t.Fatalf("oversized preface error = %v, want frame too large", err)
	}
	_ = raw.Close()
}

func TestDataCarrierOverloadIsBounded(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(1))
	first, err := edge.OpenStream(context.Background(), testStreamOpen("route-a", "request-first"))
	if err != nil {
		t.Fatalf("open first stream: %v", err)
	}
	accepted, _, err := connector.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("accept first stream: %v", err)
	}
	if _, err := edge.OpenStream(context.Background(), testStreamOpen("route-a", "request-second")); !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("second stream error = %v, want stream limit", err)
	}
	_ = first.Close()
	_ = accepted.Close()
	if !waitForCarrier(func() bool { return edge.ActiveStreams() == 0 && connector.ActiveStreams() == 0 }) {
		t.Fatal("overload test leaked stream permits")
	}
}

func TestDataCarrierCancellationAndCloseDoNotLeakOpenOrPing(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	openContext, cancelOpen := context.WithTimeout(context.Background(), 20*time.Millisecond)
	pingContext, cancelPing := context.WithTimeout(context.Background(), 20*time.Millisecond)
	openDone := make(chan error, 1)
	pingDone := make(chan error, 1)
	go func() {
		_, err := edge.OpenStream(openContext, testStreamOpen("route-a", "request-canceled"))
		openDone <- err
	}()
	go func() { pingDone <- connector.Ping(pingContext) }()
	time.Sleep(5 * time.Millisecond)
	cancelOpen()
	cancelPing()
	_ = edge.Close()
	_ = connector.Close()
	select {
	case <-openDone:
	case <-time.After(time.Second):
		t.Fatal("canceled open did not return")
	}
	select {
	case <-pingDone:
	case <-time.After(time.Second):
		t.Fatal("canceled ping did not return")
	}
	if edge.ActiveStreams() != 0 || connector.ActiveStreams() != 0 {
		t.Fatalf("active streams after close: edge=%d connector=%d", edge.ActiveStreams(), connector.ActiveStreams())
	}
}

func TestDataCarrierAcceptCancellationLeavesCarrierUsable(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	acceptContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := connector.AcceptStream(acceptContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("accept error = %v, want deadline exceeded", err)
	}
	edgeStream, err := edge.OpenStream(context.Background(), testStreamOpen("route-a", "request-after-cancel"))
	if err != nil {
		t.Fatalf("open after canceled accept: %v", err)
	}
	connectorStream, _, err := connector.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("accept after canceled accept: %v", err)
	}
	_ = edgeStream.Close()
	_ = connectorStream.Close()
}

func TestServeHTTPStreamPreservesLargeBodySSEAndTrailers(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	open := testStreamOpen("route-a", "request-http")
	edgeStream, err := edge.OpenStream(context.Background(), open)
	if err != nil {
		t.Fatalf("edge open stream: %v", err)
	}
	connectorStream, metadata, err := connector.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("connector accept stream: %v", err)
	}
	if metadata.Kind != "http" {
		t.Fatalf("stream kind = %q, want http", metadata.Kind)
	}
	firstWritten := make(chan struct{})
	releaseSecond := make(chan struct{})
	const bodySize = 2 << 20
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		count, err := io.Copy(io.Discard, request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if count != bodySize {
			t.Errorf("request body bytes = %d, want %d", count, bodySize)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("Trailer", "X-Paperboat-Trailer")
		writer.WriteHeader(http.StatusAccepted)
		flusher, ok := writer.(http.Flusher)
		if !ok {
			t.Error("response writer is not flushable")
			return
		}
		_, _ = writer.Write([]byte("event: first\n\n"))
		flusher.Flush()
		close(firstWritten)
		select {
		case <-releaseSecond:
		case <-request.Context().Done():
			return
		}
		_, _ = writer.Write([]byte("event: second\n\n"))
		writer.Header().Set("X-Paperboat-Trailer", "complete")
	})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeHTTPStream(context.Background(), connectorStream, handler, 1<<20, time.Second)
	}()
	payload := bytes.Repeat([]byte("body-"), bodySize/len("body-"))
	if len(payload) < bodySize {
		payload = append(payload, bytes.Repeat([]byte("x"), bodySize-len(payload))...)
	}
	requestHeader := "POST /upload HTTP/1.1\r\nHost: carrier.test\r\nContent-Length: " + itoa(len(payload)) + "\r\nConnection: close\r\n\r\n"
	if err := writeAll(edgeStream, []byte(requestHeader)); err != nil {
		t.Fatalf("write request header: %v", err)
	}
	if err := writeAll(edgeStream, payload); err != nil {
		t.Fatalf("write request body: %v", err)
	}
	responseReader := bufio.NewReader(edgeStream)
	response, err := http.ReadResponse(responseReader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	firstChunk := make([]byte, len("event: first\n\n"))
	if _, err := io.ReadFull(response.Body, firstChunk); err != nil {
		t.Fatalf("read first streamed chunk: %v", err)
	}
	select {
	case <-firstWritten:
	case <-time.After(time.Second):
		t.Fatal("handler did not flush first SSE chunk")
	}
	if string(firstChunk) != "event: first\n\n" {
		t.Fatalf("first response chunk = %q", firstChunk)
	}
	close(releaseSecond)
	remaining, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read remaining response: %v", err)
	}
	_ = response.Body.Close()
	if string(remaining) != "event: second\n\n" {
		t.Fatalf("remaining response body = %q", remaining)
	}
	if response.StatusCode != http.StatusAccepted || response.Trailer.Get("X-Paperboat-Trailer") != "complete" {
		t.Fatalf("response status/trailer = %d/%q", response.StatusCode, response.Trailer.Get("X-Paperboat-Trailer"))
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve HTTP stream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP stream server did not stop")
	}
	_ = edgeStream.Close()
}

func TestServeHTTPStreamH2CGRPC(t *testing.T) {
	local, remote := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", request.Proto)
		}
		if request.Header.Get("Content-Type") != "application/grpc" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read grpc body: %v", err)
		}
		if string(body) != "grpc-request" {
			t.Errorf("grpc body = %q", body)
		}
		writer.Header().Set("Content-Type", "application/grpc")
		writer.Header().Set("Trailer", "grpc-status")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("grpc-response"))
		writer.Header().Set("grpc-status", "0")
	})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeHTTPStream(ctx, remote, handler, 1<<20, time.Second)
	}()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols: protocols,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return local, nil
		},
	}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://carrier.test/grpc.Service/Call", bytes.NewReader([]byte("grpc-request")))
	if err != nil {
		t.Fatalf("new grpc request: %v", err)
	}
	request.Header.Set("Content-Type", "application/grpc")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("grpc h2c request: %v", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read grpc response: %v", err)
	}
	_ = response.Body.Close()
	if response.ProtoMajor != 2 || string(responseBody) != "grpc-response" || response.Trailer.Get("grpc-status") != "0" {
		t.Fatalf("grpc response = proto %d body %q trailer %q", response.ProtoMajor, responseBody, response.Trailer.Get("grpc-status"))
	}
	transport.CloseIdleConnections()
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve h2c stream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("h2c stream server did not stop")
	}
}

func dataCarrierPair(t *testing.T, config Config) (*Server, *Client) {
	t.Helper()
	local, remote := net.Pipe()
	edge, err := NewServer(context.Background(), remote, config)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		t.Fatalf("new edge server: %v", err)
	}
	connector, err := NewClient(context.Background(), local, config)
	if err != nil {
		_ = edge.Close()
		_ = local.Close()
		t.Fatalf("new connector client: %v", err)
	}
	t.Cleanup(func() {
		_ = connector.Close()
		_ = edge.Close()
	})
	return edge, connector
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func waitForCarrier(predicate func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return predicate()
}
