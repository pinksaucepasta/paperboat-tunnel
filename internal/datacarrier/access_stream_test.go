package datacarrier

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func TestServerAcceptAccessStreamAuthenticatesCarrierAndLeavesPayloadOpaque(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	open := testStreamOpen("route-a", "access-request")
	open.Kind = AccessStreamHTTPS
	accepted := make(chan struct {
		stream *Stream
		open   StreamOpen
		err    error
	}, 1)
	go func() {
		stream, metadata, err := edge.AcceptAccessStream(context.Background())
		accepted <- struct {
			stream *Stream
			open   StreamOpen
			err    error
		}{stream: stream, open: metadata, err: err}
	}()
	source, err := connector.OpenStream(context.Background(), open)
	if err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil || result.stream == nil || result.open != open {
		t.Fatalf("accepted stream = %+v, err=%v", result.open, result.err)
	}
	const payload = "opaque access bytes"
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(source, payload)
		writeDone <- err
	}()
	got, readErr := io.ReadAll(io.LimitReader(result.stream, int64(len(payload))))
	if readErr != nil || string(got) != payload {
		t.Fatalf("payload = %q, read error = %v", got, readErr)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	_ = result.stream.Close()
	if !waitForCarrier(func() bool { return edge.ActiveStreams() == 0 && connector.ActiveStreams() == 0 }) {
		t.Fatalf("stream permit leaked: edge=%d connector=%d", edge.ActiveStreams(), connector.ActiveStreams())
	}
}

func TestServerAcceptAccessStreamRejectsUnsupportedKindBeforePayload(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	open := testStreamOpen("route-a", "public-kind")
	// http is valid connector-v1, but it is not the private access seam.
	raw, err := connector.session.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, _, err := edge.AcceptAccessStream(context.Background())
		acceptDone <- err
	}()
	if err := connectorprotocol.WriteStreamOpen(raw, open); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acceptDone:
		if !errors.Is(err, ErrAccessStreamKind) {
			t.Fatalf("accept error = %v, want %v", err, ErrAccessStreamKind)
		}
	case <-time.After(time.Second):
		t.Fatal("access stream accept did not reject unsupported kind")
	}
	_ = raw.Close()
}

func TestServerAcceptAccessStreamRejectsStaleCarrierIdentity(t *testing.T) {
	edge, connector := dataCarrierPair(t, testCarrierConfig(4))
	open := testStreamOpen("route-a", "stale-identity")
	open.Kind = AccessStreamTCP
	open.SessionID = "session-stale"
	raw, err := connector.session.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, _, err := edge.AcceptAccessStream(context.Background())
		acceptDone <- err
	}()
	if err := connectorprotocol.WriteStreamOpen(raw, open); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acceptDone:
		if !errors.Is(err, ErrAccessStreamIdentity) {
			t.Fatalf("accept error = %v, want %v", err, ErrAccessStreamIdentity)
		}
	case <-time.After(time.Second):
		t.Fatal("stale identity accept did not return")
	}
	_ = raw.Close()
}
