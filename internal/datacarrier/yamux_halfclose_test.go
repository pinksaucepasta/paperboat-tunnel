package datacarrier

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestLibp2pYamuxDelayedHalfCloseBothDirections(t *testing.T) {
	left, right := net.Pipe()
	client, err := newYamuxSession(left, testCarrierConfig(4), true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newYamuxSession(right, testCarrierConfig(4), false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, clientFirst := range []bool{true, false} {
		opened, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		first, second := opened, accepted
		if !clientFirst {
			first, second = accepted, opened
		}
		if _, err := io.WriteString(first, "request"); err != nil {
			t.Fatal(err)
		}
		if err := first.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		request, err := io.ReadAll(second)
		if err != nil || string(request) != "request" {
			t.Fatalf("request = %q, %v", request, err)
		}
		if _, err := io.WriteString(second, "response"); err != nil {
			t.Fatal(err)
		}
		if err := second.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(first)
		if err != nil || string(response) != "response" {
			t.Fatalf("response = %q, %v", response, err)
		}
		_ = first.Close()
		_ = second.Close()
	}
}

func TestLibp2pYamuxResetLeavesNeighboringStreamUsable(t *testing.T) {
	left, right := net.Pipe()
	client, _ := newYamuxSession(left, testCarrierConfig(4), true)
	server, _ := newYamuxSession(right, testCarrierConfig(4), false)
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, _ := client.OpenStream(ctx)
	firstPeer, _ := server.AcceptStream(ctx)
	neighbor, _ := client.OpenStream(ctx)
	neighborPeer, _ := server.AcceptStream(ctx)
	if err := first.(interface{ Reset() error }).Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := firstPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("reset peer read unexpectedly succeeded")
	}
	if _, err := io.WriteString(neighbor, "ok"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(neighborPeer, buffer); err != nil || string(buffer) != "ok" {
		t.Fatalf("neighbor = %q, %v", buffer, err)
	}
	_ = firstPeer.Close()
	_ = neighbor.Close()
	_ = neighborPeer.Close()
}

func TestLibp2pYamuxGracefulClosePreservesBufferedBytes(t *testing.T) {
	left, right := net.Pipe()
	client, _ := newYamuxSession(left, testCarrierConfig(4), true)
	server, _ := newYamuxSession(right, testCarrierConfig(4), false)
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, _ := client.OpenStream(ctx)
	peer, _ := server.AcceptStream(ctx)
	if _, err := io.WriteString(stream, "ready"); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "ready" {
		t.Fatalf("ready = %q, %v", got, err)
	}
	_ = peer.Close()
}
