package datacarrier

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"
)

func TestServiceAcceptsAuthenticatedTCPCarrier(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	identity := testCarrierIdentity()
	config := testCarrierConfig(4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, err := NewService(ctx, ServiceConfig{
		Carrier: config,
		TCP: &EndpointConfig{
			Address: "127.0.0.1:0",
			TLS:     serverTLS,
			PeerBinding: func(state tls.ConnectionState) (Identity, error) {
				if len(state.PeerCertificates) == 0 {
					return Identity{}, errors.New("missing peer certificate")
				}
				return identity, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("new carrier service: %v", err)
	}
	defer service.Close()

	connection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", service.TCPAddr().String())
	if err != nil {
		t.Fatalf("dial carrier service: %v", err)
	}
	client, err := NewClient(ctx, connection, config)
	if err != nil {
		_ = connection.Close()
		t.Fatalf("new carrier client: %v", err)
	}
	defer client.Close()

	edge, err := service.Accept(ctx)
	if err != nil {
		t.Fatalf("accept authenticated carrier: %v", err)
	}
	defer edge.Close()

	open := testStreamOpen("route-a", "service-request")
	edgeStream, err := edge.OpenStream(ctx, open)
	if err != nil {
		t.Fatalf("open service stream: %v", err)
	}
	connectorStream, metadata, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept service stream: %v", err)
	}
	const body = "authenticated-service-body"
	if _, err := io.WriteString(edgeStream, body); err != nil {
		t.Fatalf("write service stream: %v", err)
	}
	if err := edgeStream.Close(); err != nil {
		t.Fatalf("close service stream: %v", err)
	}
	got, err := io.ReadAll(connectorStream)
	if err != nil {
		t.Fatalf("read service stream: %v", err)
	}
	_ = connectorStream.Close()
	if metadata != open || string(got) != body {
		t.Fatalf("service metadata/body = %+v/%q, want %+v/%q", metadata, got, open, body)
	}
}

func TestServiceRequiresAtLeastOneListener(t *testing.T) {
	_, err := NewService(context.Background(), ServiceConfig{Carrier: testCarrierConfig(1)})
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("empty service error = %v, want invalid endpoint", err)
	}
}

func TestServiceCloseClosesAcceptedCarriers(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	config := testCarrierConfig(2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, err := NewService(ctx, ServiceConfig{
		Carrier: config,
		TCP: &EndpointConfig{
			Address: "127.0.0.1:0",
			TLS:     serverTLS,
			PeerBinding: func(state tls.ConnectionState) (Identity, error) {
				if len(state.PeerCertificates) == 0 {
					return Identity{}, errors.New("missing peer certificate")
				}
				return config.Identity, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("new carrier service: %v", err)
	}

	connection, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", service.TCPAddr().String())
	if err != nil {
		_ = service.Close()
		t.Fatalf("dial carrier service: %v", err)
	}
	client, err := NewClient(ctx, connection, config)
	if err != nil {
		_ = connection.Close()
		_ = service.Close()
		t.Fatalf("new carrier client: %v", err)
	}
	defer client.Close()
	edge, err := service.Accept(ctx)
	if err != nil {
		_ = client.Close()
		_ = service.Close()
		t.Fatalf("accept carrier: %v", err)
	}

	if err := service.Close(); err != nil {
		t.Fatalf("close service: %v", err)
	}
	select {
	case <-edge.Done():
	case <-time.After(time.Second):
		t.Fatal("accepted carrier remained open after service close")
	}
	_ = edge.Close()
}
