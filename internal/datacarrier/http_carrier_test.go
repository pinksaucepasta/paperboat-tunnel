package datacarrier

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestHTTPServiceAcceptsRealHTTP2AndHTTP3CONNECT(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			clientTLS, serverTLS, _ := testEndpointCertificates(t)
			identity := testCarrierIdentity()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			endpoint := EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(state tls.ConnectionState) (Identity, error) { return identity, nil }}
			config := ServiceConfig{Carrier: testCarrierConfig(2)}
			if protocol == "h2" {
				config.TCP = &endpoint
			} else {
				config.QUIC = &endpoint
			}
			service, err := NewHTTPService(ctx, config)
			if err != nil {
				t.Fatalf("new HTTP service: %v", err)
			}
			defer service.Close()

			var roundTripper http.RoundTripper
			var closeTransport func()
			var address string
			if protocol == "h2" {
				clientTLS.NextProtos = []string{"h2"}
				transport := &http2.Transport{TLSClientConfig: clientTLS}
				roundTripper, closeTransport, address = transport, transport.CloseIdleConnections, service.TCPAddr().String()
			} else {
				clientTLS.NextProtos = []string{"h3"}
				transport := &http3.Transport{TLSClientConfig: clientTLS}
				roundTripper, closeTransport, address = transport, func() { _ = transport.Close() }, service.QUICAddr().String()
			}
			defer closeTransport()
			bodyReader, bodyWriter := io.Pipe()
			defer bodyWriter.Close()
			req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address+httpCarrierPath, bodyReader)
			if err != nil {
				t.Fatal(err)
			}
			response, err := roundTripper.RoundTrip(req)
			if err != nil {
				t.Fatalf("CONNECT: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.NegotiatedProtocol != protocol {
				t.Fatalf("status/TLS = %d/%v", response.StatusCode, response.TLS)
			}
			server, err := service.Accept(ctx)
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			client, err := NewClient(ctx, &testHTTPLink{Reader: response.Body, Writer: bodyWriter}, config.Carrier)
			if err != nil {
				t.Fatalf("new yamux client: %v", err)
			}
			stream, err := server.OpenStream(ctx, testStreamOpen("route-a", "http-connect"))
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}
			accepted, _, err := client.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("accept stream: %v", err)
			}
			if _, err := io.WriteString(stream, "duplex"); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 6)
			if _, err := io.ReadFull(accepted, buffer); err != nil || string(buffer) != "duplex" {
				t.Fatalf("read = %q, %v", buffer, err)
			}
			_ = accepted.Close()
			_ = stream.Close()
			_ = client.Close()
			if err := server.Close(); err != nil && !errors.Is(err, ErrCarrierClosed) {
				t.Fatalf("close accepted server: %v", err)
			}
		})
	}
}

type testHTTPLink struct {
	io.Reader
	io.Writer
}

func (l *testHTTPLink) Close() error { return nil }

func TestHTTPServiceRejectsPeerBinding(t *testing.T) {
	clientTLS, serverTLS, _ := testEndpointCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	service, err := NewHTTPService(ctx, ServiceConfig{Carrier: testCarrierConfig(1), TCP: &EndpointConfig{Address: "127.0.0.1:0", TLS: serverTLS, PeerBinding: func(tls.ConnectionState) (Identity, error) { return Identity{}, ErrIdentityMismatch }}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	clientTLS.NextProtos = []string{"h2"}
	transport := &http2.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	reader, writer := io.Pipe()
	defer writer.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+service.TCPAddr().String()+httpCarrierPath, reader)
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}
