package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPeerServiceDispatchUsesExactNormalizedHostAndPath(t *testing.T) {
	signaling := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusSwitchingProtocols)
	})
	relay := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	})
	previewRelay := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusCreated)
	})
	gateway := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := peerServiceDispatch("signal.example.test", signaling, relay, previewRelay, gateway)

	for _, test := range []struct {
		host   string
		method string
		path   string
		want   int
	}{
		{host: "signal.example.test", method: http.MethodGet, path: "/network-check/v1", want: http.StatusNoContent},
		{host: "signal.example.test", method: http.MethodPost, path: "/network-check/v1", want: http.StatusNotFound},
		{host: "signal.example.test", method: http.MethodGet, path: "/v1/peer-signaling", want: http.StatusSwitchingProtocols},
		{host: "SIGNAL.EXAMPLE.TEST:443", method: http.MethodGet, path: "/v1/peer-relay", want: http.StatusAccepted},
		{host: "signal.example.test", method: http.MethodPost, path: "/v1/public-preview-relay", want: http.StatusCreated},
		{host: "signal.example.test", method: http.MethodGet, path: "/v1/unknown", want: http.StatusNotFound},
		{host: "preview.example.test", method: http.MethodGet, path: "/v1/peer-signaling", want: http.StatusNoContent},
		{host: "signal.example.test.attacker.test", method: http.MethodGet, path: "/v1/peer-relay", want: http.StatusNoContent},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, "http://private"+test.path, nil)
		request.Host = test.host
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Errorf("host %q: status = %d, want %d", test.host, recorder.Code, test.want)
		}
		if test.path == "/network-check/v1" && test.method == http.MethodGet && (recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("network check body=%q cache=%q", recorder.Body.String(), recorder.Header().Get("Cache-Control"))
		}
	}
}

func TestProbeCaddyTLSVerifiesIdentityAndValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name            string
		certificateHost string
		probeHost       string
		notBefore       time.Time
		notAfter        time.Time
		wantError       bool
	}{
		{name: "valid", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour)},
		{name: "wrong host", certificateHost: "other.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), wantError: true},
		{name: "expired", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(-time.Hour), notAfter: now.Add(-time.Minute), wantError: true},
		{name: "not yet valid", certificateHost: "preview.example.test", probeHost: "preview.example.test", notBefore: now.Add(time.Minute), notAfter: now.Add(time.Hour), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := serveTLS(t, test.certificateHost, test.notBefore, test.notAfter)
			expiresAt, err := probeCaddyTLS(address, test.probeHost)
			if (err != nil) != test.wantError {
				t.Fatalf("expiry=%s error=%v", expiresAt, err)
			}
			if !expiresAt.Equal(test.notAfter) {
				t.Fatalf("expiry=%s want=%s", expiresAt, test.notAfter)
			}
		})
	}
}

func serveTLS(t *testing.T, host string, notBefore, notAfter time.Time) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	t.Cleanup(func() { _ = tlsListener.Close() })
	go func() {
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
			}()
		}
	}()
	return listener.Addr().String()
}
