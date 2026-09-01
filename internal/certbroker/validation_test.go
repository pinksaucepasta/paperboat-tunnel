package certbroker

import (
	"strings"
	"testing"
)

func TestValidateRequestAndServerNameFailClosed(t *testing.T) {
	for _, request := range []Request{
		{Version: 0, ServerName: "example.test"},
		{Version: Version + 1, ServerName: "example.test"},
		{Version: Version, ServerName: ""},
		{Version: Version, ServerName: "127.0.0.1"},
		{Version: Version, ServerName: "*.example.test"},
		{Version: Version, ServerName: "example_test"},
		{Version: Version, ServerName: "example.test/path"},
		{Version: Version, ServerName: "example..test"},
		{Version: Version, ServerName: " example.test"},
	} {
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
	for _, name := range []string{"example.test", "BÜCHER.example.test.", "one.two.example.test"} {
		if !ValidServerName(name) {
			t.Fatalf("valid server name rejected: %q", name)
		}
	}
}

func TestValidateResponseRejectsSecretBearingFailureAndMalformedSuccess(t *testing.T) {
	valid := Response{Version: Version, OK: true, CertificatePEM: []byte("cert"), PrivateKeyPEM: []byte("key")}
	if err := ValidateResponse(valid); err != nil {
		t.Fatal(err)
	}
	for _, response := range []Response{
		{Version: Version + 1, OK: false, Error: "certificate_unavailable"},
		{Version: Version, OK: false, Error: "certificate_unavailable", PrivateKeyPEM: []byte("secret")},
		{Version: Version, OK: true, CertificatePEM: []byte("cert")},
		{Version: Version, OK: true, CertificatePEM: []byte("cert"), PrivateKeyPEM: []byte("key"), Error: "unexpected"},
		{Version: Version, OK: false, Error: "line1\nline2"},
		{Version: Version, OK: false, Error: strings.Repeat("x", 129)},
	} {
		if err := ValidateResponse(response); err == nil {
			t.Fatalf("invalid response accepted: %+v", response)
		}
	}
}
