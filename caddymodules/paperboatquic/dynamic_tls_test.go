package paperboatquic

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestConfigureDynamicTLSRequiresSource(t *testing.T) {
	if _, err := ConfigureDynamicTLS(nil, nil); !errors.Is(err, ErrDynamicTLSInvalid) {
		t.Fatalf("nil source error=%v", err)
	}
	if err := (&App{}).SetDynamicTLS(nil); !errors.Is(err, ErrDynamicTLSInvalid) {
		t.Fatalf("nil app source error=%v", err)
	}
	if _, err := ConfigureDynamicTLS(&tls.Config{}, paperboatQUICEmptyCertificateSource{}); err != nil {
		t.Fatal(err)
	}
}

type paperboatQUICEmptyCertificateSource struct{}

func (paperboatQUICEmptyCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}
