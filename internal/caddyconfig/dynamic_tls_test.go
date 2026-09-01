package caddyconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestDynamicTLSConfigUsesSourceForEveryHandshake(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	first := dynamicTestCertificate(t, "first.example.test", now, 1)
	second := dynamicTestCertificate(t, "second.example.test", now, 2)
	source := &dynamicCertificateSource{certificate: &first}
	base := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{second}, NextProtos: []string{"h2"}}
	config, err := DynamicTLSConfig(base, source)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || len(config.Certificates) != 0 {
		t.Fatalf("dynamic config retained static TLS material: min=%d certificates=%d", config.MinVersion, len(config.Certificates))
	}
	selected, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "first.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Certificates) != 1 || selected.GetCertificate != nil || selected.NextProtos[0] != "h2" {
		t.Fatalf("unexpected selected config: %+v", selected)
	}
	if got := selected.Certificates[0].Certificate[0]; len(got) == 0 || string(got) == string(second.Certificate[0]) {
		t.Fatal("selected config did not use source certificate")
	}
	source.certificate = &second
	selected, err = config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "second.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if string(selected.Certificates[0].Certificate[0]) != string(second.Certificate[0]) {
		t.Fatal("certificate replacement was not visible to next handshake")
	}
}

func TestDynamicTLSConfigRequiresUsableSourceCertificate(t *testing.T) {
	if _, err := DynamicTLSConfig(nil, nil); !errors.Is(err, ErrDynamicTLSInvalid) {
		t.Fatalf("nil source error=%v", err)
	}
	config, err := DynamicTLSConfig(nil, &dynamicCertificateSource{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "missing.example.test"}); !errors.Is(err, ErrDynamicTLSInvalid) {
		t.Fatalf("empty source certificate error=%v", err)
	}
}

type dynamicCertificateSource struct{ certificate *tls.Certificate }

func (s *dynamicCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil || s.certificate == nil {
		return nil, ErrDynamicTLSInvalid
	}
	return s.certificate, nil
}

func dynamicTestCertificate(t *testing.T, host string, now time.Time, serial uint64) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetUint64(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
