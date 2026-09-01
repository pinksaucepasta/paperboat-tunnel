package caddyconfig

import (
	"crypto/tls"
	"errors"
)

var ErrDynamicTLSInvalid = errors.New("invalid dynamic TLS certificate source")

// CertificateSource is the narrow in-memory boundary used by the embedded
// Paperboat Caddy module. Implementations must select only an already
// distributed certificate; they must not issue, read, or persist key
// material during a TLS handshake.
type CertificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// DynamicTLSConfig returns a TLS configuration whose certificate selection is
// delegated to source for every ClientHello. The base configuration is cloned
// so callers may safely retain Caddy's listener, ALPN, client-auth, and
// timeout settings. Static certificates and a pre-existing certificate
// callback are intentionally not used: replacement is controlled by the
// authenticated edge distribution registry, and falling back to a stale or
// disk-backed Caddy certificate could serve an old generation after revoke.
//
// The returned configuration is safe to hand to a listener before it starts.
// CertificateSource implementations must make their own state safe for
// concurrent handshakes.
func DynamicTLSConfig(base *tls.Config, source CertificateSource) (*tls.Config, error) {
	if source == nil {
		return nil, ErrDynamicTLSInvalid
	}
	config := &tls.Config{}
	if base != nil {
		config = base.Clone()
	}
	if config.MinVersion < tls.VersionTLS13 {
		config.MinVersion = tls.VersionTLS13
	}
	config.Certificates = nil
	config.GetCertificate = source.GetCertificate
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		certificate, err := source.GetCertificate(hello)
		if err != nil {
			return nil, err
		}
		if certificate == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return nil, ErrDynamicTLSInvalid
		}
		selected := config.Clone()
		selected.Certificates = []tls.Certificate{cloneCertificate(*certificate)}
		selected.GetCertificate = nil
		selected.GetConfigForClient = nil
		return selected, nil
	}
	return config, nil
}

func cloneCertificate(certificate tls.Certificate) tls.Certificate {
	clone := certificate
	clone.Certificate = make([][]byte, len(certificate.Certificate))
	for index := range certificate.Certificate {
		clone.Certificate[index] = append([]byte(nil), certificate.Certificate[index]...)
	}
	clone.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	clone.SignedCertificateTimestamps = make([][]byte, len(certificate.SignedCertificateTimestamps))
	for index := range certificate.SignedCertificateTimestamps {
		clone.SignedCertificateTimestamps[index] = append([]byte(nil), certificate.SignedCertificateTimestamps[index]...)
	}
	return clone
}
