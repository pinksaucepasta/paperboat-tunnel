package paperboatquic

import (
	"crypto/tls"
	"errors"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/caddyconfig"
)

var ErrDynamicTLSInvalid = errors.New("invalid Paperboat dynamic TLS source")

// CertificateSource is implemented by the authenticated edge certificate
// registry. It is intentionally read-only from the Caddy side.
type CertificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// ConfigureDynamicTLS returns the listener configuration used by the QUIC
// app when certificate distribution is composed in-process. It preserves
// Paperboat's HTTP/3 and terminal ALPNs while replacing Caddy's static or
// disk-backed certificate selector with the in-memory source.
func ConfigureDynamicTLS(base *tls.Config, source CertificateSource) (*tls.Config, error) {
	if source == nil {
		return nil, ErrDynamicTLSInvalid
	}
	if base == nil {
		base = &tls.Config{}
	}
	config, err := caddyconfig.DynamicTLSConfig(terminalTLSConfig(base), source)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// SetDynamicTLS must be called before Start. The QUIC listener snapshots its
// TLS configuration at construction, so changing it after Start would leave
// one transport serving a stale certificate generation.
func (a *App) SetDynamicTLS(source CertificateSource) error {
	if a == nil || source == nil {
		return ErrDynamicTLSInvalid
	}
	config, err := ConfigureDynamicTLS(a.tlsConfig, source)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listener != nil || a.h3server != nil {
		return errors.New("dynamic TLS must be configured before Caddy QUIC starts")
	}
	a.tlsConfig = config
	return nil
}
