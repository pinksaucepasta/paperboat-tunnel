package paperboatquic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/certbroker"
)

var ErrCertificateGetterInvalid = errors.New("invalid Paperboat certificate getter")

func init() {
	caddy.RegisterModule(CertificateGetter{})
}

// CertificateGetter is Caddy's external certificate-manager adapter.  It
// talks to the tunnel runtime's permissioned Unix broker instead of Caddy
// storage.  The broker socket is the only cross-process boundary and is
// expected to be owned by the same service account with mode 0600.
type CertificateGetter struct {
	Socket  string         `json:"socket"`
	Timeout caddy.Duration `json:"timeout,omitempty"`
}

func (CertificateGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "tls.get_certificate.paperboat", New: func() caddy.Module { return new(CertificateGetter) }}
}

func (g *CertificateGetter) Provision(_ caddy.Context) error {
	if g == nil || !validCertificateGetterSocket(g.Socket) {
		return ErrCertificateGetterInvalid
	}
	if g.Timeout == 0 {
		g.Timeout = caddy.Duration(2 * time.Second)
	}
	if time.Duration(g.Timeout) <= 0 || time.Duration(g.Timeout) > 30*time.Second {
		return ErrCertificateGetterInvalid
	}
	return nil
}

func (g *CertificateGetter) Validate() error {
	if g == nil || !validCertificateGetterSocket(g.Socket) {
		return ErrCertificateGetterInvalid
	}
	if g.Timeout < 0 || time.Duration(g.Timeout) > 30*time.Second {
		return ErrCertificateGetterInvalid
	}
	return nil
}

func (g *CertificateGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if g == nil || hello == nil || !validCertificateGetterSocket(g.Socket) || !certbroker.ValidServerName(hello.ServerName) {
		return nil, ErrCertificateGetterInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(g.Timeout)
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(requestCtx, "unix", g.Socket)
	if err != nil {
		return nil, fmt.Errorf("%w: broker connection", certbroker.ErrUnavailable)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := certbroker.Write(connection, certbroker.Request{Version: certbroker.Version, ServerName: hello.ServerName}, certbroker.MaximumRequest); err != nil {
		return nil, fmt.Errorf("%w: request", certbroker.ErrUnavailable)
	}
	var response certbroker.Response
	if err := certbroker.Read(connection, &response, certbroker.MaximumResponse); err != nil {
		return nil, fmt.Errorf("%w: response", certbroker.ErrUnavailable)
	}
	// The broker response is the only place the external Caddy process sees
	// private-key bytes. Wipe both encoded buffers as soon as the response has
	// been consumed, including all validation and parse-error paths.
	defer clear(response.CertificatePEM)
	defer clear(response.PrivateKeyPEM)
	if err := certbroker.ValidateResponse(response); err != nil {
		return nil, fmt.Errorf("%w: response", certbroker.ErrUnavailable)
	}
	if !response.OK {
		return nil, fmt.Errorf("%w: %s", certbroker.ErrUnavailable, response.Error)
	}
	certificate, err := tls.X509KeyPair(response.CertificatePEM, response.PrivateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("%w: certificate", certbroker.ErrUnavailable)
	}
	certificate.Leaf, _ = x509ParseLeaf(certificate.Certificate[0])
	return &certificate, nil
}

func validCertificateGetterSocket(socket string) bool {
	return strings.HasPrefix(socket, "/") && len(socket) > 1 && len(socket) <= 100 && !strings.ContainsAny(socket, "\x00\r\n")
}

func x509ParseLeaf(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

var (
	_ certmagic.Manager = (*CertificateGetter)(nil)
	_ caddy.Provisioner = (*CertificateGetter)(nil)
	_ caddy.Validator   = (*CertificateGetter)(nil)
)
