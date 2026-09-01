package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/certbroker"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

var (
	ErrCertificateBrokerInvalid = errors.New("invalid certificate broker")
	ErrCertificateBrokerBusy    = errors.New("certificate broker socket is already in use")
)

const maximumCertificateDemandCalls = 1024

// CertificateSource is the edge certificate registry used by both the custom
// Caddy module and the broker. It normally returns only an already staged and
// active certificate. A source may expose OnDemandCertificateRequester and
// OnDemandCertificateMatcher to request one exact SNI when the central
// registry has not installed that leaf yet. The requester is invoked under
// the bounded handshake context and must authenticate the edge/node binding
// before it asks the server to issue anything.
type CertificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// OnDemandCertificateRequester is the authenticated control-plane boundary
// for an exact-SNI leaf. It must not accept arbitrary hostnames: production
// implementations validate the verified wildcard binding, edge/process/
// assignment generations, and the current node identity before issuing.
type OnDemandCertificateRequester interface {
	RequestCertificate(context.Context, string) error
}

type OnDemandCertificateRequesterFunc func(context.Context, string) error

func (f OnDemandCertificateRequesterFunc) RequestCertificate(ctx context.Context, hostname string) error {
	return f(ctx, hostname)
}

// OnDemandCertificateMatcher marks names for which the wildcard certificate
// must never be used as a silent fallback. The matcher is intentionally
// separate from the requester so an edge can reject an exact SNI locally
// while the request is still being authorized by the server.
type OnDemandCertificateMatcher interface {
	RequiresExactCertificate(string) bool
}

type OnDemandCertificateMatcherFunc func(string) bool

func (f OnDemandCertificateMatcherFunc) RequiresExactCertificate(hostname string) bool {
	return f(hostname)
}

type CertificateBrokerConfig struct {
	SocketPath         string
	Source             CertificateSource
	OnDemandRequester  OnDemandCertificateRequester
	OnDemandMatcher    OnDemandCertificateMatcher
	MaximumConnections int
	HandshakeTimeout   time.Duration
}

type CertificateBroker struct {
	socketPath string
	source     CertificateSource
	maximum    int
	timeout    time.Duration
	onDemand   OnDemandCertificateRequester
	matcher    OnDemandCertificateMatcher

	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc
	runCtx   context.Context
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	sem      chan struct{}
	demandMu sync.Mutex
	demand   map[string]*certificateDemandCall
	errMu    sync.Mutex
	lastErr  error
}

func NewCertificateBroker(config CertificateBrokerConfig) (*CertificateBroker, error) {
	if err := validateCertificateBrokerConfig(config); err != nil {
		return nil, err
	}
	if config.MaximumConnections == 0 {
		config.MaximumConnections = 64
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 2 * time.Second
	}
	return &CertificateBroker{
		socketPath: config.SocketPath,
		source:     config.Source,
		maximum:    config.MaximumConnections,
		timeout:    config.HandshakeTimeout,
		onDemand:   config.OnDemandRequester,
		matcher:    config.OnDemandMatcher,
		conns:      make(map[net.Conn]struct{}),
		sem:        make(chan struct{}, config.MaximumConnections),
		demand:     make(map[string]*certificateDemandCall),
	}, nil
}

type certificateDemandCall struct {
	done       chan struct{}
	err        error
	cancel     context.CancelFunc
	finishedAt time.Time
}

func (c CertificateBrokerConfig) Validate() error { return validateCertificateBrokerConfig(c) }

func validateCertificateBrokerConfig(config CertificateBrokerConfig) error {
	if config.Source == nil || !filepath.IsAbs(config.SocketPath) || len(config.SocketPath) > 100 || strings.ContainsAny(config.SocketPath, "\x00\r\n") || config.SocketPath == string(filepath.Separator) {
		return ErrCertificateBrokerInvalid
	}
	if config.MaximumConnections < 0 || config.MaximumConnections > 4096 || config.HandshakeTimeout < 0 || config.HandshakeTimeout > 30*time.Second {
		return ErrCertificateBrokerInvalid
	}
	return nil
}

func (c *CertificateBroker) SocketPath() string {
	if c == nil {
		return ""
	}
	return c.socketPath
}

func (c *CertificateBroker) Start(ctx context.Context) error {
	if c == nil || c.source == nil || ctx == nil {
		return ErrCertificateBrokerInvalid
	}
	c.mu.Lock()
	if c.listener != nil || c.closed {
		c.mu.Unlock()
		return ErrCertificateBrokerInvalid
	}
	c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.socketPath), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(c.socketPath), 0700); err != nil {
		return err
	}
	if err := prepareCertificateBrokerSocket(c.socketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("listen certificate broker: %w", err)
	}
	c.mu.Lock()
	if c.closed || c.listener != nil {
		c.mu.Unlock()
		_ = listener.Close()
		_ = os.Remove(c.socketPath)
		return ErrCertificateBrokerInvalid
	}
	// Keep the socket publication critical section through permission setup.
	// Shutdown may otherwise remove a just-created socket between net.Listen
	// and Chmod, turning a normal concurrent start/stop race into ENOENT.
	if err := os.Chmod(c.socketPath, 0600); err != nil {
		c.mu.Unlock()
		_ = listener.Close()
		_ = os.Remove(c.socketPath)
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	c.listener, c.cancel, c.runCtx = listener, cancel, workerCtx
	// Account for the accept loop before publishing the listener. Shutdown
	// may begin immediately after this unlock and must never race Wait with a
	// subsequent Add.
	c.wg.Add(1)
	c.mu.Unlock()
	go c.acceptLoop(workerCtx, listener)
	return nil
}

func (c *CertificateBroker) acceptLoop(ctx context.Context, listener net.Listener) {
	defer c.wg.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.recordError(fmt.Errorf("certificate broker accept: %w", err))
			return
		}
		select {
		case c.sem <- struct{}{}:
			// The accept loop itself is already counted, so this positive Add
			// remains legal even if Shutdown has started waiting. Count the
			// handler before publishing its connection to Shutdown.
			c.wg.Add(1)
			if !c.track(connection) {
				c.wg.Done()
				<-c.sem
				_ = connection.Close()
				continue
			}
			go func() {
				defer c.wg.Done()
				defer func() { <-c.sem }()
				defer c.untrack(connection)
				c.handle(ctx, connection)
			}()
		default:
			_ = connection.SetDeadline(time.Now().Add(c.timeout))
			_ = certbroker.Write(connection, certbroker.Response{Version: certbroker.Version, Error: "certificate_broker_busy"}, certbroker.MaximumResponse)
			_ = connection.Close()
		}
	}
}

func (c *CertificateBroker) track(connection net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.conns[connection] = struct{}{}
	return true
}

func (c *CertificateBroker) untrack(connection net.Conn) {
	c.mu.Lock()
	delete(c.conns, connection)
	c.mu.Unlock()
	_ = connection.Close()
}

func (c *CertificateBroker) handle(parent context.Context, connection net.Conn) {
	requestContext := parent
	var cancel context.CancelFunc
	if c.timeout > 0 {
		requestContext, cancel = context.WithTimeout(parent, c.timeout)
		defer cancel()
		if deadline, ok := requestContext.Deadline(); ok {
			_ = connection.SetDeadline(deadline)
		}
	}
	var request certbroker.Request
	if err := certbroker.Read(connection, &request, certbroker.MaximumRequest); err != nil || certbroker.ValidateRequest(request) != nil {
		c.writeError(connection, "certificate_request_invalid")
		return
	}
	if err := requestContext.Err(); err != nil {
		c.writeError(connection, "certificate_broker_closed")
		return
	}
	certificate, err := c.lookupCertificate(requestContext, request.ServerName)
	if err != nil || certificate == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		c.writeError(connection, "certificate_unavailable")
		return
	}
	certificatePEM, privateKeyPEM, err := encodeCertificate(certificate)
	if err != nil {
		c.writeError(connection, "certificate_unavailable")
		return
	}
	defer clear(certificatePEM)
	defer clear(privateKeyPEM)
	response := certbroker.Response{Version: certbroker.Version, OK: true, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}
	if err := certbroker.ValidateResponse(response); err != nil {
		c.writeError(connection, "certificate_unavailable")
		return
	}
	c.setResponseDeadline(connection)
	_ = certbroker.Write(connection, response, certbroker.MaximumResponse)
}

func (c *CertificateBroker) lookupCertificate(ctx context.Context, hostname string) (*tls.Certificate, error) {
	if c == nil || c.source == nil {
		return nil, ErrCertificateBrokerInvalid
	}
	canonicalHostname, wildcard, err := tlscert.NormalizeHostname(hostname)
	if err != nil || wildcard {
		return nil, tlscert.ErrCertificateMissing
	}
	hostname = canonicalHostname
	if c.matcher != nil && c.matcher.RequiresExactCertificate(hostname) {
		// A policy-marked name may use an already-installed exact leaf, but it
		// must never receive a wildcard result from the source. Consult the
		// source first so a matcher that conservatively marks every name does
		// not trigger duplicate CA issuance for an active exact certificate.
		certificate, sourceErr := c.source.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname})
		if sourceErr == nil && certificate != nil && certificateCoversExactHost(certificate, hostname) {
			return certificate, nil
		}
		if sourceErr != nil && !errors.Is(sourceErr, tlscert.ErrCertificateMissing) && !errors.Is(sourceErr, tlscert.ErrCertificateExpired) {
			return certificate, sourceErr
		}
		if c.onDemand == nil {
			if sourceErr != nil {
				return nil, sourceErr
			}
			return nil, tlscert.ErrCertificateMissing
		}
		if err := c.requestOnDemand(ctx, hostname); err != nil {
			return nil, err
		}
		certificate, sourceErr = c.source.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname})
		if sourceErr != nil {
			return certificate, sourceErr
		}
		if !certificateCoversExactHost(certificate, hostname) {
			return nil, tlscert.ErrCertificateMissing
		}
		return certificate, nil
	}
	certificate, err := c.source.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname})
	if err == nil {
		if certificateCoversHost(certificate, hostname) {
			return certificate, nil
		}
		// A nil or unrelated certificate is a cache miss, not a successful
		// lookup. Treating it as success would make the broker's wire handler
		// return an ambiguous empty response and bypass an available exact-leaf
		// requester.
		err = tlscert.ErrCertificateMissing
	}
	if !errors.Is(err, tlscert.ErrCertificateMissing) && !errors.Is(err, tlscert.ErrCertificateExpired) {
		return certificate, err
	}
	if c.onDemand == nil {
		return certificate, err
	}
	if requestErr := c.requestOnDemand(ctx, hostname); requestErr != nil {
		return nil, requestErr
	}
	certificate, err = c.source.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname})
	if err != nil {
		return certificate, err
	}
	if !certificateCoversHost(certificate, hostname) {
		return nil, tlscert.ErrCertificateMissing
	}
	return certificate, nil
}

// certificateCoversHost is the broker's final source-independent hostname
// fence. Registry-backed sources already enforce exact and one-label
// wildcard matching, but the broker also accepts the Caddy seam as an
// interface. Rechecking here prevents a faulty source from serving an
// unrelated certificate for a valid SNI, and keeps the broker fail closed.
func certificateCoversHost(certificate *tls.Certificate, hostname string) bool {
	leaf, ok := certificateLeaf(certificate)
	if !ok {
		return false
	}
	return leaf.VerifyHostname(hostname) == nil
}

// certificateLeaf always parses the DER which will actually cross the
// broker boundary. A caller-provided tls.Certificate.Leaf is only a cache and
// may be stale or unrelated to Certificate[0]; trusting it could make the
// broker approve one hostname and send a different certificate.
func certificateLeaf(certificate *tls.Certificate) (*x509.Certificate, bool) {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, false
	}
	return leaf, true
}

// certificateCoversExactHost is the final fail-closed fence for matcher
// marked names. A source normally enforces this itself, but the broker owns
// the policy boundary and must not trust a wildcard certificate returned by a
// different source implementation after an on-demand request completes.
func certificateCoversExactHost(certificate *tls.Certificate, hostname string) bool {
	if !certificateCoversHost(certificate, hostname) {
		return false
	}
	leaf, ok := certificateLeaf(certificate)
	if !ok {
		return false
	}
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")), "*.") {
			return false
		}
	}
	return true
}

func (c *CertificateBroker) requestOnDemand(ctx context.Context, hostname string) error {
	if c == nil || c.onDemand == nil {
		return tlscert.ErrCertificateMissing
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !certbroker.ValidServerName(hostname) {
		return tlscert.ErrCertificateMissing
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	c.demandMu.Lock()
	for key, pending := range c.demand {
		if pending == nil || !pending.finishedAt.IsZero() && now.Sub(pending.finishedAt) >= c.timeout {
			delete(c.demand, key)
		}
	}
	if call := c.demand[hostname]; call != nil {
		c.demandMu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if len(c.demand) >= maximumCertificateDemandCalls {
		c.demandMu.Unlock()
		return ErrCertificateBrokerBusy
	}
	// The leader's request must not inherit one handshake caller's cancellation:
	// another coalesced handshake may still be waiting for the same exact leaf.
	// It remains bounded by the broker timeout and the broker lifecycle context,
	// so shutdown and a dead control plane cannot leave an unbounded goroutine.
	c.mu.Lock()
	closed := c.closed
	base := c.runCtx
	c.mu.Unlock()
	if closed {
		c.demandMu.Unlock()
		return tlscert.ErrClosed
	}
	if base == nil {
		base = context.WithoutCancel(ctx)
	}
	callCtx, cancel := context.WithTimeout(base, c.timeout)
	call := &certificateDemandCall{done: make(chan struct{}), cancel: cancel}
	c.demand[hostname] = call
	c.demandMu.Unlock()
	err := c.onDemand.RequestCertificate(callCtx, hostname)
	c.demandMu.Lock()
	call.err = err
	if err == nil {
		call.finishedAt = time.Now()
	}
	close(call.done)
	if err != nil {
		delete(c.demand, hostname)
	}
	c.demandMu.Unlock()
	cancel()
	return err
}

func (c *CertificateBroker) writeError(connection net.Conn, code string) {
	if len(code) == 0 || len(code) > 128 || strings.ContainsAny(code, "\r\n\x00") {
		code = "certificate_unavailable"
	}
	c.setResponseDeadline(connection)
	_ = certbroker.Write(connection, certbroker.Response{Version: certbroker.Version, Error: code}, certbroker.MaximumResponse)
}

func (c *CertificateBroker) setResponseDeadline(connection net.Conn) {
	if c == nil || connection == nil || c.timeout <= 0 {
		return
	}
	_ = connection.SetWriteDeadline(time.Now().Add(c.timeout))
}

// LastError reports an unexpected listener failure. A normal Shutdown does
// not record an error because its listener close is intentional.
func (c *CertificateBroker) LastError() error {
	if c == nil {
		return ErrCertificateBrokerInvalid
	}
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.lastErr
}

func (c *CertificateBroker) recordError(err error) {
	if err == nil {
		return
	}
	c.errMu.Lock()
	c.lastErr = err
	c.errMu.Unlock()
}

func (c *CertificateBroker) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	listener, cancel := c.listener, c.cancel
	c.listener, c.cancel, c.runCtx = nil, nil, nil
	for connection := range c.conns {
		_ = connection.Close()
	}
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.demandMu.Lock()
	for _, call := range c.demand {
		if call != nil && call.cancel != nil {
			call.cancel()
		}
	}
	c.demandMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := os.Remove(c.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func prepareCertificateBrokerSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return ErrCertificateBrokerInvalid
	}
	probe, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = probe.Close()
		return ErrCertificateBrokerBusy
	}
	return os.Remove(path)
}

func encodeCertificate(certificate *tls.Certificate) (certificatePEM, privateKeyPEM []byte, returnErr error) {
	if certificate == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, nil, ErrCertificateBrokerInvalid
	}
	defer func() {
		if returnErr != nil {
			clear(certificatePEM)
			clear(privateKeyPEM)
		}
	}()
	for _, der := range certificate.Certificate {
		if len(der) == 0 {
			return nil, nil, ErrCertificateBrokerInvalid
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyDER)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certificatePEM, privateKeyPEM, nil
}

func clear(values []byte) {
	for index := range values {
		values[index] = 0
	}
}

var _ Component = (*CertificateBroker)(nil)
