package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	DefaultProcessCarrierServerCertificateLifetime = 7 * 24 * time.Hour
	MaxProcessCarrierServerCertificateLifetime     = 7 * 24 * time.Hour
)

type ProcessCarrierServerTrust struct {
	Certificate         tls.Certificate
	SPKISHA256          string
	CertificateChainPEM string
}

// NewProcessCarrierServerTrust mints one in-memory leaf/key for one edge
// process. A replacement process therefore cannot reuse the old process's
// carrier TLS identity even when both use the same deployment configuration.
func NewProcessCarrierServerTrust(nodeID, processEpoch, hostname string, now time.Time, lifetime time.Duration) (ProcessCarrierServerTrust, error) {
	if strings.TrimSpace(nodeID) == "" || strings.TrimSpace(processEpoch) == "" || strings.TrimSpace(hostname) != hostname || hostname == "" || lifetime <= 0 || lifetime > MaxProcessCarrierServerCertificateLifetime {
		return ProcessCarrierServerTrust{}, errors.New("invalid process carrier server trust request")
	}
	if ip := net.ParseIP(hostname); ip == nil && (len(hostname) > 253 || strings.ContainsAny(hostname, "/:@\r\n\x00")) {
		return ProcessCarrierServerTrust{}, errors.New("invalid process carrier server hostname")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Paperboat edge carrier " + nodeID},
		NotBefore: now.UTC().Add(-time.Minute), NotAfter: now.UTC().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pin, err := CarrierServerSPKISHA256(certificate)
	if err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	chain, err := CarrierServerCertificateChainPEM(certificate)
	if err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	if err := ValidateCarrierServerCertificateChain(chain, pin, hostname, now.UTC()); err != nil {
		return ProcessCarrierServerTrust{}, err
	}
	return ProcessCarrierServerTrust{Certificate: certificate, SPKISHA256: pin, CertificateChainPEM: chain}, nil
}
