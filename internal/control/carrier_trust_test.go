package control

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestProcessCarrierServerTrustIsProcessUniqueAndExactlyBound(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	one, err := NewProcessCarrierServerTrust("edge_1", "epoch_1", "edge.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewProcessCarrierServerTrust("edge_1", "epoch_2", "edge.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if one.SPKISHA256 == two.SPKISHA256 || one.CertificateChainPEM == two.CertificateChainPEM {
		t.Fatal("replacement process reused carrier server identity")
	}
	if err := ValidateCarrierServerCertificateChain(one.CertificateChainPEM, one.SPKISHA256, "edge.example.test", now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCarrierServerCertificateChain(one.CertificateChainPEM, two.SPKISHA256, "edge.example.test", now); err == nil {
		t.Fatal("wrong process pin accepted")
	}
	if err := ValidateCarrierServerCertificateChain(one.CertificateChainPEM, one.SPKISHA256, "other.example.test", now); err == nil {
		t.Fatal("wrong carrier hostname accepted")
	}
	block, _ := pem.Decode([]byte(one.CertificateChainPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !leaf.NotAfter.Equal(now.Add(time.Hour)) {
		t.Fatalf("leaf lifetime = %v, %v", leaf.NotAfter, err)
	}
}

func TestProcessCarrierServerTrustLifetimeIsBounded(t *testing.T) {
	now := time.Now().UTC()
	if DefaultProcessCarrierServerCertificateLifetime != MaxProcessCarrierServerCertificateLifetime {
		t.Fatal("default process certificate lifetime must use the bounded service-restart window")
	}
	if _, err := NewProcessCarrierServerTrust("edge_1", "epoch_1", "edge.example.test", now, MaxProcessCarrierServerCertificateLifetime+time.Second); err == nil {
		t.Fatal("over-limit process certificate lifetime accepted")
	}
}
