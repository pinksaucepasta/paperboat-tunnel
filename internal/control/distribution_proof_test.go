package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

func TestEd25519DistributionRequestSignerBindsExactRequest(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, distributionProofNonceBytes)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	signer, err := NewEd25519DistributionRequestSigner(DistributionProofSignerConfig{
		PrivateKey: privateKey, NodeID: "edge_01", ProcessEpoch: "epoch_0001",
		Now: func() time.Time { return now }, Nonce: func() ([]byte, error) { return append([]byte(nil), nonce...), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"edge_node_id":"edge_01","edge_process_epoch":"epoch_0001","limit":1}`)
	proof, err := signer.SignDistributionRequest(context.Background(), http.MethodPost, CertificateDistributionPullPath, body)
	if err != nil {
		t.Fatal(err)
	}
	header, err := distributionProofHeaders(proof)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(header[distributionProofSignatureHeader])
	if err != nil || !ed25519.Verify(publicKey, []byte(distributionProofTranscript(http.MethodPost, CertificateDistributionPullPath, "edge_01", "epoch_0001", now, header[distributionProofNonceHeader], digestHex(digest))), signature) {
		t.Fatal("signed distribution transcript did not verify")
	}
	if _, err := signer.SignDistributionRequest(context.Background(), http.MethodGet, CertificateDistributionPullPath, body); !errors.Is(err, ErrDistributionProofInvalid) {
		t.Fatalf("GET signing error = %v", err)
	}
	if _, err := signer.SignDistributionRequest(context.Background(), http.MethodPost, "/v1/edge/certificates/distributions/other", body); !errors.Is(err, ErrDistributionProofInvalid) {
		t.Fatalf("wrong path signing error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignDistributionRequest(ctx, http.MethodPost, CertificateDistributionPullPath, body); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled signing error = %v", err)
	}
}

func TestCertificateDistributionClientRequiresProofAndExactAckStatus(t *testing.T) {
	client, err := NewHTTPClient(HTTPConfig{BaseURL: "https://control.example.test", Credential: "distribution-credential-012345678901234567890123456789", Timeout: time.Second, Client: &http.Client{Transport: distributionRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(`{"version":1,"complete":true,"messages":[]}`))), Header: make(http.Header)}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertificateDistributionClient(client); err != nil {
		t.Fatal(err)
	}
	distributionClient, _ := NewCertificateDistributionClient(client)
	if _, err := distributionClient.Pull(context.Background(), "edge_01", "epoch_0001"); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("pull without signer error = %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519DistributionRequestSigner(DistributionProofSignerConfig{PrivateKey: privateKey, NodeID: "edge_01", ProcessEpoch: "epoch_0001"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetDistributionRequestSigner(signer); err != nil {
		t.Fatal(err)
	}
	envelope := tlscert.DistributionEnvelope{Action: "stage", CertificateID: "certificate_01", Fingerprint: [32]byte{1}, Binding: tlscert.Binding{AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test", DomainGeneration: 1, CertificateGeneration: 1, EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", AssignmentGeneration: 1}}
	for _, test := range []struct {
		status string
		code   string
	}{
		{status: "active"},
		{status: "ready", code: "unexpected"},
		{status: "failed"},
	} {
		if err := distributionClient.Ack(context.Background(), envelope, test.status, test.code); !errors.Is(err, ErrCertificateDistributionInvalid) {
			t.Errorf("ack status=%q code=%q error=%v", test.status, test.code, err)
		}
	}
}

type distributionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f distributionRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func digestHex(value [sha256.Size]byte) string {
	return fmt.Sprintf("%x", value[:])
}
