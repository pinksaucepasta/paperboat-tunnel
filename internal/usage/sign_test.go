package usage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func signedDocument() SignedDocument {
	return SignedDocument{OperationID: "op_usage_0001", Key: Key{Node: "edge", Epoch: "epoch_01", Environment: "env", Route: "route", Revision: 2, Direction: "egress"}, Bytes: 1024, Start: time.Unix(100, 0).UTC(), End: time.Unix(200, 0).UTC()}
}

func TestSignedReportRoundTripAndExactQueueRetry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := NewSignedReport("usage-key-1", private, signedDocument())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignedReport("usage-key-1", public, report.Payload)
	if err != nil || verified.OperationID != report.OperationID || verified.Bytes != report.Bytes {
		t.Fatalf("verified = %+v, %v", verified, err)
	}
	queue, _ := NewQueue(1, 1<<20)
	if err := queue.Enqueue(report); err != nil {
		t.Fatal(err)
	}
	first, _ := queue.Next()
	second, _ := queue.Next()
	if string(first.Payload) != string(second.Payload) {
		t.Fatal("retry payload changed")
	}
}

func TestSignedReportRejectsTamperingWrongKeyAndMalformedInterval(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	report, err := NewSignedReport("usage-key-1", private, signedDocument())
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), report.Payload...)
	tampered[len(tampered)/2] ^= 1
	if _, err := VerifySignedReport("usage-key-1", public, tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tamper error = %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySignedReport("usage-key-1", other, report.Payload); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key error = %v", err)
	}
	invalid := signedDocument()
	invalid.End = invalid.Start.Add(-time.Second)
	if _, err := NewSignedReport("usage-key-1", private, invalid); !errors.Is(err, ErrSignature) {
		t.Fatalf("interval error = %v", err)
	}
}

func TestSignedReportRejectsDuplicateAndNonCanonicalEncodings(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	report, err := NewSignedReport("usage-key-1", private, signedDocument())
	if err != nil {
		t.Fatal(err)
	}
	duplicateEnvelope := bytes.Replace(report.Payload, []byte(`"kid":"usage-key-1"`), []byte(`"kid":"usage-key-1","kid":"usage-key-1"`), 1)
	if bytes.Equal(duplicateEnvelope, report.Payload) {
		t.Fatal("envelope fixture did not mutate")
	}
	if _, err := VerifySignedReport("usage-key-1", public, duplicateEnvelope); !errors.Is(err, ErrSignature) {
		t.Fatalf("duplicate envelope error=%v", err)
	}

	var envelope signedEnvelope
	if err := json.Unmarshal(report.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	originalPayload := envelope.Payload
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	duplicatePayload := bytes.Replace(payload, []byte(`"bytes":1024`), []byte(`"bytes":1024,"bytes":1024`), 1)
	if bytes.Equal(duplicatePayload, payload) {
		t.Fatal("payload fixture did not mutate")
	}
	envelope.Payload = base64.RawURLEncoding.EncodeToString(duplicatePayload)
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, duplicatePayload))
	duplicateSigned, _ := json.Marshal(envelope)
	if _, err := VerifySignedReport("usage-key-1", public, duplicateSigned); !errors.Is(err, ErrSignature) {
		t.Fatalf("duplicate payload error=%v", err)
	}

	nonCanonical := strings.Replace(string(report.Payload), originalPayload, originalPayload+"=", 1)
	if _, err := VerifySignedReport("usage-key-1", public, []byte(nonCanonical)); !errors.Is(err, ErrSignature) {
		t.Fatalf("non-canonical base64 error=%v", err)
	}
}

func TestSignedReportCreationEnforcesCanonicalKeyAndUTC(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	document := signedDocument()
	document.Start = document.Start.In(time.FixedZone("offset", 3600))
	document.End = document.End.In(time.FixedZone("offset", 3600))
	report, err := NewSignedReport("usage-key-1", private, document)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignedReport("usage-key-1", public, report.Payload)
	if err != nil || verified.Start.Location() != time.UTC || verified.End.Location() != time.UTC || report.Interval[0].Location() != time.UTC || report.Interval[1].Location() != time.UTC {
		t.Fatalf("verified=%+v interval=%v error=%v", verified, report.Interval, err)
	}
	if _, err := NewSignedReport(strings.Repeat("k", 129), private, document); !errors.Is(err, ErrSignature) {
		t.Fatalf("overlong key ID error=%v", err)
	}
}
