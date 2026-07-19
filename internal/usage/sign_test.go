package usage

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
