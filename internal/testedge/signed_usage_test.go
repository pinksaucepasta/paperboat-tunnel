package testedge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

func TestFakeControlVerifiesSignedUsagePayload(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := New()
	fake.SetUsageKey("usage-key-1", public)
	document := usage.SignedDocument{OperationID: "op_signed", Key: usage.Key{Node: "n", Epoch: "e", Environment: "env", Route: "r", Revision: 1, Direction: "egress"}, Bytes: 10, Start: time.Unix(1, 0), End: time.Unix(2, 0)}
	report, err := usage.NewSignedReport("usage-key-1", private, document)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fake.ReportUsage(context.Background(), control.UsageReport{OperationID: report.OperationID, Key: report.Key, Bytes: report.Bytes, Interval: report.Interval, Payload: report.Payload})
	if err != nil || result.Delta != 10 {
		t.Fatalf("signed report = %+v, %v", result, err)
	}
	tampered := append([]byte(nil), report.Payload...)
	tampered[len(tampered)-1] ^= 1
	if _, err := fake.ReportUsage(context.Background(), control.UsageReport{OperationID: "op_tampered", Key: report.Key, Bytes: report.Bytes, Interval: report.Interval, Payload: tampered}); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if _, err := fake.ReportUsage(context.Background(), control.UsageReport{OperationID: report.OperationID, Key: report.Key, Bytes: report.Bytes + 1, Interval: report.Interval, Payload: report.Payload}); err == nil {
		t.Fatal("relabeled signed payload accepted")
	}
}
