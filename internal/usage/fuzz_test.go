package usage

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func FuzzVerifySignedReport(f *testing.F) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	report, err := NewSignedReport("usage-key-1", private, signedDocument())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(report.Payload)
	f.Add([]byte(nil))
	f.Add(make([]byte, 1<<20+1))

	f.Fuzz(func(t *testing.T, envelope []byte) {
		document, err := VerifySignedReport("usage-key-1", public, envelope)
		if err != nil {
			return
		}
		if err := validateDocument(document); err != nil {
			t.Fatalf("accepted invalid signed document: %v", err)
		}
		if document.OperationID == "" || document.Key.Node == "" || document.Key.Epoch == "" || document.Key.Environment == "" || document.Key.Route == "" || document.Key.Revision == 0 || document.Key.Direction != "ingress" && document.Key.Direction != "egress" {
			t.Fatalf("accepted document escaped usage binding: %+v", document)
		}
	})
}
