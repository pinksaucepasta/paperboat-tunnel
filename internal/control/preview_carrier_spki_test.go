package control

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestPreviewCarrierSPKIWirePinIsValidatedAndRetained(t *testing.T) {
	now := time.Now().UTC()
	admission := testPreviewCarrierAdmissionForHTTP(t, "preview_spki", "operation_spki", "route_spki", "preview-spki.preview.example.test", now.Add(time.Hour))

	if err := admission.Validate("edge_1", now, "edge_epoch_1"); err != nil {
		t.Fatalf("valid SPKI binding rejected: %v", err)
	}
	expected, err := admission.Expected("edge_1", now)
	if err != nil {
		t.Fatalf("convert admission: %v", err)
	}
	if expected.EdgeCarrierServerSPKISHA256 != admission.Binding.EdgeCarrierServerSPKISHA256 {
		t.Fatalf("SPKI pin was not retained: got %q, want %q", expected.EdgeCarrierServerSPKISHA256, admission.Binding.EdgeCarrierServerSPKISHA256)
	}
	if expected.EdgeCarrierServerCertificateChainPEM != admission.Binding.EdgeCarrierServerCertificateChainPEM {
		t.Fatalf("certificate chain was not retained")
	}

	for name, mutate := range map[string]func(*PreviewCarrierAdmission){
		"base64 pin": func(value *PreviewCarrierAdmission) {
			value.Binding.EdgeCarrierServerSPKISHA256 = "sha256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"uppercase pin": func(value *PreviewCarrierAdmission) {
			value.Binding.EdgeCarrierServerSPKISHA256 = "sha256:" + strings.ToUpper(strings.TrimPrefix(admission.Binding.EdgeCarrierServerSPKISHA256, "sha256:"))
		},
		"missing pin": func(value *PreviewCarrierAdmission) {
			value.Binding.EdgeCarrierServerSPKISHA256 = ""
		},
		"missing chain": func(value *PreviewCarrierAdmission) {
			value.Binding.EdgeCarrierServerCertificateChainPEM = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := admission
			mutate(&candidate)
			if err := candidate.Validate("edge_1", now, "edge_epoch_1"); err == nil {
				t.Fatal("invalid SPKI binding was accepted")
			}
		})
	}
}
