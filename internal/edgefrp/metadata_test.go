package edgefrp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestMetadataResolverDecodesExactHandoff(t *testing.T) {
	raw := `{"operation_id":"op_admit_0001","credential":"credential-012345678901234567890123456789","environment_id":"env","machine_id":"machine","connector_id":"runtime","connector_generation":3,"edge_pool":"default","edge_node_id":"edge","routes":[{"route_id":"route","route_revision":2,"kind":"runtime_https_wss","public_host":"helper.test","proxy_name":"proxy","target":{"host":"127.0.0.1","port":8080}}]}`
	request, err := (MetadataResolver{}).ResolveLogin(context.Background(), LoginContent{Metas: map[string]string{AdmissionMetadataKey: raw}})
	if err != nil || request.OperationID != "op_admit_0001" || request.Generation != 3 || len(request.Routes) != 1 || request.Routes[0].TargetPort != 8080 {
		t.Fatalf("request = %+v, %v", request, err)
	}
}

func TestMetadataResolverRejectsUnknownOversizedAndAdditionalMetadata(t *testing.T) {
	resolver := MetadataResolver{}
	for _, metas := range []map[string]string{{AdmissionMetadataKey: `{"unknown":true}`}, {AdmissionMetadataKey: `{"operation_id":"first","operation_id":"second"}`}, {AdmissionMetadataKey: `{"operation_id":"op","routes":[{"target":{"host":"127.0.0.1","host":"::1"}}]}`}, {AdmissionMetadataKey: strings.Repeat("x", maxAdmissionMetadata+1)}, {AdmissionMetadataKey: `{}`, "other": "value"}, {}} {
		if _, err := resolver.ResolveLogin(context.Background(), LoginContent{Metas: metas}); err == nil {
			t.Fatalf("metadata accepted: %v", metas)
		}
	}
}

func TestMetadataResolverDiagnosticsAreTypedAndSecretFree(t *testing.T) {
	secret := "credential-secret-that-must-not-appear"
	tests := []struct {
		name   string
		metas  map[string]string
		reason MetadataRejectReason
		count  int
		bytes  int
	}{
		{name: "missing", metas: map[string]string{}, reason: MetadataRejectCount, count: 0},
		{name: "additional metadata", metas: map[string]string{AdmissionMetadataKey: `{}`, "other": secret}, reason: MetadataRejectCount, count: 2, bytes: 0},
		{name: "missing admission key", metas: map[string]string{"other": secret}, reason: MetadataRejectMissing, count: 1, bytes: 0},
		{name: "empty admission", metas: map[string]string{AdmissionMetadataKey: ""}, reason: MetadataRejectSize, count: 1, bytes: 0},
		{name: "oversized admission", metas: map[string]string{AdmissionMetadataKey: strings.Repeat("x", maxAdmissionMetadata+1)}, reason: MetadataRejectSize, count: 1, bytes: maxAdmissionMetadata + 1},
		{name: "malformed admission", metas: map[string]string{AdmissionMetadataKey: "{" + secret}, reason: MetadataRejectDecode, count: 1, bytes: len("{" + secret)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (MetadataResolver{}).ResolveLogin(context.Background(), LoginContent{Metas: test.metas})
			if err == nil {
				t.Fatal("metadata was accepted")
			}
			if !errors.Is(err, route.ErrInvalid) {
				t.Fatalf("error=%v does not retain route classification", err)
			}
			var metadataErr *MetadataError
			if !errors.As(err, &metadataErr) {
				t.Fatalf("error=%T does not retain metadata diagnostics", err)
			}
			if metadataErr.Diagnostic.Reason != test.reason || metadataErr.Diagnostic.MetadataCount != test.count || metadataErr.Diagnostic.AdmissionBytes != test.bytes {
				t.Fatalf("diagnostic=%+v", metadataErr.Diagnostic)
			}
			if !metadataErr.Diagnostic.AdmissionPresent && test.name == "malformed admission" {
				t.Fatal("diagnostic lost admission presence")
			}
			safe := metadataErr.SafeReason()
			if strings.Contains(safe, secret) || strings.Contains(safe, "other") {
				t.Fatalf("safe reason leaked metadata: %q", safe)
			}
		})
	}
}
