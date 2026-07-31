package edgefrp

import (
	"context"
	"strings"
	"testing"
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
	for _, metas := range []map[string]string{{AdmissionMetadataKey: `{"unknown":true}`}, {AdmissionMetadataKey: strings.Repeat("x", maxAdmissionMetadata+1)}, {AdmissionMetadataKey: `{}`, "other": "value"}, {}} {
		if _, err := resolver.ResolveLogin(context.Background(), LoginContent{Metas: metas}); err == nil {
			t.Fatalf("metadata accepted: %v", metas)
		}
	}
}
