package admission

import (
	"context"
	"testing"
	"time"
)

func TestValidateRoutesRejectsAmbiguousProxyAndHostBindings(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	service := admissionService(t, now, validClaims(now))
	request := validRequest()
	request.Routes = append(request.Routes, Route{
		RouteID: "rte_helper_02", Revision: 1, Kind: "runtime_https_wss",
		PublicHost: "other.example.test", ProxyName: request.Routes[0].ProxyName,
		TargetHost: "127.0.0.1", TargetPort: 8081,
	})
	if _, err := service.Admit(context.Background(), request); err == nil {
		t.Fatal("duplicate connector proxy identity was accepted")
	}
	if service.Journal.Len() != 0 {
		t.Fatal("invalid proxy binding mutated journal")
	}
}

func TestValidateRoutesRejectsUnsafePublicHosts(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1", "example_test", "example.test/route", "example.test?query",
		"example.test#fragment", "example.test\r\nX-Injected: yes", " example.test",
		"example..test", "-example.test", "example-.test", "*.example.test",
	} {
		t.Run(host, func(t *testing.T) {
			routes := []Route{{RouteID: "route_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: host, ProxyName: "proxy_1", TargetHost: "127.0.0.1", TargetPort: 8080}}
			if err := validateRoutes(routes); err == nil {
				t.Fatalf("unsafe public host %q was accepted", host)
			}
		})
	}
}

func TestValidateRoutesCanonicalizesCaseAndIDNAForDuplicateDetection(t *testing.T) {
	routes := []Route{
		{RouteID: "route_1", Revision: 1, Kind: "runtime_https_wss", PublicHost: "BÜCHER.example.test", ProxyName: "proxy_1", TargetHost: "127.0.0.1", TargetPort: 8080},
		{RouteID: "route_2", Revision: 1, Kind: "runtime_https_wss", PublicHost: "xn--bcher-kva.example.test.", ProxyName: "proxy_2", TargetHost: "127.0.0.1", TargetPort: 8081},
	}
	if err := validateRoutes(routes); err == nil {
		t.Fatal("IDNA-equivalent public hosts were accepted as distinct routes")
	}
}
