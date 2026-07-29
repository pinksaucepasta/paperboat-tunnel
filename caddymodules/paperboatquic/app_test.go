package paperboatquic

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestTerminalTLSConfigPreservesDynamicCertificatesAndALPN(t *testing.T) {
	dynamic := &tls.Config{NextProtos: []string{"h2"}}
	base := &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return dynamic, nil
		},
	}
	configured := terminalTLSConfig(base)
	assertALPN(t, configured.NextProtos, "http/1.1", "h3", TerminalALPN)
	selected, err := configured.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	assertALPN(t, selected.NextProtos, "h2", "h3", TerminalALPN)
	if len(dynamic.NextProtos) != 1 || dynamic.NextProtos[0] != "h2" {
		t.Fatalf("dynamic TLS config was mutated: %v", dynamic.NextProtos)
	}
}

func TestValidHostname(t *testing.T) {
	for _, hostname := range []string{"helper.example.test", "a-b.example", "127.0.0.1"} {
		if !validHostname(hostname) {
			t.Fatalf("valid hostname rejected: %q", hostname)
		}
	}
	for _, hostname := range []string{"", ".example", "example.", "-bad.example", "bad_.example", "bad/host"} {
		if validHostname(hostname) {
			t.Fatalf("invalid hostname accepted: %q", hostname)
		}
	}
}

func TestRemoteIP(t *testing.T) {
	if got, ok := remoteIP(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}); !ok || got != "2001:db8::1" {
		t.Fatalf("remote IP = %q, ok=%v", got, ok)
	}
	for _, address := range []net.Addr{nil, invalidAddress("missing-port"), &net.UDPAddr{IP: net.IPv4zero, Port: 443}, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 443}} {
		if got, ok := remoteIP(address); ok {
			t.Fatalf("invalid remote address accepted: %v as %q", address, got)
		}
	}
}

type invalidAddress string

func (a invalidAddress) Network() string { return "invalid" }
func (a invalidAddress) String() string  { return string(a) }

func assertALPN(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, protocol := range want {
		count := 0
		for _, candidate := range got {
			if candidate == protocol {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("ALPN %q count=%d in %v", protocol, count, got)
		}
	}
}
