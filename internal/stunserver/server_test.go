package stunserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/relaypmtu"
	"github.com/pion/stun/v3"
)

func TestServerAnswersAuthenticatedPMTUProbe(t *testing.T) {
	server, address := startTestServer(t, Config{AuthenticatePMTU: func(token string, _ netip.AddrPort) bool { return token == "pmtu-token" }})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := relaypmtu.BuildRequest("pmtu-token", 1280)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(request, address); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, relaypmtu.MaximumSize)
	n, _, err := client.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(request) || relaypmtu.ParseResponse(response[:n], request) != nil {
		t.Fatal("invalid PMTU response")
	}
}

func TestServerDefaultRateLimitAllowsTwoPMTUMeasurementsBehindOneNAT(t *testing.T) {
	server, address := startTestServer(t, Config{AuthenticatePMTU: func(token string, _ netip.AddrPort) bool { return token == "pmtu-token" }})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, relaypmtu.MaximumSize)
	for index := range 54 {
		request, err := relaypmtu.BuildRequest("pmtu-token", 1200+index%253)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.WriteToUDP(request, address); err != nil {
			t.Fatal(err)
		}
		n, _, err := client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("probe %d: %v", index+1, err)
		}
		if n != len(request) || relaypmtu.ParseResponse(response[:n], request) != nil {
			t.Fatalf("probe %d returned an invalid response", index+1)
		}
	}
	if stats := server.Stats(); stats.Accepted != 54 || stats.Rejected != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestServerSilentlyRejectsUnauthenticatedPMTUProbe(t *testing.T) {
	server, address := startTestServer(t, Config{AuthenticatePMTU: func(string, netip.AddrPort) bool { return false }})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := relaypmtu.BuildRequest("wrong-token", 1280)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(request, address); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFromUDP(make([]byte, relaypmtu.MaximumSize)); err == nil {
		t.Fatal("unauthenticated PMTU probe received a response")
	}
}

func TestServerReturnsOnlyReflectedBindingAddress(t *testing.T) {
	server, address := startTestServer(t, Config{})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(request.Raw, address); err != nil {
		t.Fatal(err)
	}
	response := readResponse(t, client)
	if response.Type != stun.BindingSuccess || response.TransactionID != request.TransactionID {
		t.Fatalf("response type=%v transaction=%x", response.Type, response.TransactionID)
	}
	var reflected stun.XORMappedAddress
	if err := reflected.GetFrom(response); err != nil {
		t.Fatal(err)
	}
	want := client.LocalAddr().(*net.UDPAddr)
	if !reflected.IP.Equal(want.IP) || reflected.Port != want.Port {
		t.Fatalf("reflected=%s want=%s", reflected.String(), want.String())
	}
	stats := server.Stats()
	if !stats.Running || stats.Accepted != 1 || stats.Rejected != 0 || stats.Sources != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestServerRejectsMalformedNonBindingAndRateLimitedTraffic(t *testing.T) {
	server, address := startTestServer(t, Config{Burst: 2, RequestsPerSecond: 0.0001})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP([]byte("not-stun"), address); err != nil {
		t.Fatal(err)
	}
	nonBinding, err := stun.Build(stun.NewType(stun.MethodAllocate, stun.ClassRequest), stun.TransactionID, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(nonBinding.Raw, address); err != nil {
		t.Fatal(err)
	}
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(request.Raw, address); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1200)
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("rate-limited request received a response")
	}
	deadline := time.Now().Add(time.Second)
	for server.Stats().Rejected < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := server.Stats()
	if stats.Accepted != 0 || stats.Rejected != 3 || stats.Sources != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestServerBoundsSourceTrackingAndShutdown(t *testing.T) {
	server, _ := startTestServer(t, Config{MaximumSources: 1})
	shutdownTestServer(t, server)
	shutdownTestServer(t, server)
	if server.Stats().Running {
		t.Fatal("server remained running")
	}
}

func TestServerRejectsInvalidFingerprint(t *testing.T) {
	server, address := startTestServer(t, Config{})
	defer shutdownTestServer(t, server)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request.Raw[len(request.Raw)-1] ^= 0xff
	if _, err := client.WriteToUDP(request.Raw, address); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFromUDP(make([]byte, 1200)); err == nil {
		t.Fatal("invalid fingerprint received a response")
	}
}

func TestServerRejectsNonCanonicalDatagramLength(t *testing.T) {
	server, err := New(Config{Address: "127.0.0.1:3478"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	connection := &capturePacketConn{}
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4567}
	for name, raw := range map[string][]byte{
		"short":     request.Raw[:stunHeaderSize-1],
		"trailing":  append(append([]byte(nil), request.Raw...), 0, 0, 0, 0),
		"unaligned": func() []byte { value := append([]byte(nil), request.Raw...); value[3]++; return value }(),
		"oversized": make([]byte, server.config.MaximumPacket+1),
	} {
		t.Run(name, func(t *testing.T) {
			if server.handle(connection, raw, remote) {
				t.Fatal("non-canonical STUN datagram accepted")
			}
		})
	}
}

func TestServerAppliesGlobalLimitAcrossSources(t *testing.T) {
	server, err := New(Config{Address: "127.0.0.1:3478", GlobalBurst: 1, GlobalRequestsPerSecond: 0.0001})
	if err != nil {
		t.Fatal(err)
	}
	if !server.allow(netip.MustParseAddr("192.0.2.1")) || server.allow(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("global limiter did not span source addresses")
	}
}

func startTestServer(t *testing.T, config Config) (*Server, *net.UDPAddr) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	config.Address = "127.0.0.1:1"
	config.ListenPacket = func(context.Context, string, string) (net.PacketConn, error) { return connection, nil }
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return server, connection.LocalAddr().(*net.UDPAddr)
}

func readResponse(t *testing.T, client *net.UDPConn) *stun.Message {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1200)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message := &stun.Message{Raw: append([]byte(nil), buffer[:n]...)}
	if err := message.Decode(); err != nil {
		t.Fatal(err)
	}
	return message
}

func shutdownTestServer(t *testing.T, server *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
