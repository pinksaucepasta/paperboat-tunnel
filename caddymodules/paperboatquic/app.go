package paperboatquic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	TerminalALPN      = "paperboat-terminal/1"
	brokerMaxHostname = 253
	closeDraining     = quic.ApplicationErrorCode(0x5042)
	closeProtocol     = quic.ApplicationErrorCode(0x5043)
)

func init() {
	caddy.RegisterModule(App{})
}

type App struct {
	Listen                  string         `json:"listen"`
	HTTPServer              string         `json:"http_server"`
	BrokerSocket            string         `json:"broker_socket"`
	MaxConnections          int            `json:"max_connections,omitempty"`
	MaxConnectionsPerIP     int            `json:"max_connections_per_ip,omitempty"`
	MaxStreamsPerConnection int            `json:"max_streams_per_connection,omitempty"`
	MaxHTTP3Streams         int            `json:"max_http3_streams_per_connection,omitempty"`
	IdleTimeout             caddy.Duration `json:"idle_timeout,omitempty"`
	HandshakeTimeout        caddy.Duration `json:"handshake_timeout,omitempty"`

	ctx        caddy.Context
	http       *caddyhttp.Server
	tlsConfig  *tls.Config
	packetConn net.PacketConn
	listener   *quic.Listener
	h3server   *http3.Server
	cancel     context.CancelFunc

	mu      sync.Mutex
	closing bool
	byIP    map[string]int
	conns   map[*quic.Conn]string
	wg      sync.WaitGroup
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "paperboat_quic", New: func() caddy.Module { return new(App) }}
}

func (a *App) Provision(ctx caddy.Context) error {
	if a.Listen == "" || a.HTTPServer == "" || a.BrokerSocket == "" {
		return errors.New("listen, http_server, and broker_socket are required")
	}
	if a.MaxConnections == 0 {
		a.MaxConnections = 4096
	}
	if a.MaxConnectionsPerIP == 0 {
		a.MaxConnectionsPerIP = 32
	}
	if a.MaxStreamsPerConnection == 0 {
		a.MaxStreamsPerConnection = 3
	}
	if a.MaxHTTP3Streams == 0 {
		a.MaxHTTP3Streams = 64
	}
	if a.IdleTimeout == 0 {
		a.IdleTimeout = caddy.Duration(2 * time.Minute)
	}
	if a.HandshakeTimeout == 0 {
		a.HandshakeTimeout = caddy.Duration(10 * time.Second)
	}
	if a.MaxConnections < 1 || a.MaxConnectionsPerIP < 1 || a.MaxStreamsPerConnection < 1 || a.MaxHTTP3Streams < a.MaxStreamsPerConnection || a.MaxHTTP3Streams > 1024 || time.Duration(a.IdleTimeout) <= 0 || time.Duration(a.HandshakeTimeout) <= 0 {
		return errors.New("invalid Paperboat QUIC limits")
	}
	httpAppValue, err := ctx.App("http")
	if err != nil {
		return fmt.Errorf("load HTTP app: %w", err)
	}
	httpApp := httpAppValue.(*caddyhttp.App)
	server := httpApp.Servers[a.HTTPServer]
	if server == nil {
		return fmt.Errorf("HTTP server %q is not configured", a.HTTPServer)
	}
	a.ctx = ctx
	a.http = server
	a.tlsConfig = terminalTLSConfig(server.TLSConnPolicies.TLSConfig(ctx))
	a.byIP = make(map[string]int)
	a.conns = make(map[*quic.Conn]string)
	return nil
}

func (a *App) Validate() error {
	address, err := caddy.ParseNetworkAddressWithDefaults(a.Listen, "udp", 443)
	if err != nil || address.PortRangeSize() != 1 || address.Network != "udp" {
		return errors.New("listen must be one UDP address")
	}
	if !strings.HasPrefix(a.BrokerSocket, "/") || len(a.BrokerSocket) > 100 {
		return errors.New("broker_socket must be a short absolute Unix path")
	}
	return nil
}

func (a *App) Start() error {
	address, err := caddy.ParseNetworkAddressWithDefaults(a.Listen, "udp", 443)
	if err != nil {
		return err
	}
	listenerValue, err := address.Listen(a.ctx, 0, net.ListenConfig{})
	if err != nil {
		return err
	}
	packetConn, ok := listenerValue.(net.PacketConn)
	if !ok {
		return errors.New("Caddy listener is not a packet connection")
	}
	a.packetConn = packetConn
	a.listener, err = quic.Listen(packetConn, a.tlsConfig, &quic.Config{
		Allow0RTT:            false,
		HandshakeIdleTimeout: time.Duration(a.HandshakeTimeout),
		MaxIdleTimeout:       time.Duration(a.IdleTimeout),
		MaxIncomingStreams:   int64(a.MaxHTTP3Streams),
		Versions:             []quic.Version{quic.Version1, quic.Version2},
	})
	if err != nil {
		_ = packetConn.Close()
		return err
	}
	a.h3server = &http3.Server{Handler: a.http, TLSConfig: a.tlsConfig, IdleTimeout: time.Duration(a.IdleTimeout)}
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.wg.Add(1)
	go a.acceptLoop(ctx)
	return nil
}

func (a *App) Stop() error {
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return nil
	}
	a.closing = true
	connections := make([]*quic.Conn, 0, len(a.conns))
	for conn := range a.conns {
		connections = append(connections, conn)
	}
	a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
	if a.listener != nil {
		_ = a.listener.Close()
	}
	for _, conn := range connections {
		_ = conn.CloseWithError(closeDraining, "server draining")
	}
	if a.h3server != nil {
		_ = a.h3server.Close()
	}
	a.wg.Wait()
	if a.packetConn != nil {
		return a.packetConn.Close()
	}
	return nil
}

func (a *App) acceptLoop(ctx context.Context) {
	defer a.wg.Done()
	for {
		conn, err := a.listener.Accept(ctx)
		if err != nil {
			return
		}
		ip, ok := remoteIP(conn.RemoteAddr())
		if !ok {
			_ = conn.CloseWithError(closeProtocol, "invalid source address")
			continue
		}
		if !a.reserve(conn, ip) {
			_ = conn.CloseWithError(closeDraining, "connection limit")
			continue
		}
		a.wg.Add(1)
		go a.handleConnection(conn, ip)
	}
}

func (a *App) reserve(conn *quic.Conn, ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || len(a.conns) >= a.MaxConnections || a.byIP[ip] >= a.MaxConnectionsPerIP {
		return false
	}
	a.conns[conn] = ip
	a.byIP[ip]++
	return true
}

func (a *App) handleConnection(conn *quic.Conn, ip string) {
	defer func() {
		a.mu.Lock()
		delete(a.conns, conn)
		a.byIP[ip]--
		if a.byIP[ip] == 0 {
			delete(a.byIP, ip)
		}
		a.mu.Unlock()
		a.wg.Done()
	}()
	state := conn.ConnectionState().TLS
	switch state.NegotiatedProtocol {
	case http3.NextProtoH3:
		_ = a.h3server.ServeQUICConn(conn)
	case TerminalALPN:
		if state.ServerName == "" || !validHostname(state.ServerName) {
			_ = conn.CloseWithError(closeProtocol, "invalid server name")
			return
		}
		a.serveTerminal(conn, state.ServerName)
	default:
		_ = conn.CloseWithError(closeProtocol, "unsupported protocol")
	}
}

func (a *App) serveTerminal(conn *quic.Conn, hostname string) {
	var streams int
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		streams++
		if streams > a.MaxStreamsPerConnection {
			stream.CancelRead(quic.StreamErrorCode(closeProtocol))
			stream.CancelWrite(quic.StreamErrorCode(closeProtocol))
			continue
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.forwardStream(stream, hostname)
		}()
	}
}

func (a *App) forwardStream(stream *quic.Stream, hostname string) {
	broker, err := net.DialTimeout("unix", a.BrokerSocket, 2*time.Second)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(closeProtocol))
		stream.CancelWrite(quic.StreamErrorCode(closeProtocol))
		return
	}
	defer broker.Close()
	deadline := time.Now().Add(time.Duration(a.HandshakeTimeout))
	if err := broker.SetDeadline(deadline); err != nil {
		return
	}
	if err := binary.Write(broker, binary.BigEndian, uint16(len(hostname))); err != nil {
		return
	}
	if _, err := io.WriteString(broker, hostname); err != nil {
		return
	}
	var status [1]byte
	if _, err := io.ReadFull(broker, status[:]); err != nil || status[0] != 0 {
		stream.CancelRead(quic.StreamErrorCode(closeProtocol))
		stream.CancelWrite(quic.StreamErrorCode(closeProtocol))
		return
	}
	if err := broker.SetDeadline(time.Time{}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(broker, stream)
		if conn, ok := broker.(*net.UnixConn); ok {
			_ = conn.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, broker)
		_ = stream.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func terminalTLSConfig(base *tls.Config) *tls.Config {
	config := base.Clone()
	config.NextProtos = appendALPN(config.NextProtos, http3.NextProtoH3, TerminalALPN)
	if getConfig := config.GetConfigForClient; getConfig != nil {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := getConfig(hello)
			if selected == nil || err != nil {
				return selected, err
			}
			selected = selected.Clone()
			selected.NextProtos = appendALPN(selected.NextProtos, http3.NextProtoH3, TerminalALPN)
			return selected, nil
		}
	}
	return config
}

func appendALPN(current []string, protocols ...string) []string {
	result := append([]string(nil), current...)
	for _, protocol := range protocols {
		found := false
		for _, existing := range result {
			if existing == protocol {
				found = true
				break
			}
		}
		if !found {
			result = append(result, protocol)
		}
	}
	return result
}

func remoteIP(address net.Addr) (string, bool) {
	if address == nil {
		return "", false
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "", false
	}
	return ip.String(), true
}

func validHostname(hostname string) bool {
	if hostname == "" || len(hostname) > brokerMaxHostname || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
	_ http.Handler      = (*caddyhttp.Server)(nil)
)
