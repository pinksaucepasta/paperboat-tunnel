package frpconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
)

const FRPCommit = "3d8e03cb1e81d7a4bb1afaec472c5649e0deac43"
const FRPVersion = "v0.70.0"

var pathPattern = regexp.MustCompile(`^/[a-zA-Z0-9/_-]{16,255}$`)

var (
	ErrInvalid  = errors.New("invalid frps configuration")
	ErrExcluded = errors.New("excluded frp feature requested")
)

type Input struct {
	BindAddr          string
	BindPort          int
	QUICBindPort      int
	PrivateProxyAddr  string
	VhostHTTPPort     int
	HookAddr          string
	HookPath          string
	InternalAuthToken string
}

type serverConfig struct {
	BindAddr          string       `json:"bindAddr"`
	BindPort          int          `json:"bindPort"`
	KCPBindPort       int          `json:"kcpBindPort"`
	QUICBindPort      int          `json:"quicBindPort"`
	ProxyBindAddr     string       `json:"proxyBindAddr"`
	VhostHTTPPort     int          `json:"vhostHTTPPort"`
	PreserveProto     bool         `json:"vhostHTTPPreserveXForwardedProto"`
	DisableKeepAlives bool         `json:"vhostHTTPDisableKeepAlives"`
	VhostHTTPSPort    int          `json:"vhostHTTPSPort"`
	TCPMuxHTTPPort    int          `json:"tcpmuxHTTPConnectPort"`
	EnablePrometheus  bool         `json:"enablePrometheus"`
	Auth              authConfig   `json:"auth"`
	Log               logConfig    `json:"log"`
	WebServer         webConfig    `json:"webServer"`
	Transport         transport    `json:"transport"`
	HTTPPlugins       []httpPlugin `json:"httpPlugins"`
	MaxPortsPerClient int64        `json:"maxPortsPerClient"`
	UserConnTimeout   int64        `json:"userConnTimeout"`
}

type authConfig struct {
	Method string `json:"method"`
	Token  string `json:"token"`
}
type logConfig struct {
	To                string `json:"to"`
	Level             string `json:"level"`
	DisablePrintColor bool   `json:"disablePrintColor"`
}
type webConfig struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}
type transport struct {
	TCPMux                  bool  `json:"tcpMux"`
	TCPMuxKeepaliveInterval int64 `json:"tcpMuxKeepaliveInterval"`
}
type httpPlugin struct {
	Name      string   `json:"name"`
	Addr      string   `json:"addr"`
	Path      string   `json:"path"`
	Ops       []string `json:"ops"`
	TLSVerify bool     `json:"tlsVerify"`
}

type ArtifactMetadata struct {
	FRPVersion   string `json:"frp_version"`
	FRPCommit    string `json:"frp_commit"`
	ConfigSHA256 string `json:"config_sha256"`
}

func Generate(input Input) ([]byte, ArtifactMetadata, error) {
	if err := validate(input); err != nil {
		return nil, ArtifactMetadata{}, err
	}
	config := serverConfig{BindAddr: input.BindAddr, BindPort: input.BindPort, QUICBindPort: input.QUICBindPort, ProxyBindAddr: input.PrivateProxyAddr, VhostHTTPPort: input.VhostHTTPPort, PreserveProto: true, DisableKeepAlives: true, Auth: authConfig{Method: "token", Token: input.InternalAuthToken}, Log: logConfig{To: "console", Level: "error", DisablePrintColor: true}, WebServer: webConfig{Addr: "127.0.0.1", Port: 0}, Transport: transport{TCPMux: true, TCPMuxKeepaliveInterval: 30}, HTTPPlugins: []httpPlugin{{Name: "paperboat-edge", Addr: input.HookAddr, Path: input.HookPath, Ops: []string{"Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn", "NewUserConn", "CloseUserConn", "Traffic"}, TLSVerify: true}}, MaxPortsPerClient: 128, UserConnTimeout: 30}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, ArtifactMetadata{}, fmt.Errorf("encode frps config: %w", err)
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	return encoded, ArtifactMetadata{FRPVersion: FRPVersion, FRPCommit: FRPCommit, ConfigSHA256: hex.EncodeToString(digest[:])}, nil
}

func validate(input Input) error {
	if !validPort(input.BindPort) || !validPort(input.QUICBindPort) || !validPort(input.VhostHTTPPort) || input.BindAddr == "" || input.PrivateProxyAddr == "" || input.HookAddr == "" || !pathPattern.MatchString(input.HookPath) || len(input.InternalAuthToken) < 32 {
		return ErrInvalid
	}
	if err := validateBind(input.BindAddr); err != nil {
		return err
	}
	if err := validateLoopback(input.PrivateProxyAddr); err != nil {
		return err
	}
	hookHost, hookPort, err := net.SplitHostPort(input.HookAddr)
	if err != nil || net.ParseIP(hookHost) == nil || !net.ParseIP(hookHost).IsLoopback() || hookPort == "0" || hookPort == "" {
		return ErrInvalid
	}
	return nil
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validateBind(address string) error {
	if net.ParseIP(address) == nil {
		return ErrInvalid
	}
	return nil
}

func validateLoopback(address string) error {
	ip := net.ParseIP(address)
	if ip == nil || !ip.IsLoopback() {
		return ErrInvalid
	}
	return nil
}
