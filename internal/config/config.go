package config

import (
	"flag"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

const (
	defaultHealthAddress = "127.0.0.1:9090"
	maxShutdownTimeout   = 5 * time.Minute
)

var identityPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)

type Config struct {
	NodeID          string
	EdgePool        string
	HealthAddress   string
	StatePath       string
	DeploymentPath  string
	ShutdownTimeout time.Duration
}

func Parse(args []string) (Config, error) {
	fs := flag.NewFlagSet("paperboat-tunnel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg Config
	fs.StringVar(&cfg.NodeID, "node-id", "", "stable edge node identity")
	fs.StringVar(&cfg.EdgePool, "edge-pool", "default", "assigned edge pool")
	fs.StringVar(&cfg.HealthAddress, "health-address", defaultHealthAddress, "private health listener")
	fs.StringVar(&cfg.StatePath, "state-path", "state/edge-state.json", "private durable edge state path")
	fs.StringVar(&cfg.DeploymentPath, "deployment-config", "", "strict deployment JSON path")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", 30*time.Second, "bounded shutdown duration")
	if err := fs.Parse(args); err != nil {
		return Config{}, invalid("arguments", err)
	}
	if fs.NArg() != 0 {
		return Config{}, invalid("arguments", fmt.Errorf("unexpected positional arguments"))
	}
	if !identityPattern.MatchString(cfg.NodeID) {
		return Config{}, invalid("node-id", fmt.Errorf("must match %s", identityPattern))
	}
	if !identityPattern.MatchString(cfg.EdgePool) {
		return Config{}, invalid("edge-pool", fmt.Errorf("must match %s", identityPattern))
	}
	if err := validatePrivateAddress(cfg.HealthAddress); err != nil {
		return Config{}, invalid("health-address", err)
	}
	if cfg.StatePath == "" || len(cfg.StatePath) > 4096 || strings.ContainsRune(cfg.StatePath, 0) {
		return Config{}, invalid("state-path", fmt.Errorf("must be a bounded non-empty path"))
	}
	if cfg.DeploymentPath != "" && (len(cfg.DeploymentPath) > 4096 || strings.ContainsRune(cfg.DeploymentPath, 0)) {
		return Config{}, invalid("deployment-config", fmt.Errorf("must be a bounded path"))
	}
	if cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > maxShutdownTimeout {
		return Config{}, invalid("shutdown-timeout", fmt.Errorf("must be greater than zero and at most %s", maxShutdownTimeout))
	}
	return cfg, nil
}

func validatePrivateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listener address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listener must use an explicit loopback IP")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("listener must use a fixed nonzero port")
	}
	return nil
}

func invalid(field string, cause error) error {
	return edgeerrors.Wrap(edgeerrors.CodeConfigInvalid, "invalid "+field, "correct the static configuration and restart", cause)
}
