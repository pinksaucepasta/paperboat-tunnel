package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/testedge"
)

const maxSeedBytes = 1 << 20

type seed struct {
	LoseNextUsageAck bool `json:"lose_next_usage_ack"`
	Assignments      []struct {
		Environment string `json:"environment_id"`
		Helper      string `json:"helper_id"`
		Generation  uint64 `json:"connector_generation"`
		EdgePool    string `json:"edge_pool"`
		EdgeNode    string `json:"edge_node_id"`
		Revoked     bool   `json:"revoked"`
	} `json:"assignments"`
	Routes []struct {
		RouteID     string `json:"route_id"`
		Revision    uint64 `json:"route_revision"`
		Environment string `json:"environment_id"`
		Generation  uint64 `json:"connector_generation"`
		NodeID      string `json:"edge_node_id"`
		Kind        string `json:"kind"`
		PublicHost  string `json:"public_host"`
		Target      struct {
			Host string `json:"host"`
			Port uint16 `json:"port"`
		} `json:"target"`
	} `json:"routes"`
	UsageKeys []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	} `json:"usage_keys"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("paperboat-fake-control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var address, credentialPath, seedPath, tlsCertPath, tlsKeyPath string
	flags.StringVar(&address, "listen", "127.0.0.1:18081", "private loopback listener")
	flags.StringVar(&credentialPath, "credential-file", "", "owner-only bearer credential file")
	flags.StringVar(&seedPath, "seed-file", "", "strict fake-control seed JSON")
	flags.StringVar(&tlsCertPath, "tls-cert-file", "", "TLS certificate chain")
	flags.StringVar(&tlsKeyPath, "tls-key-file", "", "owner-only TLS private key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid fake-control arguments")
	}
	if err := validateLoopback(address); err != nil {
		return err
	}
	if (tlsCertPath == "") != (tlsKeyPath == "") {
		return errors.New("TLS certificate and key must be configured together")
	}
	credential, err := readPrivateCredential(credentialPath)
	if err != nil {
		return err
	}
	configuration, err := readSeed(seedPath)
	if err != nil {
		return err
	}
	fake := testedge.New()
	if configuration.LoseNextUsageAck {
		fake.LoseNextAcknowledgment()
	}
	for _, item := range configuration.Assignments {
		if item.Environment == "" || item.Helper == "" || item.Generation == 0 || item.EdgePool == "" || item.EdgeNode == "" {
			return errors.New("invalid assignment seed")
		}
		fake.SetAssignment(item.Environment, item.Helper, admission.Current{Generation: item.Generation, EdgePool: item.EdgePool, EdgeNode: item.EdgeNode, Revoked: item.Revoked})
	}
	for _, item := range configuration.Routes {
		if err := fake.SetRoute(control.RouteAssignment{RouteID: item.RouteID, Revision: item.Revision, Environment: item.Environment, Generation: item.Generation, NodeID: item.NodeID, Kind: item.Kind, PublicHost: item.PublicHost, TargetHost: item.Target.Host, TargetPort: item.Target.Port}); err != nil {
			return err
		}
	}
	for _, item := range configuration.UsageKeys {
		public, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil || item.KeyID == "" || len(public) != ed25519.PublicKeySize {
			return errors.New("invalid usage key seed")
		}
		fake.SetUsageKey(item.KeyID, ed25519.PublicKey(public))
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", testedge.Handler{Fake: fake, Credential: credential})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	root, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if tlsCertPath != "" {
			done <- server.ListenAndServeTLS(tlsCertPath, tlsKeyPath)
			return
		}
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-root.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func validateLoopback(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" || port == "0" {
		return errors.New("fake-control listener must use a fixed loopback address")
	}
	return nil
}

func readPrivateCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return "", errors.New("invalid credential file")
	}
	data, err := os.ReadFile(path)
	credential := strings.TrimSpace(string(data))
	if err != nil || len(credential) < 32 || len(credential) > 8192 {
		return "", errors.New("invalid credential file")
	}
	return credential, nil
}

func readSeed(path string) (seed, error) {
	file, err := os.Open(path)
	if err != nil {
		return seed{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSeedBytes+1))
	if err != nil || len(data) > maxSeedBytes {
		return seed{}, errors.New("invalid seed file")
	}
	var value seed
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return seed{}, errors.New("invalid seed file")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return seed{}, errors.New("invalid seed file")
	}
	return value, nil
}
