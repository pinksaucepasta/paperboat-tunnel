package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

var errInvalid = errors.New("invalid control conformance configuration")

type config struct {
	ControlURL          string `json:"control_url"`
	ControlCredential   string `json:"control_credential"`
	ControlCAFile       string `json:"control_ca_file"`
	NodeID              string `json:"edge_node_id"`
	EdgePool            string `json:"edge_pool"`
	ProcessEpoch        string `json:"process_epoch"`
	EnvironmentID       string `json:"environment_id"`
	HelperID            string `json:"helper_id"`
	ConnectorGeneration uint64 `json:"connector_generation"`
	RouteID             string `json:"route_id"`
	RouteRevision       uint64 `json:"route_revision"`
	UsageKeyID          string `json:"usage_key_id"`
	UsageSeed           string `json:"usage_seed_base64url"`
	CounterEpoch        string `json:"counter_epoch"`
	UsageOperationID    string `json:"usage_operation_id"`
	RevokedKeyID        string `json:"expected_revoked_key_id,omitempty"`
	Now                 string `json:"now"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: paperboat-control-conformance <absolute-private-config-path>")
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "paperboat-control-conformance: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path string, output io.Writer) error {
	value, err := loadConfig(path)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(value.ControlCAFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errInvalid
	}
	client, err := control.NewHTTPClient(control.HTTPConfig{BaseURL: value.ControlURL, Credential: value.ControlCredential, Timeout: 5 * time.Second, TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}})
	if err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339Nano, value.Now)
	if err != nil {
		return errInvalid
	}
	registration := control.NodeRegistration{NodeID: value.NodeID, EdgePool: value.EdgePool, Artifact: "paperboat-control-conformance", Protocol: "1.0", ProcessEpoch: value.ProcessEpoch, Capacity: 8, Endpoint: control.ConnectorEndpoint{Host: "edge.example.test", TCPPort: 17000, QUICPort: 17001}}
	if err := client.RegisterNode(ctx, registration); err != nil {
		return fmt.Errorf("register node: %w", err)
	}
	if err := client.Heartbeat(ctx, control.NodeObservation{NodeID: value.NodeID, ProcessEpoch: value.ProcessEpoch, Ready: true, At: now}); err != nil {
		return fmt.Errorf("heartbeat node: %w", err)
	}
	current, err := client.Current(ctx, value.EnvironmentID, value.HelperID)
	if err != nil || current.Generation != value.ConnectorGeneration || current.EdgePool != value.EdgePool || current.EdgeNode != value.NodeID || current.Revoked {
		return fmt.Errorf("assignment mismatch: %w", errors.Join(errInvalid, err))
	}
	routes, err := client.DesiredRoutes(ctx, value.NodeID)
	if err != nil || len(routes) != 1 || routes[0].RouteID != value.RouteID || routes[0].Revision != value.RouteRevision || routes[0].Environment != value.EnvironmentID || routes[0].Generation != value.ConnectorGeneration || routes[0].NodeID != value.NodeID {
		return fmt.Errorf("route mismatch: %w", errors.Join(errInvalid, err))
	}
	if err := client.ObserveRoutes(ctx, value.NodeID, []control.RouteObservation{{RouteID: value.RouteID, RouteRevision: value.RouteRevision, EdgeNodeID: value.NodeID, ConnectorGeneration: value.ConnectorGeneration}}); err != nil {
		return fmt.Errorf("observe route: %w", err)
	}
	revocations, err := client.Revocations(ctx)
	var revocationDocument struct {
		JTIs         []string `json:"jtis"`
		Environments []string `json:"environments"`
		Helpers      []struct {
			HelperID   string `json:"helper_id"`
			Generation uint64 `json:"connector_generation"`
		} `json:"helper_generations"`
		KeyIDs []string `json:"key_ids"`
	}
	if err != nil || strictJSON(revocations, &revocationDocument) != nil || !contains(revocationDocument.KeyIDs, value.RevokedKeyID) {
		return fmt.Errorf("fetch revocations: %w", errors.Join(errInvalid, err))
	}
	seed, err := base64.RawURLEncoding.DecodeString(value.UsageSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return errInvalid
	}
	key := usage.Key{Node: value.NodeID, Epoch: value.CounterEpoch, Environment: value.EnvironmentID, Route: value.RouteID, Revision: value.RouteRevision, Direction: "egress"}
	signed, err := usage.NewSignedReport(value.UsageKeyID, ed25519.NewKeyFromSeed(seed), usage.SignedDocument{OperationID: value.UsageOperationID, Key: key, Bytes: 4096, Start: now.Add(-time.Minute), End: now})
	if err != nil {
		return err
	}
	receipt, err := client.ReportUsage(ctx, control.UsageReport{OperationID: signed.OperationID, Key: signed.Key, Bytes: signed.Bytes, Interval: signed.Interval, Payload: signed.Payload})
	if err != nil || receipt.Delta != 4096 {
		return fmt.Errorf("report usage: %w", errors.Join(errInvalid, err))
	}
	return json.NewEncoder(output).Encode(map[string]any{"status": "passed", "edge_node_id": value.NodeID, "route_id": value.RouteID, "usage_delta": receipt.Delta})
}

func loadConfig(path string) (config, error) {
	if !filepath.IsAbs(path) {
		return config{}, errInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return config{}, errInvalid
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var value config
	if strictJSON(body, &value) != nil || value.ControlURL == "" || len(value.ControlCredential) < 32 || !filepath.IsAbs(value.ControlCAFile) || value.NodeID == "" || value.EdgePool == "" || value.ProcessEpoch == "" || value.EnvironmentID == "" || value.HelperID == "" || value.ConnectorGeneration == 0 || value.RouteID == "" || value.RouteRevision == 0 || value.UsageKeyID == "" || value.UsageSeed == "" || value.CounterEpoch == "" || value.UsageOperationID == "" || value.RevokedKeyID == "" || value.Now == "" {
		return config{}, errInvalid
	}
	return value, nil
}

func strictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errInvalid
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errInvalid
				}
				if _, exists := seen[key]; exists {
					return errInvalid
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errInvalid
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errInvalid
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
