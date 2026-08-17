package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

type stormProcessConfig struct {
	BaseURL    string `json:"base_url"`
	Credential string `json:"credential"`
	CAPEM      string `json:"ca_pem"`
	Prefix     string `json:"prefix"`
	Nodes      int    `json:"nodes"`
	ReportPath string `json:"report_path"`
}

// TestControlStormParticipant is invoked by paperboat-server's scale harness through
// a repository-built test binary. It keeps the production client module boundary intact.
func TestControlStormParticipant(t *testing.T) {
	encoded := os.Getenv("PAPERBOAT_TUNNEL_CONTROL_STORM")
	if encoded == "" {
		t.Skip("control-storm process mode is not configured")
	}
	var config stormProcessConfig
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		t.Fatal(err)
	}
	if config.Nodes < 1 || config.Nodes > 1000 || config.Prefix == "" || config.ReportPath == "" {
		t.Fatal("invalid control-storm process configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.CAPEM)) {
		t.Fatal("invalid control-storm CA certificate")
	}
	client, err := NewHTTPClient(HTTPConfig{
		BaseURL: config.BaseURL, Credential: config.Credential, Timeout: 45 * time.Second,
		TLS: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	errors := make(chan error, config.Nodes*4)
	durations := make(chan time.Duration, config.Nodes*4)
	for index := 0; index < config.Nodes; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			nodeID := config.Prefix + strconv.Itoa(index)
			registration := NodeRegistration{
				NodeID: nodeID, EdgePool: "default", Artifact: "paperboat-control-storm",
				Protocol: "1.0", ProcessEpoch: "tunnel_client_epoch", Capacity: 128,
				Endpoint:      ConnectorEndpoint{Host: "127.0.0.1", TCPPort: uint16(20000 + index), QUICPort: uint16(30000 + index)},
				SignalingHost: "signal.example.test", STUNEndpoint: UDPEndpoint{Host: "127.0.0.1", Port: 3478},
			}
			started := time.Now()
			err := client.RegisterNode(ctx, registration)
			durations <- time.Since(started)
			if err != nil {
				errors <- fmt.Errorf("register node %d: %w", index, err)
				return
			}
			started = time.Now()
			err = client.Heartbeat(ctx, NodeObservation{NodeID: nodeID, ProcessEpoch: registration.ProcessEpoch, Ready: true, ActiveStreams: uint32(index % 17), At: time.Now().UTC()})
			durations <- time.Since(started)
			if err != nil {
				errors <- fmt.Errorf("heartbeat node %d: %w", index, err)
				return
			}
			started = time.Now()
			routes, err := client.DesiredRoutes(ctx, nodeID)
			durations <- time.Since(started)
			if err != nil {
				errors <- fmt.Errorf("desired routes node %d: %w", index, err)
			} else if len(routes) != 0 {
				errors <- fmt.Errorf("desired routes node %d: got %d, want 0", index, len(routes))
			}
			started = time.Now()
			_, err = client.Revocations(ctx)
			durations <- time.Since(started)
			if err != nil {
				errors <- fmt.Errorf("revocations node %d: %w", index, err)
			}
		}(index)
	}
	wg.Wait()
	close(errors)
	close(durations)
	for err := range errors {
		t.Error(err)
	}
	result := make([]time.Duration, 0, config.Nodes*4)
	for duration := range durations {
		result = append(result, duration)
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ReportPath, encodedResult, 0o600); err != nil {
		t.Fatal(err)
	}
}
