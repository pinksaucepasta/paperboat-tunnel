package control_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/auth"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

// TestPrivateControlAcceptance exercises the exact bootstrap calls required by
// the edge before it publishes readiness. It is opt-in because the endpoint,
// CA, and credential belong to an isolated deployment acceptance environment.
func TestPrivateControlAcceptance(t *testing.T) {
	if os.Getenv("PAPERBOAT_PRIVATE_CONTROL_ACCEPTANCE") != "1" {
		t.Skip("set PAPERBOAT_PRIVATE_CONTROL_ACCEPTANCE=1 in an isolated edge network")
	}
	baseURL := os.Getenv("PAPERBOAT_PRIVATE_CONTROL_URL")
	nodeID := os.Getenv("PAPERBOAT_PRIVATE_CONTROL_NODE_ID")
	credential, err := os.ReadFile(os.Getenv("PAPERBOAT_PRIVATE_CONTROL_CREDENTIAL_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(os.Getenv("PAPERBOAT_PRIVATE_CONTROL_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("private control CA contains no certificate")
	}
	client, err := control.NewHTTPClient(control.HTTPConfig{
		BaseURL: baseURL, Credential: strings.TrimSpace(string(credential)), Timeout: 5 * time.Second,
		TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	routes, err := client.DesiredRoutes(ctx, nodeID)
	if err != nil {
		t.Fatalf("desired routes: %v", err)
	}
	revocations, err := client.Revocations(ctx)
	if err != nil {
		t.Fatalf("revocations: %v", err)
	}
	snapshot := auth.NewSnapshot()
	if err := snapshot.ReplaceRevocations(revocations); err != nil {
		t.Fatalf("validate revocations: %v", err)
	}
	t.Logf("private control bootstrap passed routes=%d revocation_bytes=%d", len(routes), len(revocations))
}
