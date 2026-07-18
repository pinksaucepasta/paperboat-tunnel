package contracttest

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCredentialContractVector(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/fixtures/credentials/terminal-operation.ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TestOnly bool `json:"test_only"`
		Key      struct {
			Public string `json:"public_base64url"`
		} `json:"key"`
		Header map[string]string `json:"header"`
		Token  string            `json:"token"`
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(vector.Token, ".")
	if !vector.TestOnly || len(parts) != 3 || vector.Header["alg"] != "EdDSA" {
		t.Fatal("invalid credential vector")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(vector.Key.Public)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("credential signature is invalid")
	}
}

func TestCredentialRejectionCoverage(t *testing.T) {
	f, err := os.Open("../../testdata/contracts/fixtures/credentials/negative.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	required := map[string]bool{"wrong-audience": false, "wrong-environment": false, "wrong-scope": false, "unknown-key": false, "expired": false, "not-yet-valid": false, "replayed": false, "revoked": false}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var vector struct {
			Case    string `json:"case"`
			Valid   bool   `json:"valid"`
			Error   string `json:"error"`
			Mutated bool   `json:"mutated"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if _, ok := required[vector.Case]; !ok || vector.Valid || vector.Error == "" || vector.Mutated {
			t.Fatalf("unsafe credential vector: %#v", vector)
		}
		required[vector.Case] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for name, seen := range required {
		if !seen {
			t.Errorf("missing credential case %q", name)
		}
	}
}
