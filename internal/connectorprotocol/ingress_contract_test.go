package connectorprotocol

import (
	"bufio"
	"os"
	"testing"
	"time"
)

func TestIngressContractVectors(t *testing.T) {
	f, err := os.Open("../../testdata/contracts/connector-v1/fixtures/ingress.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		var v struct {
			Case     string          `json:"case"`
			Valid    bool            `json:"valid"`
			Now      time.Time       `json:"now"`
			Decision IngressDecision `json:"decision"`
		}
		if err := decodeStrict(s.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if got := v.Decision.Validate(v.Now) == nil; got != v.Valid {
			t.Errorf("%s: valid=%v want %v", v.Case, got, v.Valid)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}
