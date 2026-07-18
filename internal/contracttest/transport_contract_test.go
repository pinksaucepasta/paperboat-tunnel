package contracttest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestHelperTransportPassThroughVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/fixtures/helper/transport.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Case       string   `json:"case"`
			Valid      bool     `json:"valid"`
			WireChunks []string `json:"wire_chunks_base64"`
			Error      string   `json:"error"`
			CloseCode  int      `json:"close_code"`
			Count      int      `json:"expected_count"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Cases {
		if !vector.Valid && (vector.Error == "" || vector.CloseCode == 0) {
			t.Errorf("%s: rejection lacks error/close code", vector.Case)
		}
		if vector.Case == "structured-fragmented" || vector.Case == "structured-coalesced" {
			wire, err := concatenate(vector.WireChunks)
			if err != nil {
				t.Fatal(err)
			}
			count, err := countFrames(wire)
			want := 1
			if vector.Count > 0 {
				want = vector.Count
			}
			if err != nil || count != want {
				t.Fatalf("%s: frames=%d, want %d, err=%v", vector.Case, count, want, err)
			}
		}
	}
}

func concatenate(chunks []string) ([]byte, error) {
	var wire []byte
	for _, chunk := range chunks {
		decoded, err := base64.StdEncoding.DecodeString(chunk)
		if err != nil {
			return nil, err
		}
		wire = append(wire, decoded...)
	}
	return wire, nil
}

func countFrames(wire []byte) (int, error) {
	count := 0
	for len(wire) > 0 {
		if len(wire) < 4 {
			return count, fmt.Errorf("truncated frame length")
		}
		length := int(binary.BigEndian.Uint32(wire[:4]))
		wire = wire[4:]
		if length > 65536 || len(wire) < length {
			return count, fmt.Errorf("invalid frame length")
		}
		wire = wire[length:]
		count++
	}
	return count, nil
}
