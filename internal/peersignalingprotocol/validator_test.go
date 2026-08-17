package peersignalingprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
	"github.com/pion/ice/v4"
)

func TestValidatorAcceptsExactCredentialCandidateEndSequence(t *testing.T) {
	binding := peersignaling.Binding{IntentID: "intent_1", AttemptGeneration: 2, NetworkGeneration: 4, Role: peersignaling.RoleControlling}
	validator, err := (Factory{}).NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp4", Address: "192.0.2.10", Port: 4567, Component: ice.ComponentRTP})
	if err != nil {
		t.Fatal(err)
	}
	messages := []message{
		baseMessage(binding, 1, "credentials", func(value *message) { value.Ufrag, value.Password = "ufragA1", "pppppppppppppppppppppp" }),
		baseMessage(binding, 2, "candidate", func(value *message) { value.Candidate = candidate.Marshal() }),
		baseMessage(binding, 3, "candidate", func(value *message) { value.Candidate = candidate.Marshal() }),
		baseMessage(binding, 4, "end", nil),
		baseMessage(binding, 5, "ready", nil),
		baseMessage(binding, 6, "close", func(value *message) { value.Reason = "completed" }),
	}
	for _, current := range messages {
		applied, err := validator.Accept(encode(t, current))
		if err != nil || applied != (current.Sequence != 3) {
			t.Fatalf("kind=%s sequence=%d applied=%t error=%v", current.Kind, current.Sequence, applied, err)
		}
	}
	if _, err := validator.Accept(encode(t, messages[len(messages)-1])); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close error=%v", err)
	}
}

func TestValidatorRejectsStaleSequenceFieldsAndCandidatePolicy(t *testing.T) {
	binding := peersignaling.Binding{IntentID: "intent_1", AttemptGeneration: 2, NetworkGeneration: 4, Role: peersignaling.RoleControlled}
	credential := baseMessage(binding, 1, "credentials", func(value *message) { value.Ufrag, value.Password = "ufragB1", "qqqqqqqqqqqqqqqqqqqqqq" })
	for name, raw := range map[string][]byte{
		"unknown field": append(encode(t, credential)[:len(encode(t, credential))-1], []byte(`,"extra":true}`)...),
		"trailing":      append(encode(t, credential), []byte(`{}`)...),
		"duplicate":     []byte(strings.Replace(string(encode(t, credential)), `"sequence":1`, `"sequence":1,"sequence":1`, 1)),
		"whitespace":    append([]byte(" "), encode(t, credential)...),
		"wrong role":    encode(t, func() message { value := credential; value.Role = peersignaling.RoleControlling; return value }()),
		"stale network": encode(t, func() message { value := credential; value.NetworkGeneration++; return value }()),
	} {
		validator, _ := (Factory{}).NewValidator(binding)
		_, err := validator.Accept(raw)
		if name == "stale network" {
			if !errors.Is(err, ErrStale) {
				t.Fatalf("%s error=%v", name, err)
			}
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	validator, _ := (Factory{}).NewValidator(binding)
	if _, err := validator.Accept(encode(t, credential)); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"1 1 tcp 1 192.0.2.1 9 typ host tcptype active",
		"1 1 udp 1 host.local 9999 typ host",
		"1 1 udp 1 192.0.2.1 9999 typ relay raddr 198.51.100.1 rport 9998",
	} {
		current := baseMessage(binding, 2, "candidate", func(value *message) { value.Candidate = candidate })
		if _, err := validator.Accept(encode(t, current)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("candidate=%q error=%v", candidate, err)
		}
	}
	if _, err := validator.Accept(encode(t, baseMessage(binding, 3, "end", nil))); !errors.Is(err, ErrSequence) {
		t.Fatalf("rejected messages committed sequence: %v", err)
	}
}

func TestValidatorBoundsDistinctCandidates(t *testing.T) {
	binding := peersignaling.Binding{IntentID: "intent_1", AttemptGeneration: 1, NetworkGeneration: 1, Role: peersignaling.RoleControlling}
	validator, _ := (Factory{}).NewValidator(binding)
	credential := baseMessage(binding, 1, "credentials", func(value *message) { value.Ufrag, value.Password = "ufragA1", "pppppppppppppppppppppp" })
	if _, err := validator.Accept(encode(t, credential)); err != nil {
		t.Fatal(err)
	}
	for index := range MaximumCandidates {
		candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp4", Address: fmt.Sprintf("192.0.2.%d", index+1), Port: 4000 + index, Component: ice.ComponentRTP})
		if err != nil {
			t.Fatal(err)
		}
		current := baseMessage(binding, uint64(index+2), "candidate", func(value *message) { value.Candidate = candidate.Marshal() })
		if _, err := validator.Accept(encode(t, current)); err != nil {
			t.Fatalf("candidate %d: %v", index, err)
		}
	}
	overflow, _ := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp4", Address: "198.51.100.1", Port: 5000, Component: ice.ComponentRTP})
	current := baseMessage(binding, MaximumCandidates+2, "candidate", func(value *message) { value.Candidate = overflow.Marshal() })
	if _, err := validator.Accept(encode(t, current)); !errors.Is(err, ErrLimit) {
		t.Fatalf("overflow error=%v", err)
	}
}

func TestValidatorSequenceExhaustionIsPermanent(t *testing.T) {
	binding := peersignaling.Binding{IntentID: "intent_1", AttemptGeneration: 1, NetworkGeneration: 1, Role: peersignaling.RoleControlling}
	interfaceValidator, err := (Factory{}).NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	validator := interfaceValidator.(*validator)
	validator.lastSequence = math.MaxUint64
	validator.credentials = true
	validator.candidates["candidate:1 1 udp 1 192.0.2.1 5000 typ host"] = struct{}{}

	wantCandidateCount := len(validator.candidates)
	for _, raw := range [][]byte{
		[]byte(`{"schema":"paperboat.peer-signaling/v1"}`),
		encode(t, baseMessage(binding, 1, "end", nil)),
	} {
		if _, acceptErr := validator.Accept(raw); !errors.Is(acceptErr, ErrSequence) {
			t.Fatalf("accept error=%v", acceptErr)
		}
		if validator.lastSequence != math.MaxUint64 || !validator.credentials || validator.ended || validator.closed || len(validator.candidates) != wantCandidateCount {
			t.Fatalf("validator mutated after exhaustion: %+v", validator)
		}
	}
}

func baseMessage(binding peersignaling.Binding, sequence uint64, kind string, mutate func(*message)) message {
	value := message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: binding.AttemptGeneration, NetworkGeneration: binding.NetworkGeneration, Role: binding.Role, Sequence: sequence, Kind: kind}
	if mutate != nil {
		mutate(&value)
	}
	return value
}

func encode(t *testing.T, value message) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
