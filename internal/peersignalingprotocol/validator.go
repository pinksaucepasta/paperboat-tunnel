// Package peersignalingprotocol validates the endpoint signaling wire contract
// before messages enter the tunnel's bounded forwarding service.
package peersignalingprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"strings"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
	"github.com/pion/ice/v4"
)

const (
	Schema            = "paperboat.peer-signaling/v1"
	MaximumMessage    = 16 << 10
	MaximumCandidate  = 2048
	MaximumCandidates = 64
)

var (
	ErrInvalid  = errors.New("invalid peer signaling message")
	ErrStale    = errors.New("stale peer signaling generation")
	ErrSequence = errors.New("peer signaling sequence is invalid")
	ErrLimit    = errors.New("peer signaling limit exceeded")
	ErrClosed   = errors.New("peer signaling session is closed")
)

type Factory struct{}

func (Factory) NewValidator(binding peersignaling.Binding) (peersignaling.Validator, error) {
	if !validBinding(binding) {
		return nil, ErrInvalid
	}
	return &validator{binding: binding, candidates: make(map[string]struct{})}, nil
}

type message struct {
	Schema            string             `json:"schema"`
	IntentID          string             `json:"intent_id"`
	AttemptGeneration uint64             `json:"attempt_generation"`
	NetworkGeneration uint64             `json:"network_generation"`
	Role              peersignaling.Role `json:"role"`
	Sequence          uint64             `json:"sequence"`
	Kind              string             `json:"kind"`
	Ufrag             string             `json:"ufrag,omitempty"`
	Password          string             `json:"password,omitempty"`
	Candidate         string             `json:"candidate,omitempty"`
	Reason            string             `json:"reason,omitempty"`
}

type validator struct {
	binding      peersignaling.Binding
	lastSequence uint64
	candidates   map[string]struct{}
	credentials  bool
	ended        bool
	ready        bool
	closed       bool
}

func (v *validator) Accept(raw []byte) (bool, error) {
	if v == nil {
		return false, ErrInvalid
	}
	if v.closed {
		return false, ErrClosed
	}
	if v.lastSequence == math.MaxUint64 {
		return false, ErrSequence
	}
	current, err := decode(raw, v.binding)
	if err != nil {
		return false, err
	}
	if current.Sequence != v.lastSequence+1 {
		return false, ErrSequence
	}
	switch current.Kind {
	case "credentials":
		if v.credentials || v.ended {
			return false, ErrSequence
		}
	case "candidate":
		if !v.credentials || v.ended {
			return false, ErrSequence
		}
		if _, duplicate := v.candidates[current.Candidate]; !duplicate && len(v.candidates) >= MaximumCandidates {
			return false, ErrLimit
		}
	case "end":
		if !v.credentials || v.ended {
			return false, ErrSequence
		}
	case "ready":
		if !v.credentials || v.ready {
			return false, ErrSequence
		}
	}
	v.lastSequence = current.Sequence
	switch current.Kind {
	case "credentials":
		v.credentials = true
	case "candidate":
		if _, duplicate := v.candidates[current.Candidate]; duplicate {
			return false, nil
		}
		v.candidates[current.Candidate] = struct{}{}
	case "end":
		v.ended = true
	case "ready":
		v.ready = true
	case "close":
		v.closed = true
	}
	return true, nil
}

func decode(raw []byte, binding peersignaling.Binding) (message, error) {
	if len(raw) == 0 || len(raw) > MaximumMessage {
		return message{}, ErrLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var current message
	if decoder.Decode(&current) != nil {
		return message{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return message{}, ErrInvalid
	}
	if current.Schema != Schema || current.IntentID != binding.IntentID || current.Role != binding.Role || current.Sequence == 0 {
		return message{}, ErrInvalid
	}
	if current.AttemptGeneration != binding.AttemptGeneration || current.NetworkGeneration != binding.NetworkGeneration {
		return message{}, ErrStale
	}
	switch current.Kind {
	case "credentials":
		if !validCredential(current.Ufrag, current.Password) || current.Candidate != "" || current.Reason != "" {
			return message{}, ErrInvalid
		}
	case "candidate":
		if current.Ufrag != "" || current.Password != "" || current.Reason != "" || !validCandidate(current.Candidate) {
			return message{}, ErrInvalid
		}
	case "end", "ready":
		if current.Ufrag != "" || current.Password != "" || current.Candidate != "" || current.Reason != "" {
			return message{}, ErrInvalid
		}
	case "close":
		if current.Ufrag != "" || current.Password != "" || current.Candidate != "" || !validReason(current.Reason) {
			return message{}, ErrInvalid
		}
	default:
		return message{}, ErrInvalid
	}
	canonical, err := json.Marshal(current)
	if err != nil || !bytes.Equal(canonical, raw) {
		return message{}, ErrInvalid
	}
	return current, nil
}

func validCandidate(raw string) bool {
	if len(raw) == 0 || len(raw) > MaximumCandidate {
		return false
	}
	candidate, err := ice.UnmarshalCandidate(raw)
	if err != nil || candidate == nil || candidate.NetworkType() != ice.NetworkTypeUDP4 && candidate.NetworkType() != ice.NetworkTypeUDP6 || net.ParseIP(candidate.Address()) == nil {
		return false
	}
	switch candidate.Type() {
	case ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive:
		return true
	default:
		return false
	}
}

func validBinding(value peersignaling.Binding) bool {
	return boundedID(value.IntentID) && value.AttemptGeneration > 0 && value.NetworkGeneration > 0 && (value.Role == peersignaling.RoleControlling || value.Role == peersignaling.RoleControlled)
}

func boundedID(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validCredential(ufrag, password string) bool {
	return len(ufrag) >= 4 && len(ufrag) <= 256 && len(password) >= 22 && len(password) <= 256 && credentialCharacters(ufrag) && credentialCharacters(password)
}

func credentialCharacters(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '+' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func validReason(value string) bool {
	switch value {
	case "completed", "canceled", "network_changed", "expired", "revoked", "protocol_error", "capacity":
		return true
	default:
		return false
	}
}

var _ peersignaling.ValidatorFactory = Factory{}
