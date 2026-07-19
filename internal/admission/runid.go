package admission

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/edgeerrors"
)

type RunID struct {
	Value      string
	Generation uint64
	ExpiresAt  time.Time
	Revoked    bool
}

func NewRunID(generation uint64, expiresAt time.Time) (RunID, error) {
	if generation == 0 || !expiresAt.After(time.Now()) {
		return RunID{}, edgeerrors.New(edgeerrors.CodeRunIDInvalid, "run ID parameters are invalid", "request a fresh admission")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return RunID{}, edgeerrors.Wrap(edgeerrors.CodeRunIDInvalid, "run ID entropy unavailable", "retry admission", err)
	}
	return RunID{Value: base64.RawURLEncoding.EncodeToString(raw[:]), Generation: generation, ExpiresAt: expiresAt}, nil
}

func (r RunID) Resume(value string, generation uint64, now time.Time) error {
	if r.Value == "" || generation == 0 || r.Generation == 0 {
		return edgeerrors.New(edgeerrors.CodeRunIDInvalid, "run ID is invalid", "request a fresh admission")
	}
	if r.Revoked {
		return edgeerrors.New(edgeerrors.CodeRunIDRevoked, "run ID is revoked", "request a fresh admission")
	}
	if !r.ExpiresAt.After(now) {
		return edgeerrors.New(edgeerrors.CodeRunIDExpired, "run ID is expired", "request a fresh admission")
	}
	if generation != r.Generation || value != r.Value {
		return edgeerrors.New(edgeerrors.CodeRunIDMismatch, "run ID does not match the admitted generation", "request a fresh admission")
	}
	return nil
}
