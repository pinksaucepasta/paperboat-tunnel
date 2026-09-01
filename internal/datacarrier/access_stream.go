package datacarrier

import (
	"context"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

var (
	// ErrAccessStreamKind is returned before application bytes are exposed when
	// a host attempts to use the client-initiated access seam for a public or
	// unsupported stream kind.
	ErrAccessStreamKind = errors.New("invalid private access stream kind")
	// ErrAccessStreamIdentity is distinct from a route denial so callers can
	// treat a stale/replaced carrier as unavailable without exposing route
	// existence.
	ErrAccessStreamIdentity = errors.New("private access stream identity mismatch")
)

const (
	// AccessStreamHTTPS carries a bounded private HTTP/CONNECT envelope followed
	// by opaque full-duplex bytes.
	AccessStreamHTTPS = connectorprotocol.PrivateAccessHTTP
	// AccessStreamTCP carries a bounded private raw-TCP envelope followed by
	// opaque full-duplex bytes. It never uses the preview HTTP preface.
	AccessStreamTCP = connectorprotocol.PrivateAccessTCP
)

// AcceptAccessStream accepts a host-initiated access request on an already
// authenticated carrier. It authenticates only the immutable connector-v1
// carrier identity and stream kind. Private route authorization is deliberately
// performed by edgehttp's PrivateAccessStreamBridge after its bounded machine
// proof envelope has been decoded, so this method cannot accidentally treat a
// carrier connection as route permission.
//
// The returned stream owns one carrier permit and must be closed by the bridge.
// The acceptance context controls only the accept and preface read; it does not
// cancel the returned stream after a successful handoff.
func (s *Server) AcceptAccessStream(ctx context.Context) (*Stream, StreamOpen, error) {
	if s == nil || ctx == nil {
		return nil, StreamOpen{}, ErrInvalidConfig
	}
	raw, err := s.acceptRaw(ctx)
	if err != nil {
		return nil, StreamOpen{}, err
	}
	deadline := time.Now().Add(s.config.StreamOpenLimit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := raw.SetReadDeadline(deadline); err != nil {
		_ = raw.Close()
		s.releasePermit()
		return nil, StreamOpen{}, ErrInvalidPreface
	}
	open, err := connectorprotocol.ReadStreamOpen(raw)
	_ = raw.SetReadDeadline(time.Time{})
	if err != nil {
		_ = raw.Close()
		s.releasePermit()
		return nil, StreamOpen{}, err
	}
	if !s.config.Identity.matches(open) {
		_ = raw.Close()
		s.releasePermit()
		return nil, StreamOpen{}, ErrAccessStreamIdentity
	}
	if open.Kind != AccessStreamHTTPS && open.Kind != AccessStreamTCP {
		_ = raw.Close()
		s.releasePermit()
		return nil, StreamOpen{}, ErrAccessStreamKind
	}
	return wrapStream(raw, context.Background(), s.releasePermit, open), open, nil
}
