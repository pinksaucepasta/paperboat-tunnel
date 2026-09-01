package datacarrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func TestTRK35StaleSessionAndProcessCloseCannotRemoveReplacement(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	old := testExpectedAdmissionForRegistry(now.Add(time.Hour))
	registry, err := NewExpectedAdmissionRegistry(ExpectedAdmissionRegistryConfig{
		NodeID: old.EdgeNodeID, ProcessEpoch: old.EdgeProcessEpoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Upsert(old, now); err != nil {
		t.Fatal(err)
	}

	// A reconnect can replace both the authenticated carrier session and its
	// process fence while retaining the operation/route key. A delayed close
	// from any old incarnation must be unable to remove the replacement.
	replacement := old
	replacement.OwnerSessionID = "owner_session_2"
	replacement.Identity.SessionID = "session_2"
	replacement.Identity.ProcessGeneration = 2
	replacement.Identity.Generation = 2
	replacement.LeaseGeneration = 2
	replacement.ConfigGeneration = 2
	replacement.RouteRevision = 2
	replacement.AttachmentGeneration = 2
	replacement.ExpiresAt = now.Add(2 * time.Hour)
	if err := registry.Upsert(replacement, now); err != nil {
		t.Fatal(err)
	}

	for name, stale := range map[string]ExpectedAdmission{
		"old session and process": old,
		"old session": func() ExpectedAdmission {
			value := replacement
			value.Identity.SessionID = old.Identity.SessionID
			return value
		}(),
		"old process": func() ExpectedAdmission {
			value := replacement
			value.Identity.ProcessGeneration = old.Identity.ProcessGeneration
			return value
		}(),
		"old generations": func() ExpectedAdmission {
			value := replacement
			value.Identity = old.Identity
			value.LeaseGeneration = old.LeaseGeneration
			value.ConfigGeneration = old.ConfigGeneration
			value.RouteRevision = old.RouteRevision
			value.AttachmentGeneration = old.AttachmentGeneration
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := registry.Remove(stale); !errors.Is(err, ErrAdmissionConflict) {
				t.Fatalf("stale close error = %v, want ErrAdmissionConflict", err)
			}
			got := registry.Snapshot()
			if len(got) != 1 || got[0].Identity != replacement.Identity || got[0].AttachmentGeneration != replacement.AttachmentGeneration {
				t.Fatalf("stale close changed replacement: %+v", got)
			}
		})
	}
	if err := registry.Remove(replacement); err != nil {
		t.Fatalf("replacement close error = %v", err)
	}
	if err := registry.Remove(replacement); err != nil {
		t.Fatalf("idempotent replacement close error = %v", err)
	}
	if got := registry.Snapshot(); len(got) != 0 {
		t.Fatalf("replacement remained after exact close: %+v", got)
	}
}

func TestTRK35ReconnectStormBoundsClientQueueAndCancelsBackpressure(t *testing.T) {
	config := testCarrierConfig(4)
	config.QueueDepth = 2
	config.AcceptBacklog = 4
	transport := newTRK35Session(16)
	clientContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := NewClientWithSession(clientContext, transport, config)
	if err != nil {
		t.Fatal(err)
	}

	links := make([]*trk35MemoryLink, 6)
	for index := range links {
		links[index] = trk35StreamLink(t, testStreamOpen("route-a", "request-trk35-"+string(rune('a'+index))))
		transport.accepts <- links[index]
	}

	waitTRK35(t, func() bool {
		return len(client.accepted) == config.QueueDepth && transport.acceptCalls.Load() >= int32(config.QueueDepth+1)
	})
	if got := len(client.accepted); got > config.QueueDepth {
		t.Fatalf("accepted queue grew past bound: got %d, max %d", got, config.QueueDepth)
	}
	if got := transport.acceptCalls.Load(); got != int32(config.QueueDepth+1) {
		t.Fatalf("accept loop bypassed backpressure: calls=%d, want %d", got, config.QueueDepth+1)
	}

	// A carrier reconnect/teardown must unblock the publisher which is waiting
	// for queue capacity and close that not-yet-delivered stream.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	waitTRK35(t, func() bool { return links[config.QueueDepth].isClosed() })
	if got := len(client.accepted); got > config.QueueDepth {
		t.Fatalf("accepted queue exceeded bound after close: got %d", got)
	}

	// Streams already handed to the bounded queue belong to the consumer. A
	// shutdown test drains those results explicitly, proving that the bounded
	// publisher did not lose ownership or hide an unbounded backlog.
	for index := 0; index < config.QueueDepth; index++ {
		select {
		case result, ok := <-client.accepted:
			if !ok {
				t.Fatalf("accepted queue closed before result %d", index)
			}
			if result.stream == nil {
				t.Fatalf("accepted result %d has no stream: %+v", index, result)
			}
			_ = result.stream.Close()
		case <-time.After(time.Second):
			t.Fatalf("timed out draining accepted result %d", index)
		}
	}
	waitTRK35(t, func() bool {
		return links[0].isClosed() && links[1].isClosed() && links[2].isClosed()
	})
}

func waitTRK35(t *testing.T, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatal("condition did not become true before bounded timeout")
		default:
			runtime.Gosched()
		}
	}
}

type trk35MemoryLink struct {
	reader    *bytes.Reader
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
}

func trk35StreamLink(t *testing.T, open StreamOpen) *trk35MemoryLink {
	t.Helper()
	var wire bytes.Buffer
	if err := connectorprotocol.WriteStreamOpen(&wire, open); err != nil {
		t.Fatalf("encode stream-open: %v", err)
	}
	return &trk35MemoryLink{reader: bytes.NewReader(wire.Bytes()), closed: make(chan struct{})}
}

func (l *trk35MemoryLink) Read(p []byte) (int, error) {
	if l.isClosed() {
		return 0, net.ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reader.Read(p)
}

func (l *trk35MemoryLink) Write(p []byte) (int, error) {
	if l.isClosed() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (l *trk35MemoryLink) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *trk35MemoryLink) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

func (l *trk35MemoryLink) SetDeadline(time.Time) error      { return nil }
func (l *trk35MemoryLink) SetReadDeadline(time.Time) error  { return nil }
func (l *trk35MemoryLink) SetWriteDeadline(time.Time) error { return nil }

var _ StreamLink = (*trk35MemoryLink)(nil)

type trk35Session struct {
	accepts     chan StreamLink
	closed      chan struct{}
	closeOnce   sync.Once
	acceptCalls atomic.Int32
}

func newTRK35Session(capacity int) *trk35Session {
	return &trk35Session{accepts: make(chan StreamLink, capacity), closed: make(chan struct{})}
}

func (s *trk35Session) OpenStream(context.Context) (StreamLink, error) { return nil, ErrCarrierClosed }

func (s *trk35Session) AcceptStream(ctx context.Context) (StreamLink, error) {
	s.acceptCalls.Add(1)
	select {
	case <-s.closed:
		return nil, ErrCarrierClosed
	default:
	}
	select {
	case <-s.closed:
		return nil, ErrCarrierClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case stream := <-s.accepts:
		return stream, nil
	}
}

func (s *trk35Session) Ping(ctx context.Context) error {
	select {
	case <-s.closed:
		return ErrCarrierClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *trk35Session) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *trk35Session) CloseChan() <-chan struct{} { return s.closed }

var _ Session = (*trk35Session)(nil)

var _ io.ReadWriteCloser = (*trk35MemoryLink)(nil)
