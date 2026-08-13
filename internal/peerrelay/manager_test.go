package peerrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestManagerForwardsOpaqueBytesAndRecordsCarrierOnce(t *testing.T) {
	recorder := &recordingUsage{}
	manager := newTestManager(t, DevelopmentConfig(), recorder)
	binding := testBinding(time.Now().Add(time.Minute), 1<<20)
	initiator, initiatorRelay := net.Pipe()
	host, hostRelay := net.Pipe()
	results := attachPair(manager, binding, CarrierQUIC, CarrierQUIC, initiatorRelay, hostRelay)

	toHost := []byte("opaque-noise-record-to-host")
	writeAndRead(t, initiator, host, toHost)
	toInitiator := []byte("opaque-noise-record-to-initiator")
	writeAndRead(t, host, initiator, toInitiator)
	_ = initiator.Close()
	_ = host.Close()
	first, second := <-results, <-results
	for _, result := range []attachResult{first, second} {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.usage.Path != PathRelayQUIC || result.usage.BytesToHost != uint64(len(toHost)) || result.usage.BytesToInitiator != uint64(len(toInitiator)) {
			t.Fatalf("usage=%+v", result.usage)
		}
	}
	recorded := recorder.snapshot()
	if len(recorded) != 1 || recorded[0].Path != PathRelayQUIC || recorded[0].BytesToHost != uint64(len(toHost)) || recorded[0].BytesToInitiator != uint64(len(toInitiator)) {
		t.Fatalf("recorded=%+v", recorded)
	}
	if stats := manager.Stats(); stats != (Stats{}) {
		t.Fatalf("stats=%+v", stats)
	}
	replayClient, replayRelay := net.Pipe()
	if _, err := manager.Attach(context.Background(), Admission{Binding: binding, Role: RoleInitiator, Carrier: CarrierQUIC}, replayRelay); !errors.Is(err, ErrConflict) {
		t.Fatalf("consumed handle replay error=%v", err)
	}
	_ = replayClient.Close()
}

func TestManagerIsolatesConcurrentQUICAndWSSBindings(t *testing.T) {
	manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
	binding := testBinding(time.Now().Add(time.Minute), 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 2)
	clients := make([]net.Conn, 0, 2)
	for _, carrier := range []Carrier{CarrierQUIC, CarrierWSS} {
		client, relay := net.Pipe()
		clients = append(clients, client)
		go func(carrier Carrier) {
			_, err := manager.Attach(ctx, Admission{Binding: binding, Role: RoleHost, Carrier: carrier}, relay)
			results <- err
		}(carrier)
	}
	waitStats(t, manager, Stats{Pending: 2})
	cancel()
	for range 2 {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatalf("carrier-isolated cancellation=%v", err)
		}
	}
	for _, client := range clients {
		_ = client.Close()
	}
}

func TestManagerClassifiesTwoQUICLegs(t *testing.T) {
	recorder := &recordingUsage{}
	manager := newTestManager(t, DevelopmentConfig(), recorder)
	left, leftRelay := net.Pipe()
	right, rightRelay := net.Pipe()
	results := attachPair(manager, testBinding(time.Now().Add(time.Minute), 1024), CarrierQUIC, CarrierQUIC, leftRelay, rightRelay)
	_ = left.Close()
	_ = right.Close()
	for range 2 {
		result := <-results
		if result.err != nil || result.usage.Path != PathRelayQUIC {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestManagerRejectsDuplicateRoleAndBoundsPending(t *testing.T) {
	config := DevelopmentConfig()
	config.MaximumPending = 1
	manager := newTestManager(t, config, &recordingUsage{})
	ctx, cancel := context.WithCancel(context.Background())
	binding := testBinding(time.Now().Add(time.Minute), 1024)
	firstClient, firstRelay := net.Pipe()
	first := make(chan error, 1)
	go func() {
		_, err := manager.Attach(ctx, Admission{Binding: binding, Role: RoleInitiator, Carrier: CarrierQUIC}, firstRelay)
		first <- err
	}()
	waitStats(t, manager, Stats{Pending: 1})
	duplicateClient, duplicateRelay := net.Pipe()
	if _, err := manager.Attach(context.Background(), Admission{Binding: binding, Role: RoleInitiator, Carrier: CarrierWSS}, duplicateRelay); !errors.Is(err, ErrCapacity) {
		t.Fatalf("duplicate error=%v", err)
	}
	_ = duplicateClient.Close()
	otherClient, otherRelay := net.Pipe()
	if _, err := manager.Attach(context.Background(), Admission{Binding: testBinding(time.Now().Add(time.Minute), 1024), Role: RoleInitiator, Carrier: CarrierQUIC}, otherRelay); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	_ = otherClient.Close()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending cancellation=%v", err)
	}
	_ = firstClient.Close()
}

func TestManagerBoundsActivationAcrossPendingPairs(t *testing.T) {
	config := DevelopmentConfig()
	config.MaximumActive = 1
	manager := newTestManager(t, config, &recordingUsage{})
	firstBinding := testBinding(time.Now().Add(time.Minute), 1024)
	secondBinding := testBinding(time.Now().Add(time.Minute), 1024)
	secondBinding.StreamHandle[0]++
	firstClient, firstRelay := net.Pipe()
	secondClient, secondRelay := net.Pipe()
	firstPending := make(chan error, 1)
	secondPending := make(chan error, 1)
	go func() {
		_, err := manager.Attach(context.Background(), Admission{Binding: firstBinding, Role: RoleInitiator, Carrier: CarrierQUIC}, firstRelay)
		firstPending <- err
	}()
	go func() {
		_, err := manager.Attach(context.Background(), Admission{Binding: secondBinding, Role: RoleInitiator, Carrier: CarrierQUIC}, secondRelay)
		secondPending <- err
	}()
	waitStats(t, manager, Stats{Pending: 2})
	firstHost, firstHostRelay := net.Pipe()
	firstActive := make(chan error, 1)
	go func() {
		_, err := manager.Attach(context.Background(), Admission{Binding: firstBinding, Role: RoleHost, Carrier: CarrierQUIC}, firstHostRelay)
		firstActive <- err
	}()
	waitStats(t, manager, Stats{Pending: 1, Active: 1})
	rejected, rejectedRelay := net.Pipe()
	if _, err := manager.Attach(context.Background(), Admission{Binding: secondBinding, Role: RoleHost, Carrier: CarrierQUIC}, rejectedRelay); !errors.Is(err, ErrCapacity) {
		t.Fatalf("activation error=%v", err)
	}
	_ = rejected.Close()
	_ = manager.Close()
	for _, result := range []<-chan error{firstPending, secondPending, firstActive} {
		if err := <-result; !errors.Is(err, ErrClosed) {
			t.Fatalf("close error=%v", err)
		}
	}
	_ = firstClient.Close()
	_ = secondClient.Close()
	_ = firstHost.Close()
}

func TestManagerAllowsBoundedPendingWhileActiveCapacityIsFull(t *testing.T) {
	config := DevelopmentConfig()
	config.MaximumPending = 1
	config.MaximumActive = 1
	manager := newTestManager(t, config, &recordingUsage{})

	activeBinding := testBinding(time.Now().Add(time.Minute), 1024)
	activeLeft, activeLeftRelay := net.Pipe()
	activeRight, activeRightRelay := net.Pipe()
	activeResults := attachPair(manager, activeBinding, CarrierQUIC, CarrierQUIC, activeLeftRelay, activeRightRelay)
	waitStats(t, manager, Stats{Active: 1})

	pendingBinding := testBinding(time.Now().Add(time.Minute), 1024)
	pendingBinding.StreamHandle[0]++
	pendingClient, pendingRelay := net.Pipe()
	pendingResult := make(chan error, 1)
	go func() {
		_, err := manager.Attach(context.Background(), Admission{Binding: pendingBinding, Role: RoleInitiator, Carrier: CarrierWSS}, pendingRelay)
		pendingResult <- err
	}()
	waitStats(t, manager, Stats{Pending: 1, Active: 1})

	secondClient, secondRelay := net.Pipe()
	if _, err := manager.Attach(context.Background(), Admission{Binding: pendingBinding, Role: RoleHost, Carrier: CarrierWSS}, secondRelay); !errors.Is(err, ErrCapacity) {
		t.Fatalf("activation error=%v", err)
	}
	_ = secondClient.Close()
	_ = manager.Close()
	for range 2 {
		if result := <-activeResults; !errors.Is(result.err, ErrClosed) {
			t.Fatalf("active close error=%v", result.err)
		}
	}
	if err := <-pendingResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("pending close error=%v", err)
	}
	_ = activeLeft.Close()
	_ = activeRight.Close()
	_ = pendingClient.Close()
}

func TestManagerLimitRevocationDrainAndClose(t *testing.T) {
	t.Run("limit", func(t *testing.T) {
		manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
		binding := testBinding(time.Now().Add(time.Minute), 4)
		initiator, initiatorRelay := net.Pipe()
		host, hostRelay := net.Pipe()
		results := attachPair(manager, binding, CarrierQUIC, CarrierQUIC, initiatorRelay, hostRelay)
		writeDone := make(chan error, 1)
		go func() { _, err := initiator.Write([]byte("12345")); writeDone <- err }()
		got := make([]byte, 4)
		if _, err := io.ReadFull(host, got); err != nil || string(got) != "1234" {
			t.Fatalf("got=%q err=%v", got, err)
		}
		_ = initiator.Close()
		_ = host.Close()
		<-writeDone
		for range 2 {
			if result := <-results; !errors.Is(result.err, ErrLimit) {
				t.Fatalf("limit error=%v", result.err)
			}
		}
	})

	t.Run("revoke", func(t *testing.T) {
		recorder := &recordingUsage{}
		manager := newTestManager(t, DevelopmentConfig(), recorder)
		binding := testBinding(time.Now().Add(time.Minute), 1024)
		left, leftRelay := net.Pipe()
		right, rightRelay := net.Pipe()
		results := attachPair(manager, binding, CarrierWSS, CarrierWSS, leftRelay, rightRelay)
		waitStats(t, manager, Stats{Active: 1})
		writeAndRead(t, left, right, []byte("ciphertext"))
		manager.Revoke(binding)
		for range 2 {
			if result := <-results; !errors.Is(result.err, ErrRevoked) || result.usage.BytesToHost != uint64(len("ciphertext")) {
				t.Fatalf("revoke error=%v", result.err)
			}
		}
		if values := recorder.snapshot(); len(values) != 1 || values[0].BytesToHost != uint64(len("ciphertext")) {
			t.Fatalf("usage=%+v", values)
		}
		_ = left.Close()
		_ = right.Close()
	})

	t.Run("revoke canonical binding", func(t *testing.T) {
		manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
		binding := testBinding(time.Now().Add(time.Minute), 1024)
		client, relay := net.Pipe()
		result := make(chan error, 1)
		go func() {
			_, err := manager.Attach(context.Background(), Admission{Binding: binding, Role: RoleInitiator, Carrier: CarrierQUIC}, relay)
			result <- err
		}()
		waitStats(t, manager, Stats{Pending: 1})
		revocation := binding
		revocation.ExpiresAt = binding.ExpiresAt.In(time.FixedZone("equivalent", 5*60*60+30*60))
		manager.Revoke(revocation)
		if err := <-result; !errors.Is(err, ErrRevoked) {
			t.Fatalf("revocation error=%v", err)
		}
		_ = client.Close()
	})

	t.Run("drain and close", func(t *testing.T) {
		manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
		manager.BeginDrain()
		client, relay := net.Pipe()
		if _, err := manager.Attach(context.Background(), Admission{Binding: testBinding(time.Now().Add(time.Minute), 1024), Role: RoleHost, Carrier: CarrierWSS}, relay); !errors.Is(err, ErrDraining) {
			t.Fatalf("drain error=%v", err)
		}
		_ = client.Close()
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagerExpiresPendingAttachment(t *testing.T) {
	manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
	client, relay := net.Pipe()
	result := make(chan error, 1)
	go func() {
		_, err := manager.Attach(context.Background(), Admission{Binding: testBinding(time.Now().Add(30*time.Millisecond), 1024), Role: RoleInitiator, Carrier: CarrierQUIC}, relay)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("expiry error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending attachment did not expire")
	}
	_ = client.Close()
}

func TestManagerRejectsCanceledContextAndTypedNilStream(t *testing.T) {
	manager := newTestManager(t, DevelopmentConfig(), &recordingUsage{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, relay := net.Pipe()
	if _, err := manager.Attach(ctx, Admission{Binding: testBinding(time.Now().Add(time.Minute), 1024), Role: RoleInitiator, Carrier: CarrierQUIC}, relay); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error=%v", err)
	}
	_ = client.Close()
	var typedNil *typedNilStream
	if _, err := manager.Attach(context.Background(), Admission{}, typedNil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil error=%v", err)
	}
}

type typedNilStream struct{}

func (*typedNilStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (*typedNilStream) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (*typedNilStream) Close() error              { return nil }

type attachResult struct {
	usage Usage
	err   error
}

func attachPair(manager *Manager, binding Binding, initiatorCarrier, hostCarrier Carrier, initiatorRelay, hostRelay io.ReadWriteCloser) <-chan attachResult {
	results := make(chan attachResult, 2)
	go func() {
		usage, err := manager.Attach(context.Background(), Admission{Binding: binding, Role: RoleInitiator, Carrier: initiatorCarrier}, initiatorRelay)
		results <- attachResult{usage: usage, err: err}
	}()
	go func() {
		usage, err := manager.Attach(context.Background(), Admission{Binding: binding, Role: RoleHost, Carrier: hostCarrier}, hostRelay)
		results <- attachResult{usage: usage, err: err}
	}()
	return results
}

func writeAndRead(t *testing.T, source net.Conn, destination net.Conn, payload []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := source.Write(payload)
		written <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(destination, got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got=%q want=%q", got, payload)
	}
}

func testBinding(expires time.Time, maximum uint64) Binding {
	var route, stream [16]byte
	copy(route[:], bytes.Repeat([]byte{1}, len(route)))
	copy(stream[:], bytes.Repeat([]byte{2}, len(stream)))
	return Binding{RouteAllocation: route, StreamHandle: stream, EnvironmentID: "environment_01", RouteID: "peer_route_01", RouteRevision: 4, IntentID: "intent_01", Attempt: 2, Network: 3, ExpiresAt: expires.UTC(), MaximumBytes: maximum}
}

func newTestManager(t *testing.T, config Config, recorder Recorder) *Manager {
	t.Helper()
	manager, err := NewManager(config, recorder, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func waitStats(t *testing.T, manager *Manager, expected Stats) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.Stats() == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stats=%+v want=%+v", manager.Stats(), expected)
}

type recordingUsage struct {
	mu     sync.Mutex
	values []Usage
}

func (r *recordingUsage) RecordRelayUsage(_ context.Context, usage Usage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, usage)
	return nil
}

func (r *recordingUsage) snapshot() []Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Usage(nil), r.values...)
}
