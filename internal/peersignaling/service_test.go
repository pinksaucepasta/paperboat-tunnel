package peersignaling

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type authenticatorFunc func(context.Context, string) (Admission, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, credential string) (Admission, error) {
	return f(ctx, credential)
}

type validatorFactory struct {
	mu       sync.Mutex
	bindings []Binding
	reject   error
}

func (f *validatorFactory) NewValidator(binding Binding) (Validator, error) {
	f.mu.Lock()
	f.bindings = append(f.bindings, binding)
	f.mu.Unlock()
	return validatorFunc(func([]byte) (bool, error) { return true, f.reject }), nil
}

type validatorFunc func([]byte) (bool, error)

func (f validatorFunc) Accept(raw []byte) (bool, error) { return f(raw) }

func TestServiceForwardsOrderedMessagesWithReciprocalBindings(t *testing.T) {
	now := time.Now().UTC()
	revoked := make(chan struct{})
	admissions := map[string]Admission{
		"left":  testAdmission(now, "left", "right", RoleControlling, revoked),
		"right": testAdmission(now, "right", "left", RoleControlled, nil),
	}
	factory := &validatorFactory{}
	service, err := New(Config{Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) { return admissions[credential], nil }), Validators: factory, MaximumSessions: 1, QueueDepth: 2, MaximumMessage: 32, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("one")); err != nil {
		t.Fatal(err)
	}
	right, err := service.Attach(context.Background(), "right")
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	if err := left.Send(context.Background(), []byte("two")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		raw, receiveErr := right.Receive(context.Background())
		if receiveErr != nil || string(raw) != want {
			t.Fatalf("message=%q error=%v", raw, receiveErr)
		}
		raw[0] = 'x'
	}
	if stats := service.Stats(); stats.Sessions != 1 || stats.Attachments != 2 {
		t.Fatalf("stats=%+v", stats)
	}
	factory.mu.Lock()
	bindings := append([]Binding(nil), factory.bindings...)
	factory.mu.Unlock()
	if len(bindings) != 2 || bindings[0].Role != RoleControlling || bindings[1].Role != RoleControlled {
		t.Fatalf("bindings=%+v", bindings)
	}
	close(revoked)
	deadline := time.Now().Add(time.Second)
	for service.Stats().Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := right.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("revocation error=%v", err)
	}
}

func TestServiceCompletePreservesPeerDrainUntilBothRolesComplete(t *testing.T) {
	now := time.Now().UTC()
	admissions := map[string]Admission{
		"left":       testAdmission(now, "left", "right", RoleControlling, nil),
		"left-again": testAdmission(now, "left-again", "right", RoleControlling, nil),
		"right":      testAdmission(now, "right", "left", RoleControlled, nil),
	}
	service, err := New(Config{
		Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
			return admissions[credential], nil
		}),
		Validators: &validatorFactory{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	right, err := service.Attach(context.Background(), "right")
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("queued")); err != nil {
		t.Fatal(err)
	}
	if err := left.Complete(); err != nil {
		t.Fatal(err)
	}
	message, err := right.Receive(context.Background())
	if err != nil || string(message) != "queued" {
		t.Fatalf("message=%q error=%v", message, err)
	}
	if _, err := service.Attach(context.Background(), "left-again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("completed role reattachment error=%v", err)
	}
	if stats := service.Stats(); stats.Sessions != 1 || stats.Attachments != 1 {
		t.Fatalf("half-closed stats=%+v", stats)
	}
	if err := right.Complete(); err != nil {
		t.Fatal(err)
	}
	if stats := service.Stats(); stats.Sessions != 0 || stats.Attachments != 0 {
		t.Fatalf("completed stats=%+v", stats)
	}
}

func TestServiceRejectsConflictsCapacityAndInvalidMessages(t *testing.T) {
	now := time.Now().UTC()
	admissions := map[string]Admission{
		"left":      testAdmission(now, "left", "right", RoleControlling, nil),
		"duplicate": testAdmission(now, "left", "right", RoleControlling, nil),
		"wrong":     testAdmission(now, "intruder", "left", RoleControlled, nil),
		"other":     testAdmission(now, "third", "fourth", RoleControlling, nil),
	}
	rejected := errors.New("protocol rejected")
	factory := &validatorFactory{reject: rejected}
	service, err := New(Config{Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
		value := admissions[credential]
		if credential == "other" {
			value.IntentID = "other_intent"
		}
		return value, nil
	}), Validators: factory, MaximumSessions: 1, QueueDepth: 1, MaximumMessage: 4, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Attach(context.Background(), "duplicate"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	if _, err := service.Attach(context.Background(), "wrong"); !errors.Is(err, ErrConflict) {
		t.Fatalf("reciprocal error=%v", err)
	}
	if _, err := service.Attach(context.Background(), "other"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	if err := left.Send(context.Background(), []byte("bad")); !errors.Is(err, rejected) {
		t.Fatalf("validation error=%v", err)
	}
	if err := left.Send(context.Background(), []byte("large")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("size error=%v", err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("bad")); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed error=%v", err)
	}
	if _, err := service.Attach(context.Background(), "left"); !errors.Is(err, ErrConflict) {
		t.Fatalf("credential replay error=%v", err)
	}
}

func TestServiceQueueCapacityDoesNotAdvanceValidation(t *testing.T) {
	now := time.Now().UTC()
	accepted := 0
	service, err := New(Config{
		Authenticator: authenticatorFunc(func(context.Context, string) (Admission, error) {
			return testAdmission(now, "left", "right", RoleControlling, nil), nil
		}),
		Validators: validatorFactoryFunc(func(Binding) (Validator, error) {
			return validatorFunc(func([]byte) (bool, error) { accepted++; return true, nil }), nil
		}),
		MaximumSessions: 1, QueueDepth: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	attachment, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.Send(context.Background(), []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := attachment.Send(context.Background(), []byte("two")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	if accepted != 1 {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestServiceDoesNotForwardDeduplicatedMessages(t *testing.T) {
	now := time.Now().UTC()
	service, err := New(Config{
		Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
			if credential == "left" {
				return testAdmission(now, "left", "right", RoleControlling, nil), nil
			}
			return testAdmission(now, "right", "left", RoleControlled, nil), nil
		}),
		Validators: validatorFactoryFunc(func(Binding) (Validator, error) {
			return validatorFunc(func(raw []byte) (bool, error) { return string(raw) != "duplicate", nil }), nil
		}),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	right, err := service.Attach(context.Background(), "right")
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("duplicate")); err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("unique")); err != nil {
		t.Fatal(err)
	}
	raw, err := right.Receive(context.Background())
	if err != nil || string(raw) != "unique" {
		t.Fatalf("message=%q error=%v", raw, err)
	}
}

func TestServiceExpiryAuthenticationAndShutdown(t *testing.T) {
	now := time.Now().UTC()
	authErr := errors.New("authority unavailable")
	service, err := New(Config{Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
		if credential == "failure" {
			return Admission{}, authErr
		}
		value := testAdmission(now, "left", "right", RoleControlling, nil)
		value.ExpiresAt = time.Now().Add(20 * time.Millisecond)
		return value, nil
	}), Validators: &validatorFactory{}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Attach(context.Background(), "failure"); !errors.Is(err, authErr) {
		t.Fatalf("authentication error=%v", err)
	}
	attachment, err := service.Attach(context.Background(), "valid")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := attachment.Receive(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("expiry error=%v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Attach(context.Background(), "valid"); !errors.Is(err, ErrClosed) {
		t.Fatalf("shutdown error=%v", err)
	}
}

func TestServiceReleasesBothAdmissionWatchersWhenEitherSideCloses(t *testing.T) {
	now := time.Now().UTC()
	var releases atomic.Int32
	service, err := New(Config{
		Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
			if credential == "left" {
				value := testAdmission(now, "left", "right", RoleControlling, nil)
				value.Release = func() { releases.Add(1) }
				return value, nil
			}
			value := testAdmission(now, "right", "left", RoleControlled, nil)
			value.Release = func() { releases.Add(1) }
			return value, nil
		}),
		Validators: &validatorFactory{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Attach(context.Background(), "right"); err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for releases.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if releases.Load() != 2 {
		t.Fatalf("releases=%d", releases.Load())
	}
}

func TestRevocationDropsBufferedMessages(t *testing.T) {
	now := time.Now().UTC()
	revoked := make(chan struct{})
	service, err := New(Config{
		Authenticator: authenticatorFunc(func(_ context.Context, credential string) (Admission, error) {
			if credential == "left" {
				return testAdmission(now, "left", "right", RoleControlling, revoked), nil
			}
			return testAdmission(now, "right", "left", RoleControlled, nil), nil
		}),
		Validators: &validatorFactory{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	left, err := service.Attach(context.Background(), "left")
	if err != nil {
		t.Fatal(err)
	}
	right, err := service.Attach(context.Background(), "right")
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), []byte("private-candidate")); err != nil {
		t.Fatal(err)
	}
	close(revoked)
	deadline := time.Now().Add(time.Second)
	for service.Stats().Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if raw, err := right.Receive(context.Background()); !errors.Is(err, ErrClosed) || raw != nil {
		t.Fatalf("buffered message=%q error=%v", raw, err)
	}
}

func testAdmission(now time.Time, endpoint, peer string, role Role, revoked <-chan struct{}) Admission {
	return Admission{CredentialID: "credential_" + endpoint, EnvironmentID: "environment_1", NodeID: "node_1", IntentID: "intent_1", EndpointID: endpoint, PeerEndpointID: peer, AttemptGeneration: 2, NetworkGeneration: 4, Role: role, ExpiresAt: now.Add(time.Minute), Revoked: revoked}
}

type validatorFactoryFunc func(Binding) (Validator, error)

func (f validatorFactoryFunc) NewValidator(binding Binding) (Validator, error) { return f(binding) }
