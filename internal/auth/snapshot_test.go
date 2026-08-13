package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/strictjson"
)

func makeJWKS(t testing.TB, entries map[string]ed25519.PublicKey) []byte {
	t.Helper()
	keys := make([]map[string]string, 0, len(entries))
	for id, key := range entries {
		keys = append(keys, map[string]string{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": id, "x": base64.RawURLEncoding.EncodeToString(key)})
	}
	data, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSnapshotRotationAndRevocation(t *testing.T) {
	oldPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := NewSnapshot()
	if err := snapshot.ReplaceJWKS(makeJWKS(t, map[string]ed25519.PublicKey{"old": oldPublic, "new": newPublic})); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Key(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.ReplaceJWKS(makeJWKS(t, map[string]ed25519.PublicKey{"new": newPublic})); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Key(context.Background(), "old"); err == nil {
		t.Fatal("retired key retained")
	}
	revocations, _ := json.Marshal(RevocationDocument{JTIs: []string{"jti"}, Environments: []string{"other-env"}, Connectors: []RevokedConnectorGeneration{{MachineID: "machine", ConnectorID: "runtime", Generation: 3}}, KeyIDs: []string{"retired"}})
	if err := snapshot.ReplaceRevocations(revocations); err != nil {
		t.Fatal(err)
	}
	for _, claims := range []admission.Claims{{JTI: "jti"}, {EnvironmentID: "other-env"}, {MachineID: "machine", ConnectorID: "runtime", ConnectorGeneration: 3}, {KeyID: "retired"}} {
		revoked, err := snapshot.Revoked(context.Background(), claims)
		if err != nil || !revoked {
			t.Fatalf("not revoked: %+v, %v", claims, err)
		}
	}
}

func TestSnapshotRejectsMalformedAndSupportsConcurrentReaders(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := NewSnapshot()
	for _, invalid := range [][]byte{nil, []byte(`{"keys":[]}`), []byte(`{"keys":[{"kty":"RSA"}]}`), []byte(`{"keys":[],"unknown":true}`), []byte(`{"keys":[],"keys":[]}`)} {
		if err := snapshot.ReplaceJWKS(invalid); err == nil {
			t.Fatalf("invalid JWKS accepted: %s", invalid)
		}
	}
	canonicalKey := base64.RawURLEncoding.EncodeToString(public)
	if err := snapshot.ReplaceJWKS([]byte(strings.Replace(string(makeJWKS(t, map[string]ed25519.PublicKey{"key": public})), canonicalKey, canonicalKey+"=", 1))); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("non-canonical JWK error=%v", err)
	}
	data := makeJWKS(t, map[string]ed25519.PublicKey{"key": public})
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				_ = snapshot.ReplaceJWKS(data)
				_, _ = snapshot.Key(context.Background(), "key")
			}
		}()
	}
	group.Wait()
}

func TestSnapshotFailsClosedWhenRevocationsAreStale(t *testing.T) {
	now := time.Unix(1000, 0)
	snapshot := NewSnapshot()
	snapshot.ConfigureRevocationFreshness(time.Minute, func() time.Time { return now })
	if err := snapshot.ReplaceRevocations([]byte(`{"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Revoked(context.Background(), admission.Claims{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute + time.Nanosecond)
	if _, err := snapshot.Revoked(context.Background(), admission.Claims{}); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("stale revocations error = %v", err)
	}
	now = time.Unix(999, 0)
	if _, err := snapshot.Revoked(context.Background(), admission.Claims{}); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("clock rollback error = %v", err)
	}
}

func TestSnapshotRejectsDuplicateRevocationFields(t *testing.T) {
	snapshot := NewSnapshot()
	for _, invalid := range [][]byte{
		[]byte(`{"jtis":[],"jtis":[],"environments":[],"connector_generations":[],"key_ids":[]}`),
		[]byte(`{"jtis":[],"environments":[],"connector_generations":[{"machine_id":"a","machine_id":"b","connector_id":"c","connector_generation":1}],"key_ids":[]}`),
	} {
		if err := snapshot.ReplaceRevocations(invalid); !errors.Is(err, ErrSnapshotInvalid) {
			t.Fatalf("duplicate fields error=%v", err)
		}
	}
}

func TestSnapshotJSONNestingIsBounded(t *testing.T) {
	withinLimit := []byte(strings.Repeat("[", maxSnapshotJSONDepth) + "0" + strings.Repeat("]", maxSnapshotJSONDepth))
	if err := strictjson.Validate(withinLimit, maxSnapshotJSONDepth); err != nil {
		t.Fatalf("bounded nesting rejected: %v", err)
	}
	overLimit := []byte(strings.Repeat("[", maxSnapshotJSONDepth+1) + "0" + strings.Repeat("]", maxSnapshotJSONDepth+1))
	if err := strictjson.Validate(overLimit, maxSnapshotJSONDepth); !errors.Is(err, strictjson.ErrInvalid) {
		t.Fatalf("deep nesting error=%v", err)
	}
}

func TestSnapshotWatcherReleaseOwnsExactRegistration(t *testing.T) {
	snapshot := NewSnapshot()
	claims := admission.Claims{JTI: "jti", EnvironmentID: "environment", KeyID: "key"}
	_, releaseFirst, err := snapshot.Watch(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseSecond, err := snapshot.Watch(claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.watchers) != 2 {
		t.Fatalf("watchers=%d", len(snapshot.watchers))
	}
	releaseFirst()
	releaseFirst()
	if len(snapshot.watchers) != 1 {
		t.Fatalf("first release removed wrong watcher: %d", len(snapshot.watchers))
	}
	releaseSecond()
	if len(snapshot.watchers) != 0 {
		t.Fatalf("second release retained watcher: %d", len(snapshot.watchers))
	}
}
