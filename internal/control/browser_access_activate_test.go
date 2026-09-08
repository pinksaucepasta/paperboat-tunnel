package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
)

func TestBrowserAccessActivateUsesSignedEdgeRequest(t *testing.T) {
	want := connectorprotocol.IngressDecision{DecisionID: "decision_lazy"}
	client := controlClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/edge/browser-access/activate" || r.Header.Get("Authorization") != "Bearer "+testControlCredential || r.Header.Get("X-Paperboat-Edge-Node-ID") != "edge_1" || r.Header.Get("X-Paperboat-Edge-Process-Epoch") != "epoch_12345678" {
			t.Fatalf("activation request = %s %s %#v", r.Method, r.URL.Path, r.Header)
		}
		var input BrowserAuthorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Host != "p3000-abcdefghijklmnop.preview.example.test" || input.ResourceKind != "lazy_policy" || input.ResourceID != "" || input.RouteID != "" || input.Token != "credential" {
			t.Fatalf("activation input = %#v err=%v", input, err)
		}
		body, _ := json.Marshal(want)
		return response(http.StatusOK, string(body)), nil
	})
	authority := &BrowserAccessClient{HTTP: client, NodeID: "edge_1", ProcessEpoch: "epoch_12345678"}
	got, err := authority.Activate(context.Background(), BrowserAuthorizeRequest{Host: "p3000-abcdefghijklmnop.preview.example.test", Token: "credential", ResourceKind: "lazy_policy"})
	if err != nil || got.DecisionID != want.DecisionID {
		t.Fatalf("decision=%#v err=%v", got, err)
	}
}

func TestBrowserAccessActivateClassifiesFailures(t *testing.T) {
	for code, want := range map[string]error{
		"host_offline":        ErrLazyHostOffline,
		"origin_unavailable":  ErrLazyOriginUnavailable,
		"activation_timeout":  ErrLazyActivationTimeout,
		"generation_conflict": ErrLazyGenerationConflict,
		"activation_limit":    ErrLazyCapacity,
		"forwarding_failed":   ErrLazyForwardingFailed,
		"activation_cooldown": ErrLazyCooldown,
	} {
		t.Run(code, func(t *testing.T) {
			client := controlClient(t, func(*http.Request) (*http.Response, error) {
				return response(http.StatusServiceUnavailable, `{"error":{"code":"`+code+`","message":"safe"}}`), nil
			})
			authority := &BrowserAccessClient{HTTP: client, NodeID: "edge_1", ProcessEpoch: "epoch_12345678"}
			if _, err := authority.Activate(context.Background(), BrowserAuthorizeRequest{}); !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
		})
	}
}
