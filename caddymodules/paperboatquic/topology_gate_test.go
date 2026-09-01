package paperboatquic

import "testing"

func TestTopologyRelayOptionsFailClosedOnPartialEnablement(t *testing.T) {
	if enabled, fileRelay, upstream, err := topologyRelayOptions("", "", ""); err != nil || enabled || fileRelay || upstream != "" {
		t.Fatalf("disabled options = %v, %v, %q, %v", enabled, fileRelay, upstream, err)
	}
	for _, test := range []struct {
		role, relay, upstream string
	}{
		{"", "1", "upstream:8080"},
		{"relay-edge", "1", ""},
		{"relay-edge", "0", "upstream:8080"},
		{"relay-edge", "yes", "upstream:8080"},
		{"relay-edge ", "", ""},
	} {
		if _, _, _, err := topologyRelayOptions(test.role, test.relay, test.upstream); err == nil {
			t.Fatalf("invalid options accepted: %+v", test)
		}
	}
	enabled, fileRelay, upstream, err := topologyRelayOptions("relay-edge", "1", "upstream:8080")
	if err != nil || !enabled || !fileRelay || upstream != "upstream:8080" {
		t.Fatalf("valid options = %v, %v, %q, %v", enabled, fileRelay, upstream, err)
	}
}
