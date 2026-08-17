package main

import (
	"encoding/json"
	"testing"
)

func TestCanonicalDocumentIsBounded(t *testing.T) {
	data, err := canonicalDocument()
	if err != nil {
		t.Fatal(err)
	}
	var value document
	if err := json.Unmarshal(data, &value); err != nil || value.SchemaVersion != schemaVersion || len(value.Metrics) == 0 {
		t.Fatalf("document=%+v error=%v", value, err)
	}
	for _, item := range value.Metrics {
		for label, values := range item.Labels {
			if len(values) == 0 {
				t.Fatalf("metric %q label %q is unbounded", item.Name, label)
			}
		}
	}
}

func TestRealMetricsHandlerMatchesSchema(t *testing.T) {
	if err := verifyHandler(); err != nil {
		t.Fatal(err)
	}
}

func TestParseLabelsRejectsDuplicateAndMalformedValues(t *testing.T) {
	labels, err := parseLabels(`kind="stream",result="success"`)
	if err != nil || labels["kind"] != "stream" || labels["result"] != "success" {
		t.Fatalf("labels=%v error=%v", labels, err)
	}
	for _, value := range []string{`kind`, `kind=stream`, `kind="stream",kind="route"`} {
		if _, err := parseLabels(value); err == nil {
			t.Fatalf("invalid labels %q accepted", value)
		}
	}
}
