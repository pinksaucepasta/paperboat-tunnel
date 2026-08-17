package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/node"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/observability"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

const schemaVersion = 1

type document struct {
	SchemaVersion int      `json:"schema_version"`
	Metrics       []metric `json:"metrics"`
}

type metric struct {
	Name   string              `json:"name"`
	Kind   string              `json:"kind"`
	Labels map[string][]string `json:"labels,omitempty"`
}

func main() {
	write := flag.Bool("write", false, "write the canonical metric schema")
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("usage: metric-schema [-write] DOCUMENT")
	}
	data, err := canonicalDocument()
	if err != nil {
		fatalf("metric schema: %v", err)
	}
	path := flag.Arg(0)
	if *write {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fatalf("write metric schema: %v", err)
		}
		return
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, data) {
		fatalf("%s is stale; run make metrics-generate", path)
	}
	if err := verifyHandler(); err != nil {
		fatalf("metric handler: %v", err)
	}
}

func canonicalDocument() ([]byte, error) {
	descriptors := observability.MetricDescriptors()
	metrics := make([]metric, 0, len(descriptors))
	for index, descriptor := range descriptors {
		if descriptor.Name == "" || descriptor.Kind != "counter" && descriptor.Kind != "gauge" {
			return nil, fmt.Errorf("invalid descriptor %+v", descriptor)
		}
		if index > 0 && descriptors[index-1].Name >= descriptor.Name {
			return nil, fmt.Errorf("descriptors are not uniquely sorted at %q", descriptor.Name)
		}
		for label, values := range descriptor.Labels {
			if label == "" || len(values) == 0 || !sort.StringsAreSorted(values) {
				return nil, fmt.Errorf("metric %q label %q is not bounded and sorted", descriptor.Name, label)
			}
			for valueIndex := 1; valueIndex < len(values); valueIndex++ {
				if values[valueIndex-1] == values[valueIndex] {
					return nil, fmt.Errorf("metric %q label %q contains duplicate values", descriptor.Name, label)
				}
			}
		}
		metrics = append(metrics, metric{Name: descriptor.Name, Kind: descriptor.Kind, Labels: descriptor.Labels})
	}
	data, err := json.MarshalIndent(document{SchemaVersion: schemaVersion, Metrics: metrics}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func verifyHandler() error {
	now := time.Unix(1_800_000_000, 0).UTC()
	handler, err := observability.NewHandler(observability.Sources{
		Node:     func() node.Snapshot { return node.Snapshot{Live: true, Ready: true} },
		Manager:  func() node.ManagerSnapshot { return node.ManagerSnapshot{Capacity: 8} },
		Sessions: func() int { return 1 }, SessionRoutes: func() int { return 1 },
		ActiveStreams: func() uint32 { return 1 }, RouteCount: func() int { return 1 },
		Usage:      func() usage.QueueStats { return usage.QueueStats{MaxReports: 8, MaxBytes: 1024} },
		ControlErr: func() error { return nil }, RouteErr: func() error { return nil }, UsageErr: func() error { return nil },
		FRPRunning: func() bool { return true }, CaddyRunning: func() bool { return true },
		STUN: func() observability.STUNStats { return observability.STUNStats{Running: true, Accepted: 1} },
		Signaling: func() observability.SignalingStats {
			return observability.SignalingStats{Running: true, Sessions: 1, Attachments: 1, Capacity: 8}
		},
		CaddyTLS: func() (time.Time, error) { return now.Add(time.Hour), nil },
		Events: func() map[observability.MetricKey]uint64 {
			return map[observability.MetricKey]uint64{{Kind: observability.Admission, Result: observability.Success}: 1}
		},
		Traffic: func() []usage.CounterRecord { return nil }, Now: func() time.Time { return now },
	})
	if err != nil {
		return err
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		return fmt.Errorf("status %d", recorder.Code)
	}
	documented := make(map[string]observability.MetricDescriptor)
	for _, descriptor := range observability.MetricDescriptors() {
		documented[descriptor.Name] = descriptor
	}
	emitted := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSpace(recorder.Body.String()), "\n") {
		token := strings.Fields(line)[0]
		name := token
		labels := map[string]string{}
		if index := strings.IndexByte(token, '{'); index >= 0 {
			name = token[:index]
			parsed, parseErr := parseLabels(token[index+1 : len(token)-1])
			if parseErr != nil {
				return fmt.Errorf("parse %s labels: %w", name, parseErr)
			}
			labels = parsed
		}
		descriptor, ok := documented[name]
		if !ok {
			return fmt.Errorf("handler emitted undocumented metric %q", name)
		}
		if err := validateLabels(descriptor, labels); err != nil {
			return err
		}
		emitted[name] = struct{}{}
	}
	for name := range documented {
		if _, ok := emitted[name]; !ok {
			return fmt.Errorf("documented metric %q was not emitted", name)
		}
	}
	return nil
}

func parseLabels(value string) (map[string]string, error) {
	result := map[string]string{}
	if value == "" {
		return result, nil
	}
	for _, item := range strings.Split(value, ",") {
		key, quoted, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid label %q", item)
		}
		decoded, err := strconv.Unquote(quoted)
		if err != nil {
			return nil, err
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate label %q", key)
		}
		result[key] = decoded
	}
	return result, nil
}

func validateLabels(descriptor observability.MetricDescriptor, labels map[string]string) error {
	if len(labels) != len(descriptor.Labels) {
		return fmt.Errorf("metric %q labels=%v want=%v", descriptor.Name, labels, descriptor.Labels)
	}
	for label, value := range labels {
		allowed, ok := descriptor.Labels[label]
		if !ok || !contains(allowed, value) {
			return fmt.Errorf("metric %q has undocumented label %s=%q", descriptor.Name, label, value)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
