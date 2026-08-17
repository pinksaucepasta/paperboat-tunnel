package peerrelay

import (
	"context"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

type UsageMeter interface {
	Record(environment, route string, revision uint64, ingress, egress uint64) error
}

// MeterRecorder projects completed relay directions into the existing signed
// absolute usage-counter contract. Each forwarded byte enters exactly one
// customer direction rather than being counted once for each tunnel leg.
type MeterRecorder struct {
	Meter UsageMeter
}

func (r MeterRecorder) RecordRelayUsage(_ context.Context, record Usage) error {
	if r.Meter == nil || record.EnvironmentID == "" || record.RouteID == "" || record.RouteRevision == 0 {
		return usage.ErrMeterInvalid
	}
	return r.Meter.Record(record.EnvironmentID, record.RouteID, record.RouteRevision, record.BytesToHost, record.BytesToInitiator)
}

var _ Recorder = MeterRecorder{}
