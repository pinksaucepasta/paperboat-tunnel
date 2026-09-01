// Package telemetry provides bounded, typed, construction-safe edge telemetry.
// It intentionally has no exporter, HTTP handler, filesystem, or network dependency.
package telemetry

import "fmt"

type ErrorCode string

const (
	ErrorInvalidDimension   ErrorCode = "invalid_dimension"
	ErrorInvalidStatus      ErrorCode = "invalid_status"
	ErrorInvalidCode        ErrorCode = "invalid_code"
	ErrorInvalidRetry       ErrorCode = "invalid_retry"
	ErrorInvalidTime        ErrorCode = "invalid_time"
	ErrorInvalidString      ErrorCode = "invalid_string"
	ErrorInvalidID          ErrorCode = "invalid_id"
	ErrorInvalidEvent       ErrorCode = "invalid_event"
	ErrorInvalidCapacity    ErrorCode = "invalid_capacity"
	ErrorUnknownMetric      ErrorCode = "unknown_metric"
	ErrorMetricKindMismatch ErrorCode = "metric_kind_mismatch"
	ErrorUnknownLabel       ErrorCode = "unknown_label"
	ErrorMissingLabel       ErrorCode = "missing_label"
	ErrorLabelValueRejected ErrorCode = "label_value_rejected"
	ErrorMetricOverflow     ErrorCode = "metric_overflow"
	ErrorMetricCardinality  ErrorCode = "metric_cardinality"
	ErrorInvalidObservation ErrorCode = "invalid_observation"
	ErrorClosed             ErrorCode = "closed"
)

type Error struct {
	Code      ErrorCode
	Operation string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Code)
}

func newError(code ErrorCode, operation string) error {
	return &Error{Code: code, Operation: operation}
}
