package telemetry

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ContractSchemaV1 is the language-neutral resource schema shared by the
// server, host runtime, edge and dashboard.
const ContractSchemaV1 = "paperboat.preview-tunnel/v1"

// ResourceSchemaV1 is retained as the edge package's descriptive alias.
const ResourceSchemaV1 = ContractSchemaV1

const (
	KindHealth = "health"
	KindEvent  = "event"
	KindLog    = "log_entry"
	KindError  = "error"
)

var (
	resourceIDPattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,128}$`)
	healthResourceKindSet = map[string]struct{}{
		"preview_lease": {}, "tunnel": {}, "route": {}, "domain_binding": {}, "connector": {},
	}
	actorTypeSet              = map[string]struct{}{"user": {}, "host": {}, "system": {}, "edge": {}}
	metadataKeyPattern        = regexp.MustCompile(`(?i)(token|secret|private[_-]?key|authorization|password|cookie)`)
	canonicalEventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,79}$`)
)

type CanonicalHealthDimension struct {
	Status HealthStatus `json:"status"`
	Code   string       `json:"code"`
}

type CanonicalHealthDimensions struct {
	Service     CanonicalHealthDimension `json:"service"`
	Edge        CanonicalHealthDimension `json:"edge"`
	Config      CanonicalHealthDimension `json:"config"`
	Route       CanonicalHealthDimension `json:"route"`
	Origin      CanonicalHealthDimension `json:"origin"`
	DNS         CanonicalHealthDimension `json:"dns"`
	Certificate CanonicalHealthDimension `json:"certificate"`
	Access      CanonicalHealthDimension `json:"access"`
	Update      CanonicalHealthDimension `json:"update"`
}

func (d CanonicalHealthDimensions) Get(dimension Dimension) CanonicalHealthDimension {
	switch dimension {
	case DimensionService:
		return d.Service
	case DimensionEdge:
		return d.Edge
	case DimensionConfig:
		return d.Config
	case DimensionRoute:
		return d.Route
	case DimensionOrigin:
		return d.Origin
	case DimensionDNS:
		return d.DNS
	case DimensionCertificate:
		return d.Certificate
	case DimensionAccess:
		return d.Access
	case DimensionUpdate:
		return d.Update
	default:
		return CanonicalHealthDimension{}
	}
}

func (d *CanonicalHealthDimensions) set(dimension Dimension, value CanonicalHealthDimension) {
	switch dimension {
	case DimensionService:
		d.Service = value
	case DimensionEdge:
		d.Edge = value
	case DimensionConfig:
		d.Config = value
	case DimensionRoute:
		d.Route = value
	case DimensionOrigin:
		d.Origin = value
	case DimensionDNS:
		d.DNS = value
	case DimensionCertificate:
		d.Certificate = value
	case DimensionAccess:
		d.Access = value
	case DimensionUpdate:
		d.Update = value
	}
}

// ResourceHealthDimension identifies one canonical health dimension used by
// both server and edge serialization.
type ResourceHealthDimension = CanonicalHealthDimension
type ResourceHealthDimensions = CanonicalHealthDimensions

type HealthResourceBinding struct {
	ResourceKind  string
	ResourceID    string
	CorrelationID string
}

type HealthResource struct {
	Schema        string                   `json:"schema"`
	Kind          string                   `json:"kind"`
	ResourceKind  string                   `json:"resource_kind"`
	ResourceID    string                   `json:"resource_id"`
	OverallCode   string                   `json:"overall_code"`
	Dimensions    ResourceHealthDimensions `json:"dimensions"`
	Summary       string                   `json:"summary"`
	Since         time.Time                `json:"since"`
	Retrying      bool                     `json:"retrying"`
	NextRetryAt   *time.Time               `json:"next_retry_at,omitempty"`
	RepairAction  string                   `json:"repair_action"`
	CorrelationID string                   `json:"correlation_id"`
}

func ProjectHealthResource(snapshot HealthSnapshot, binding HealthResourceBinding) (HealthResource, error) {
	if snapshot.Schema != HealthSchemaV1 {
		return HealthResource{}, newError(ErrorInvalidObservation, "project edge health resource")
	}
	return NewHealthResource(HealthResourceInput{
		ResourceKind:  binding.ResourceKind,
		ResourceID:    binding.ResourceID,
		Snapshot:      snapshot,
		CorrelationID: binding.CorrelationID,
	})
}

type HealthResourceInput struct {
	ResourceKind  string
	ResourceID    string
	Snapshot      HealthSnapshot
	CorrelationID string
}

func NewHealthResource(input HealthResourceInput) (HealthResource, error) {
	if !validHealthResourceKind(input.ResourceKind) || !resourceIDPattern.MatchString(input.ResourceID) {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	snapshot := input.Snapshot
	if snapshot.Schema != "" && snapshot.Schema != HealthSchemaV1 {
		return HealthResource{}, newError(ErrorInvalidObservation, "construct health resource")
	}
	if snapshot.UpdatedAt.IsZero() || snapshot.Overall.Since.IsZero() || !stableCodePattern.MatchString(snapshot.Overall.Code) {
		return HealthResource{}, newError(ErrorInvalidObservation, "construct health resource")
	}
	correlationID := input.CorrelationID
	if correlationID == "" {
		correlationID = snapshot.Overall.CorrelationID
	}
	if input.CorrelationID != "" && snapshot.Overall.CorrelationID != "" && input.CorrelationID != snapshot.Overall.CorrelationID {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	if !resourceIDPattern.MatchString(correlationID) {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	var nextRetryAt *time.Time
	if snapshot.Overall.NextRetryAt != nil {
		value := normalizeTime(*snapshot.Overall.NextRetryAt)
		nextRetryAt = &value
	}
	resource := HealthResource{
		Schema:        ContractSchemaV1,
		Kind:          KindHealth,
		ResourceKind:  input.ResourceKind,
		ResourceID:    input.ResourceID,
		OverallCode:   snapshot.Overall.Code,
		Summary:       snapshot.Overall.Summary,
		Since:         normalizeTime(snapshot.Overall.Since),
		Retrying:      snapshot.Overall.Retry == RetryScheduled,
		NextRetryAt:   nextRetryAt,
		RepairAction:  snapshot.Overall.RepairAction,
		CorrelationID: correlationID,
	}
	for _, dimension := range dimensionOrder {
		state := snapshot.Dimensions.Get(dimension)
		resource.Dimensions.set(dimension, CanonicalHealthDimension{Status: state.Status, Code: state.Code})
	}
	if err := resource.Validate(); err != nil {
		return HealthResource{}, err
	}
	return resource, nil
}

func (s HealthSnapshot) AsResource(resourceKind, resourceID, correlationID string) (HealthResource, error) {
	return NewHealthResource(HealthResourceInput{ResourceKind: resourceKind, ResourceID: resourceID, Snapshot: s, CorrelationID: correlationID})
}

func (r HealthResource) Validate() error {
	if r.Schema != ContractSchemaV1 || r.Kind != KindHealth || !validHealthResourceKind(r.ResourceKind) || !resourceIDPattern.MatchString(r.ResourceID) || !stableCodePattern.MatchString(r.OverallCode) || r.Since.IsZero() || !resourceIDPattern.MatchString(r.CorrelationID) || r.Summary == "" || r.RepairAction == "" || r.Retrying != (r.NextRetryAt != nil) || (r.NextRetryAt != nil && r.NextRetryAt.IsZero()) {
		return newError(ErrorInvalidObservation, "validate health resource")
	}
	for _, dimension := range dimensionOrder {
		state := r.Dimensions.Get(dimension)
		if !validHealthStatus(state.Status) || !stableCodePattern.MatchString(state.Code) {
			return newError(ErrorInvalidObservation, "validate health resource")
		}
	}
	return nil
}

func (r HealthResource) JSON() ([]byte, error) { return json.Marshal(r) }

type CanonicalActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type EventActor = CanonicalActor

type EventResourceBinding struct {
	ID           string
	Cursor       string
	ResourceKind string
	ResourceID   string
	Actor        EventActor
}

type CanonicalEventResource struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	Cursor        string         `json:"cursor"`
	EventType     string         `json:"event_type"`
	ResourceKind  string         `json:"resource_kind"`
	ResourceID    string         `json:"resource_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Actor         CanonicalActor `json:"actor"`
	CorrelationID string         `json:"correlation_id"`
	SafeMetadata  map[string]any `json:"safe_metadata"`
}

type CanonicalEventInput struct {
	ID            string
	Cursor        string
	EventType     string
	ResourceKind  string
	ResourceID    string
	OccurredAt    time.Time
	ActorType     string
	ActorID       string
	CorrelationID string
	SafeMetadata  map[string]any
}

func NewCanonicalEvent(input CanonicalEventInput) (CanonicalEventResource, error) {
	if !resourceIDPattern.MatchString(input.ID) || !resourceIDPattern.MatchString(input.Cursor) || !canonicalEventTypePattern.MatchString(input.EventType) || !validEventResourceKind(input.ResourceKind) || !resourceIDPattern.MatchString(input.ResourceID) || normalizeTime(input.OccurredAt).IsZero() || !validActorType(input.ActorType) || !resourceIDPattern.MatchString(input.ActorID) || !resourceIDPattern.MatchString(input.CorrelationID) {
		return CanonicalEventResource{}, newError(ErrorInvalidEvent, "construct canonical event")
	}
	metadata, err := safeMetadata(input.SafeMetadata)
	if err != nil {
		return CanonicalEventResource{}, err
	}
	event := CanonicalEventResource{Schema: ContractSchemaV1, Kind: KindEvent, ID: input.ID, Cursor: input.Cursor, EventType: input.EventType, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, OccurredAt: normalizeTime(input.OccurredAt), Actor: CanonicalActor{Type: input.ActorType, ID: input.ActorID}, CorrelationID: input.CorrelationID, SafeMetadata: metadata}
	return event, event.Validate()
}

func (e CanonicalEventResource) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindEvent || !resourceIDPattern.MatchString(e.ID) || !resourceIDPattern.MatchString(e.Cursor) || !canonicalEventTypePattern.MatchString(e.EventType) || !validEventResourceKind(e.ResourceKind) || !resourceIDPattern.MatchString(e.ResourceID) || e.OccurredAt.IsZero() || !validActorType(e.Actor.Type) || !resourceIDPattern.MatchString(e.Actor.ID) || !resourceIDPattern.MatchString(e.CorrelationID) {
		return newError(ErrorInvalidEvent, "validate canonical event")
	}
	_, err := safeMetadata(e.SafeMetadata)
	return err
}

func (e CanonicalEventResource) JSON() ([]byte, error) { return json.Marshal(e) }

type EventResource = CanonicalEventResource

func NewEventResource(input CanonicalEventInput) (EventResource, error) {
	return NewCanonicalEvent(input)
}

type LogEntry struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	TunnelID      string         `json:"tunnel_id,omitempty"`
	PreviewID     string         `json:"preview_id,omitempty"`
	RouteID       string         `json:"route_id,omitempty"`
	ConnectorID   string         `json:"connector_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	Level         EventSeverity  `json:"level"`
	Component     string         `json:"component"`
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Metadata      map[string]any `json:"metadata"`
	CorrelationID string         `json:"correlation_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Cursor        string         `json:"cursor"`
}

type LogEntryInput struct {
	ID, TunnelID, PreviewID, RouteID, ConnectorID, SessionID string
	Level                                                    EventSeverity
	Component, Code, Message, CorrelationID, Cursor          string
	Metadata                                                 map[string]any
	OccurredAt                                               time.Time
}

func NewLogEntry(input LogEntryInput) (LogEntry, error) {
	if !resourceIDPattern.MatchString(input.ID) || !validEventSeverity(input.Level) || input.Component == "" || len(input.Component) > 40 || !canonicalEventTypePattern.MatchString(input.Code) || !resourceIDPattern.MatchString(input.CorrelationID) || !resourceIDPattern.MatchString(input.Cursor) || normalizeTime(input.OccurredAt).IsZero() {
		return LogEntry{}, newError(ErrorInvalidEvent, "construct log entry")
	}
	message, err := safeBoundedString(input.Message, 1000, true)
	if err != nil {
		return LogEntry{}, err
	}
	metadata, err := safeMetadata(input.Metadata)
	if err != nil {
		return LogEntry{}, err
	}
	entry := LogEntry{Schema: ContractSchemaV1, Kind: KindLog, ID: input.ID, TunnelID: input.TunnelID, PreviewID: input.PreviewID, RouteID: input.RouteID, ConnectorID: input.ConnectorID, SessionID: input.SessionID, Level: input.Level, Component: input.Component, Code: input.Code, Message: message, Metadata: metadata, CorrelationID: input.CorrelationID, OccurredAt: normalizeTime(input.OccurredAt), Cursor: input.Cursor}
	return entry, entry.Validate()
}

func (e LogEntry) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindLog || !resourceIDPattern.MatchString(e.ID) || !validEventSeverity(e.Level) || e.Component == "" || len(e.Component) > 40 || !canonicalEventTypePattern.MatchString(e.Code) || e.Message == "" || !resourceIDPattern.MatchString(e.CorrelationID) || e.OccurredAt.IsZero() || !resourceIDPattern.MatchString(e.Cursor) {
		return newError(ErrorInvalidEvent, "validate log entry")
	}
	for _, id := range []string{e.TunnelID, e.PreviewID, e.RouteID, e.ConnectorID, e.SessionID} {
		if id != "" && !resourceIDPattern.MatchString(id) {
			return newError(ErrorInvalidID, "validate log entry")
		}
	}
	_, err := safeMetadata(e.Metadata)
	return err
}

func (e LogEntry) JSON() ([]byte, error) { return json.Marshal(e) }

type ErrorResource struct {
	Schema        string     `json:"schema"`
	Kind          string     `json:"kind"`
	Code          string     `json:"code"`
	Component     Dimension  `json:"component"`
	Message       string     `json:"message"`
	Outcome       string     `json:"outcome"`
	Retryable     bool       `json:"retryable"`
	RetryAt       *time.Time `json:"retry_at"`
	RepairAction  string     `json:"repair_action"`
	RequestID     string     `json:"request_id"`
	CorrelationID string     `json:"correlation_id"`
}

type ErrorResourceInput struct {
	Code          string
	Component     Dimension
	Message       string
	Outcome       string
	Retryable     bool
	RetryAt       time.Time
	RepairAction  string
	RequestID     string
	CorrelationID string
}

func NewErrorResource(input ErrorResourceInput) (ErrorResource, error) {
	message, err := safeBoundedString(input.Message, 1000, true)
	if err != nil {
		return ErrorResource{}, err
	}
	repair, err := safeBoundedString(input.RepairAction, 1000, true)
	if err != nil {
		return ErrorResource{}, err
	}
	if !stableCodePattern.MatchString(input.Code) || !validDimension(input.Component) || (input.Outcome != "unchanged" && input.Outcome != "changed" && input.Outcome != "uncertain") || !resourceIDPattern.MatchString(input.RequestID) || !resourceIDPattern.MatchString(input.CorrelationID) {
		return ErrorResource{}, newError(ErrorInvalidEvent, "construct error resource")
	}
	result := ErrorResource{Schema: ContractSchemaV1, Kind: KindError, Code: input.Code, Component: input.Component, Message: message, Outcome: input.Outcome, Retryable: input.Retryable, RepairAction: repair, RequestID: input.RequestID, CorrelationID: input.CorrelationID}
	if !input.RetryAt.IsZero() {
		retryAt := normalizeTime(input.RetryAt)
		result.RetryAt = &retryAt
	}
	return result, result.Validate()
}

func (e ErrorResource) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindError || !stableCodePattern.MatchString(e.Code) || !validDimension(e.Component) || (e.Outcome != "unchanged" && e.Outcome != "changed" && e.Outcome != "uncertain") || e.Message == "" || e.RepairAction == "" || !resourceIDPattern.MatchString(e.RequestID) || !resourceIDPattern.MatchString(e.CorrelationID) {
		return newError(ErrorInvalidEvent, "validate error resource")
	}
	return nil
}

func (e ErrorResource) JSON() ([]byte, error) { return json.Marshal(e) }

func ProjectEventResource(event Event, binding EventResourceBinding) (EventResource, error) {
	if event.Schema != EventSchemaV1 || !stableCodePattern.MatchString(event.Name) || !validWireValue(event.CorrelationID, 3, 128) || event.At.IsZero() {
		return EventResource{}, newError(ErrorInvalidEvent, "project edge event resource")
	}
	if !validEventResourceKind(binding.ResourceKind) || !validWireValue(binding.ID, 3, 128) || !validWireValue(binding.Cursor, 1, 1000) || !validWireValue(binding.ResourceID, 3, 128) || !validActorType(binding.Actor.Type) || !validWireValue(binding.Actor.ID, 3, 128) {
		return EventResource{}, newError(ErrorInvalidID, "project edge event resource")
	}
	metadata := make(map[string]any, 14)
	addSafeMetadata(metadata, "account_id", event.IDs.AccountID)
	addSafeMetadata(metadata, "actor_id", event.IDs.ActorID)
	addSafeMetadata(metadata, "tunnel_id", event.IDs.TunnelID)
	addSafeMetadata(metadata, "route_id", event.IDs.RouteID)
	addSafeMetadata(metadata, "connector_id", event.IDs.ConnectorID)
	addSafeMetadata(metadata, "domain_id", event.IDs.DomainID)
	addSafeMetadata(metadata, "session_id", event.IDs.SessionID)
	addSafeMetadata(metadata, "operation_id", event.IDs.OperationID)
	addSafeMetadata(metadata, "request_id", event.IDs.RequestID)
	addSafeMetadata(metadata, "edge_node_id", event.IDs.EdgeNodeID)
	addSafeMetadata(metadata, "certificate_id", event.IDs.CertificateID)
	addSafeMetadata(metadata, "assignment_id", event.IDs.AssignmentID)
	addSafeMetadata(metadata, "host_id", event.IDs.HostID)
	addSafeMetadata(metadata, "device_id", event.IDs.DeviceID)
	addGenerationMetadata(metadata, "config_generation", event.Generations.Config)
	addGenerationMetadata(metadata, "route_generation", event.Generations.Route)
	addGenerationMetadata(metadata, "assignment_generation", event.Generations.Assignment)
	addGenerationMetadata(metadata, "connector_generation", event.Generations.Connector)
	addGenerationMetadata(metadata, "process_generation", event.Generations.Process)
	addGenerationMetadata(metadata, "session_generation", event.Generations.Session)
	metadata, err := safeMetadata(metadata)
	if err != nil {
		return EventResource{}, err
	}
	// Structured opaque IDs are explicitly safe and remain useful to callers.
	// The free-form redaction policy still applies to every other metadata
	// value, including text that happens to contain an ID-looking token.
	restoreSafeIDMetadata(metadata, event.IDs)
	result := EventResource{
		Schema: ContractSchemaV1, Kind: KindEvent, ID: binding.ID, Cursor: binding.Cursor,
		EventType: event.Name, ResourceKind: binding.ResourceKind, ResourceID: binding.ResourceID,
		OccurredAt: normalizeTime(event.At), Actor: binding.Actor, CorrelationID: event.CorrelationID,
		SafeMetadata: metadata,
	}
	return result, result.Validate()
}

func restoreSafeIDMetadata(metadata map[string]any, ids SafeIDs) {
	for name, value := range map[string]string{
		"account_id": ids.AccountID, "actor_id": ids.ActorID, "tunnel_id": ids.TunnelID,
		"route_id": ids.RouteID, "connector_id": ids.ConnectorID, "domain_id": ids.DomainID,
		"certificate_id": ids.CertificateID, "assignment_id": ids.AssignmentID, "host_id": ids.HostID,
		"device_id": ids.DeviceID, "session_id": ids.SessionID, "operation_id": ids.OperationID,
		"request_id": ids.RequestID, "edge_node_id": ids.EdgeNodeID,
	} {
		if value != "" {
			metadata[name] = value
		}
	}
}

func validHealthResourceKind(value string) bool {
	_, ok := healthResourceKindSet[value]
	return ok
}

func validEventResourceKind(value string) bool {
	return validHealthResourceKind(value) || value == "config_generation" || value == "operation"
}

func validActorType(value string) bool {
	_, ok := actorTypeSet[value]
	return ok
}

func validWireValue(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func safeMetadata(input map[string]any) (map[string]any, error) {
	if len(input) > 64 {
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
	result, err := sanitizeMetadataMap(input, 0)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func sanitizeMetadataMap(input map[string]any, depth int) (map[string]any, error) {
	if depth > 8 || len(input) > 64 {
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
	result := make(map[string]any, len(input))
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" || len(key) > 128 || metadataKeyPattern.MatchString(key) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		value, err := sanitizeMetadataValue(input[key], depth+1)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func sanitizeMetadataValue(value any, depth int) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return safeBoundedString(typed, 1000, false)
	case bool:
		return typed, nil
	case int:
		return typed, nil
	case int8:
		return typed, nil
	case int16:
		return typed, nil
	case int32:
		return typed, nil
	case int64:
		return typed, nil
	case uint:
		return typed, nil
	case uint8:
		return typed, nil
	case uint16:
		return typed, nil
	case uint32:
		return typed, nil
	case uint64:
		return typed, nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		return typed, nil
	case []any:
		if len(typed) > 64 {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			clean, err := sanitizeMetadataValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = clean
		}
		return result, nil
	case map[string]any:
		return sanitizeMetadataMap(typed, depth)
	default:
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
}

func addSafeMetadata(metadata map[string]any, name, value string) {
	if value != "" {
		metadata[name] = value
	}
}

func addGenerationMetadata(metadata map[string]any, name string, value uint64) {
	if value != 0 {
		metadata[name] = value
	}
}
