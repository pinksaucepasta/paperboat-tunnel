package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"sync"
	"time"
)

// HealthSchemaV1 is shared with the control plane so one decoder can consume
// health from either side of the product.
const HealthSchemaV1 = "paperboat.health/v1"

type Dimension string

const (
	DimensionService     Dimension = "service"
	DimensionEdge        Dimension = "edge"
	DimensionConfig      Dimension = "config"
	DimensionRoute       Dimension = "route"
	DimensionOrigin      Dimension = "origin"
	DimensionDNS         Dimension = "dns"
	DimensionCertificate Dimension = "certificate"
	DimensionAccess      Dimension = "access"
	DimensionUpdate      Dimension = "update"
)

var dimensionOrder = []Dimension{
	DimensionService,
	DimensionEdge,
	DimensionConfig,
	DimensionRoute,
	DimensionOrigin,
	DimensionDNS,
	DimensionCertificate,
	DimensionAccess,
	DimensionUpdate,
}

// Dimensions returns the canonical order used in JSON, metrics and overall
// tie-breaking. The returned slice is independent of package state.
func Dimensions() []Dimension { return append([]Dimension(nil), dimensionOrder...) }

type HealthStatus string

const (
	StatusUnknown       HealthStatus = "unknown"
	StatusReady         HealthStatus = "ready"
	StatusDegraded      HealthStatus = "degraded"
	StatusDown          HealthStatus = "down"
	StatusNotApplicable HealthStatus = "not_applicable"
)

type RetryDecision string

const (
	RetryNone          RetryDecision = "none"
	RetryScheduled     RetryDecision = "scheduled"
	RetryWaitForChange RetryDecision = "wait_for_change"
	RetryNotRetryable  RetryDecision = "not_retryable"
)

var stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type HealthUpdate struct {
	Dimension     Dimension
	Status        HealthStatus
	Code          string
	Summary       string
	RepairAction  string
	CorrelationID string
	Retry         RetryDecision
	NextRetryAt   time.Time
}

type DimensionHealth struct {
	Status        HealthStatus  `json:"status"`
	Code          string        `json:"code"`
	Since         time.Time     `json:"since"`
	BrokenSince   *time.Time    `json:"broken_since,omitempty"`
	Summary       string        `json:"summary"`
	RepairAction  string        `json:"repair_action"`
	CorrelationID string        `json:"correlation_id,omitempty"`
	Retry         RetryDecision `json:"retry"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`
	SuppressedBy  Dimension     `json:"suppressed_by,omitempty"`
}

type HealthDimensions struct {
	Service     DimensionHealth `json:"service"`
	Edge        DimensionHealth `json:"edge"`
	Config      DimensionHealth `json:"config"`
	Route       DimensionHealth `json:"route"`
	Origin      DimensionHealth `json:"origin"`
	DNS         DimensionHealth `json:"dns"`
	Certificate DimensionHealth `json:"certificate"`
	Access      DimensionHealth `json:"access"`
	Update      DimensionHealth `json:"update"`
}

func (d HealthDimensions) Get(dimension Dimension) DimensionHealth {
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
		return DimensionHealth{}
	}
}

func (d *HealthDimensions) set(dimension Dimension, value DimensionHealth) {
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

type OverallHealth struct {
	Status        HealthStatus  `json:"status"`
	Code          string        `json:"code"`
	Dimension     Dimension     `json:"dimension,omitempty"`
	Since         time.Time     `json:"since"`
	BrokenSince   *time.Time    `json:"broken_since,omitempty"`
	Summary       string        `json:"summary"`
	RepairAction  string        `json:"repair_action"`
	CorrelationID string        `json:"correlation_id,omitempty"`
	Retry         RetryDecision `json:"retry"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`
}

type HealthSnapshot struct {
	Schema     string           `json:"schema"`
	UpdatedAt  time.Time        `json:"updated_at"`
	Overall    OverallHealth    `json:"overall"`
	Dimensions HealthDimensions `json:"dimensions"`
	ETag       string           `json:"etag"`
}

func (s HealthSnapshot) JSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// Validate checks the complete internal v1 snapshot before it is exported.
func (s HealthSnapshot) Validate() error {
	if s.Schema != HealthSchemaV1 || normalizeTime(s.UpdatedAt).IsZero() || !validHealthStatus(s.Overall.Status) || !stableCodePattern.MatchString(s.Overall.Code) || normalizeTime(s.Overall.Since).IsZero() || !storedSafeText(s.Overall.Summary, maximumSummaryBytes) || !storedSafeText(s.Overall.RepairAction, maximumRepairBytes) || !validRetry(s.Overall.Retry, timeValue(s.Overall.NextRetryAt)) {
		return newError(ErrorInvalidObservation, "validate edge health")
	}
	if s.Overall.Dimension != "" && !validDimension(s.Overall.Dimension) {
		return newError(ErrorInvalidDimension, "validate edge health")
	}
	if s.Overall.CorrelationID != "" && !validCorrelationID(s.Overall.CorrelationID) {
		return newError(ErrorInvalidID, "validate edge health")
	}
	if isBroken(s.Overall.Status) != (s.Overall.BrokenSince != nil) {
		return newError(ErrorInvalidObservation, "validate edge health")
	}
	for _, dimension := range dimensionOrder {
		state := s.Dimensions.Get(dimension)
		if !validHealthStatus(state.Status) || !stableCodePattern.MatchString(state.Code) || normalizeTime(state.Since).IsZero() || !storedSafeText(state.Summary, maximumSummaryBytes) || !storedSafeText(state.RepairAction, maximumRepairBytes) || !validRetry(state.Retry, timeValue(state.NextRetryAt)) {
			return newError(ErrorInvalidObservation, "validate edge health")
		}
		if state.CorrelationID != "" && !validCorrelationID(state.CorrelationID) {
			return newError(ErrorInvalidID, "validate edge health")
		}
		if state.SuppressedBy != "" && (!validDimension(state.SuppressedBy) || state.SuppressedBy == dimension) {
			return newError(ErrorInvalidDimension, "validate edge health")
		}
		if isBroken(state.Status) != (state.BrokenSince != nil) {
			return newError(ErrorInvalidObservation, "validate edge health")
		}
	}
	if !etagPattern.MatchString(s.ETag) {
		return newError(ErrorInvalidObservation, "validate edge health")
	}
	return nil
}

var etagPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func storedSafeText(value string, maximum int) bool {
	clean, err := safeBoundedString(value, maximum, true)
	return err == nil && clean == value
}

// Alert is a safe, actionable projection suitable for a pager or notification
// adapter. It contains no raw provider or request data.
type Alert struct {
	At            time.Time     `json:"at"`
	Dimension     Dimension     `json:"dimension"`
	Status        HealthStatus  `json:"status"`
	Code          string        `json:"code"`
	BrokenSince   *time.Time    `json:"broken_since,omitempty"`
	Summary       string        `json:"summary"`
	RepairAction  string        `json:"repair_action"`
	CorrelationID string        `json:"correlation_id,omitempty"`
	Retry         RetryDecision `json:"retry"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`
	Correlation   string        `json:"-"`
}

// AlertFor returns an immutable-safe alert projection for one dimension.
func (s HealthSnapshot) AlertFor(dimension Dimension) (Alert, bool) {
	if !validDimension(dimension) {
		return Alert{}, false
	}
	state := s.Dimensions.Get(dimension)
	if state.SuppressedBy != "" || state.Status == StatusReady || state.Status == StatusNotApplicable {
		return Alert{}, false
	}
	return Alert{At: s.UpdatedAt, Dimension: dimension, Status: state.Status, Code: state.Code, BrokenSince: cloneTime(state.BrokenSince), Summary: state.Summary, RepairAction: state.RepairAction, CorrelationID: state.CorrelationID, Correlation: state.CorrelationID, Retry: state.Retry, NextRetryAt: cloneTime(state.NextRetryAt)}, true
}

// Alerts returns only deterministic actionable root alerts. Failures hidden by
// a down dependency are omitted so operators receive one repair target.
func (s HealthSnapshot) Alerts() []Alert {
	alerts := make([]Alert, 0, len(dimensionOrder))
	for _, dimension := range dimensionOrder {
		if alert, ok := s.AlertFor(dimension); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

type HealthTracker struct {
	mu        sync.RWMutex
	now       func() time.Time
	updatedAt time.Time
	states    HealthDimensions
}

func NewHealthTracker(now func() time.Time) (*HealthTracker, error) {
	if now == nil {
		now = time.Now
	}
	at := normalizeTime(now())
	if at.IsZero() {
		return nil, newError(ErrorInvalidTime, "construct control-plane health tracker")
	}
	unknown := DimensionHealth{
		Status:       StatusUnknown,
		Code:         "not_observed",
		Since:        at,
		Summary:      "Health has not been observed.",
		RepairAction: "Wait for the first health observation.",
		Retry:        RetryNone,
	}
	states := HealthDimensions{}
	for _, dimension := range dimensionOrder {
		states.set(dimension, unknown)
	}
	return &HealthTracker{now: now, updatedAt: at, states: states}, nil
}

func (t *HealthTracker) Update(update HealthUpdate) error {
	if t == nil {
		return newError(ErrorInvalidObservation, "update control-plane health")
	}
	prepared, err := prepareHealthUpdate(update)
	if err != nil {
		return err
	}
	at := normalizeTime(t.now())
	if at.IsZero() {
		return newError(ErrorInvalidTime, "update control-plane health")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	previous := t.states.Get(update.Dimension)
	next := DimensionHealth{
		Status:        prepared.Status,
		Code:          prepared.Code,
		Since:         at,
		Summary:       prepared.Summary,
		RepairAction:  prepared.RepairAction,
		CorrelationID: prepared.CorrelationID,
		Retry:         prepared.Retry,
	}
	if !prepared.NextRetryAt.IsZero() {
		nextRetry := normalizeTime(prepared.NextRetryAt)
		next.NextRetryAt = &nextRetry
	}
	if previous.Status == next.Status && previous.Code == next.Code {
		next.Since = previous.Since
	}
	if isBroken(next.Status) {
		brokenAt := at
		if previous.BrokenSince != nil {
			brokenAt = *previous.BrokenSince
		}
		next.BrokenSince = &brokenAt
	}
	if dimensionHealthEqual(previous, next) {
		return nil
	}
	t.states.set(update.Dimension, next)
	t.updatedAt = at
	return nil
}

func (t *HealthTracker) Snapshot() HealthSnapshot {
	if t == nil {
		return HealthSnapshot{}
	}
	t.mu.RLock()
	states := cloneHealthDimensions(t.states)
	updatedAt := t.updatedAt
	t.mu.RUnlock()

	states = suppressDependencies(states)
	snapshot := HealthSnapshot{
		Schema:     HealthSchemaV1,
		UpdatedAt:  updatedAt,
		Overall:    projectOverall(states, updatedAt),
		Dimensions: states,
	}
	withoutETag, _ := json.Marshal(snapshot)
	digest := sha256.Sum256(withoutETag)
	snapshot.ETag = "sha256:" + hex.EncodeToString(digest[:])
	return snapshot
}

func cloneHealthDimensions(states HealthDimensions) HealthDimensions {
	for _, dimension := range dimensionOrder {
		state := states.Get(dimension)
		state.BrokenSince = cloneTime(state.BrokenSince)
		state.NextRetryAt = cloneTime(state.NextRetryAt)
		states.set(dimension, state)
	}
	return states
}

func prepareHealthUpdate(update HealthUpdate) (HealthUpdate, error) {
	if !validDimension(update.Dimension) {
		return HealthUpdate{}, newError(ErrorInvalidDimension, "update control-plane health")
	}
	if !validHealthStatus(update.Status) {
		return HealthUpdate{}, newError(ErrorInvalidStatus, "update control-plane health")
	}
	if !stableCodePattern.MatchString(update.Code) {
		return HealthUpdate{}, newError(ErrorInvalidCode, "update control-plane health")
	}
	if !validRetry(update.Retry, update.NextRetryAt) {
		return HealthUpdate{}, newError(ErrorInvalidRetry, "update control-plane health")
	}
	summary, err := safeBoundedString(update.Summary, maximumSummaryBytes, true)
	if err != nil {
		return HealthUpdate{}, err
	}
	repair, err := safeBoundedString(update.RepairAction, maximumRepairBytes, true)
	if err != nil {
		return HealthUpdate{}, err
	}
	if update.CorrelationID != "" && !validCorrelationID(update.CorrelationID) {
		return HealthUpdate{}, newError(ErrorInvalidID, "update control-plane health")
	}
	update.Summary = summary
	update.RepairAction = repair
	update.NextRetryAt = normalizeTime(update.NextRetryAt)
	return update, nil
}

func validDimension(value Dimension) bool {
	for _, dimension := range dimensionOrder {
		if value == dimension {
			return true
		}
	}
	return false
}

func validHealthStatus(value HealthStatus) bool {
	return value == StatusUnknown || value == StatusReady || value == StatusDegraded || value == StatusDown || value == StatusNotApplicable
}

func validRetry(decision RetryDecision, next time.Time) bool {
	switch decision {
	case RetryScheduled:
		return !next.IsZero()
	case RetryNone, RetryWaitForChange, RetryNotRetryable:
		return next.IsZero()
	default:
		return false
	}
}

func isBroken(status HealthStatus) bool { return status == StatusDegraded || status == StatusDown }

func normalizeTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}

func dimensionHealthEqual(left, right DimensionHealth) bool {
	left.SuppressedBy, right.SuppressedBy = "", ""
	return left.Status == right.Status && left.Code == right.Code && left.Since.Equal(right.Since) &&
		timesEqual(left.BrokenSince, right.BrokenSince) && left.Summary == right.Summary &&
		left.RepairAction == right.RepairAction && left.CorrelationID == right.CorrelationID &&
		left.Retry == right.Retry && timesEqual(left.NextRetryAt, right.NextRetryAt)
}

func timesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

var dimensionDependencies = map[Dimension][]Dimension{
	DimensionEdge:        {DimensionService},
	DimensionConfig:      {DimensionService},
	DimensionRoute:       {DimensionService, DimensionEdge, DimensionConfig},
	DimensionOrigin:      {DimensionService, DimensionEdge, DimensionConfig, DimensionRoute},
	DimensionDNS:         {DimensionService, DimensionEdge, DimensionConfig, DimensionRoute},
	DimensionCertificate: {DimensionService, DimensionEdge, DimensionConfig, DimensionRoute, DimensionDNS},
	DimensionAccess:      {DimensionService, DimensionEdge, DimensionConfig, DimensionRoute},
	DimensionUpdate:      {DimensionService},
}

func suppressDependencies(states HealthDimensions) HealthDimensions {
	for _, dimension := range dimensionOrder {
		state := states.Get(dimension)
		for _, dependency := range dimensionDependencies[dimension] {
			dependencyState := states.Get(dependency)
			if dependencyState.Status == StatusDown {
				state.SuppressedBy = dependency
				break
			}
		}
		states.set(dimension, state)
	}
	return states
}

func projectOverall(states HealthDimensions, updatedAt time.Time) OverallHealth {
	type candidate struct {
		dimension Dimension
		state     DimensionHealth
		severity  int
		priority  int
	}
	candidates := make([]candidate, 0, len(dimensionOrder))
	for priority, dimension := range dimensionOrder {
		state := states.Get(dimension)
		if state.SuppressedBy != "" || state.Status == StatusReady || state.Status == StatusNotApplicable {
			continue
		}
		severity := map[HealthStatus]int{StatusUnknown: 1, StatusDegraded: 2, StatusDown: 3}[state.Status]
		candidates = append(candidates, candidate{dimension: dimension, state: state, severity: severity, priority: priority})
	}
	if len(candidates) == 0 {
		return OverallHealth{
			Status:       StatusReady,
			Code:         "ready",
			Since:        updatedAt,
			Summary:      "All applicable control-plane health dimensions are ready.",
			RepairAction: "No action is required.",
			Retry:        RetryNone,
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].severity != candidates[j].severity {
			return candidates[i].severity > candidates[j].severity
		}
		return candidates[i].priority < candidates[j].priority
	})
	selected := candidates[0]
	return OverallHealth{
		Status:        selected.state.Status,
		Code:          selected.state.Code,
		Dimension:     selected.dimension,
		Since:         selected.state.Since,
		BrokenSince:   cloneTime(selected.state.BrokenSince),
		Summary:       selected.state.Summary,
		RepairAction:  selected.state.RepairAction,
		CorrelationID: selected.state.CorrelationID,
		Retry:         selected.state.Retry,
		NextRetryAt:   cloneTime(selected.state.NextRetryAt),
	}
}
