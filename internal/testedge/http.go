package testedge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/usage"
)

const maxHTTPDocument = 1 << 20

type Handler struct {
	Fake       *Fake
	Credential string
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Fake == nil || len(h.Credential) < 32 || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+h.Credential || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.NotFound(w, r)
		return
	}
	var err error
	switch r.URL.Path {
	case "/v1/edge/assignments/current":
		var request struct {
			Environment string `json:"environment_id"`
			Machine     string `json:"machine_id"`
			Connector   string `json:"connector_id"`
		}
		if !decodeHTTP(r, &request) {
			break
		}
		current, currentErr := h.Fake.Current(r.Context(), request.Environment, request.Machine, request.Connector)
		err = currentErr
		if err == nil {
			writeHTTP(w, map[string]any{"connector_generation": current.Generation, "edge_pool": current.EdgePool, "edge_node_id": current.EdgeNode, "revoked": current.Revoked})
			return
		}
	case "/v1/edge/usage-reports":
		type wire struct {
			OperationID string          `json:"operation_id"`
			Node        string          `json:"edge_node_id"`
			Epoch       string          `json:"counter_epoch"`
			Environment string          `json:"environment_id"`
			Route       string          `json:"route_id"`
			Revision    uint64          `json:"route_revision"`
			Direction   string          `json:"direction"`
			Bytes       uint64          `json:"bytes"`
			Start       time.Time       `json:"interval_start"`
			End         time.Time       `json:"interval_end"`
			Payload     json.RawMessage `json:"signed_payload,omitempty"`
		}
		var input wire
		if !decodeHTTP(r, &input) {
			break
		}
		result, reportErr := h.Fake.ReportUsage(r.Context(), control.UsageReport{OperationID: input.OperationID, Key: usage.Key{Node: input.Node, Epoch: input.Epoch, Environment: input.Environment, Route: input.Route, Revision: input.Revision, Direction: input.Direction}, Bytes: input.Bytes, Interval: [2]time.Time{input.Start, input.End}, Payload: append([]byte(nil), input.Payload...)})
		err = reportErr
		if err == nil {
			writeHTTP(w, result)
			return
		}
	case "/v1/nodes/register":
		var request control.NodeRegistration
		if decodeHTTP(r, &request) {
			err = h.Fake.RegisterNode(r.Context(), request)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
	case "/v1/nodes/heartbeat":
		var request control.NodeObservation
		if decodeHTTP(r, &request) {
			err = h.Fake.Heartbeat(r.Context(), request)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
	case "/v1/edge/routes/desired-state":
		var request struct {
			NodeID string `json:"edge_node_id"`
		}
		if !decodeHTTP(r, &request) {
			break
		}
		routes, routeErr := h.Fake.DesiredRoutes(r.Context(), request.NodeID)
		if routeErr == nil {
			items := make([]map[string]any, 0, len(routes))
			for _, route := range routes {
				items = append(items, map[string]any{"route_id": route.RouteID, "route_revision": route.Revision, "environment_id": route.Environment, "connector_generation": route.Generation, "edge_node_id": route.NodeID, "kind": route.Kind, "public_host": route.PublicHost, "target": map[string]any{"host": route.TargetHost, "port": route.TargetPort}})
			}
			writeHTTP(w, map[string]any{"routes": items})
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	http.Error(w, "request rejected", http.StatusBadRequest)
}

func decodeHTTP(r *http.Request, target any) bool {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPDocument+1))
	if err != nil || len(data) > maxHTTPDocument {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func writeHTTP(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
