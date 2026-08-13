package publicpreviewrelay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
)

const admissionHeader = "X-Paperboat-Connector-Admission"

var relayPreface = [...]byte{'P', 'B', 'P', 'R', 1}

const startupMarker byte = 0

type Handler struct {
	Manager       *Manager
	ObserveAttach func(carrier string)
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	carrier := request.Header.Get("X-Paperboat-Relay-Carrier")
	request.Header.Del("X-Paperboat-Relay-Carrier")
	slog.Info("public preview relay stage", "carrier", carrier, "stage", "request_received", "protocol", request.Proto)
	if h.Manager == nil || request.URL.Path != Path || request.URL.RawQuery != "" || request.Method != http.MethodPost || carrier != "HTTP/3.0" && carrier != "HTTP/2.0" || request.Header.Get("Content-Type") != "application/octet-stream" {
		http.NotFound(writer, request)
		return
	}
	encoded := request.Header.Get(admissionHeader)
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(payload) == 0 || len(payload) > 64<<10 || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var document struct {
		OperationID string `json:"operation_id"`
		Credential  string `json:"credential"`
		Environment string `json:"environment_id"`
		Machine     string `json:"machine_id"`
		Connector   string `json:"connector_id"`
		Generation  uint64 `json:"connector_generation"`
		EdgePool    string `json:"edge_pool"`
		EdgeNode    string `json:"edge_node_id"`
		Routes      []struct {
			RouteID    string `json:"route_id"`
			Revision   uint64 `json:"route_revision"`
			Kind       string `json:"kind"`
			PublicHost string `json:"public_host"`
			ProxyName  string `json:"proxy_name"`
			Target     struct {
				Host string `json:"host"`
				Port uint16 `json:"port"`
			} `json:"target"`
		} `json:"routes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	routes := make([]admission.Route, len(document.Routes))
	for index, item := range document.Routes {
		routes[index] = admission.Route{RouteID: item.RouteID, Revision: item.Revision, Kind: item.Kind, PublicHost: item.PublicHost, ProxyName: item.ProxyName, TargetHost: item.Target.Host, TargetPort: item.Target.Port}
	}
	slog.Info("public preview relay stage", "carrier", carrier, "stage", "admission_started")
	response, err := h.Manager.Admit(request.Context(), admission.Request{OperationID: document.OperationID, Credential: document.Credential, Environment: document.Environment, Machine: document.Machine, Connector: document.Connector, Generation: document.Generation, EdgePool: document.EdgePool, EdgeNode: document.EdgeNode, Routes: routes})
	if err != nil {
		slog.Warn("public preview relay stage", "carrier", carrier, "stage", "admission_failed", "error", err)
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	slog.Info("public preview relay stage", "carrier", carrier, "stage", "admitted")
	var preface [len(relayPreface)]byte
	if _, err := io.ReadFull(request.Body, preface[:]); err != nil || preface != relayPreface {
		slog.Warn("public preview relay stage", "carrier", carrier, "stage", "preface_failed", "error", err)
		return
	}
	slog.Info("public preview relay stage", "carrier", carrier, "stage", "preface_valid")
	var marker [1]byte
	if _, err := io.ReadFull(request.Body, marker[:]); err != nil || marker[0] != startupMarker {
		return
	}
	controller := http.NewResponseController(writer)
	if err := controller.EnableFullDuplex(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		return
	}
	slog.Info("public preview relay stage", "carrier", carrier, "stage", "response_flushed")
	if h.ObserveAttach != nil {
		h.ObserveAttach(carrier)
	}
	stream := &httpStream{reader: request.Body, writer: writer, flush: controller.Flush}
	_ = h.Manager.Attach(request.Context(), response, stream)
}

type httpStream struct {
	reader io.ReadCloser
	writer io.Writer
	flush  func() error
	mu     sync.Mutex
}

func (s *httpStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *httpStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.writer.Write(p)
	if err == nil {
		err = s.flush()
	}
	return n, err
}
func (s *httpStream) Close() error { return s.reader.Close() }
