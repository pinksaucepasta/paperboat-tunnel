// Package certbroker contains the private, bounded wire format shared by the
// tunnel runtime and the custom Caddy certificate manager.  It is deliberately
// not an HTTP or public API: the Unix socket is created with mode 0600 inside a
// 0700 runtime directory and carries key material only in memory.
package certbroker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

const (
	Version           = 1
	MaximumRequest    = 4 << 10
	MaximumResponse   = 16 << 20
	MaximumServerName = 253
)

var (
	ErrInvalid     = errors.New("invalid certificate broker message")
	ErrUnavailable = errors.New("certificate broker unavailable")
)

// Request asks the runtime for the certificate selected for one SNI value.
// No client-provided identity or certificate data is accepted here.
type Request struct {
	Version    int    `json:"version"`
	ServerName string `json:"server_name"`
}

// Response is returned only over the private broker socket.  PEM values must
// never be logged, persisted, or copied into an API/audit structure.
type Response struct {
	Version        int    `json:"version"`
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  []byte `json:"private_key_pem,omitempty"`
}

func ValidateRequest(request Request) error {
	if request.Version != Version || !ValidServerName(request.ServerName) {
		return ErrInvalid
	}
	return nil
}

func ValidateResponse(response Response) error {
	if response.Version != Version {
		return ErrInvalid
	}
	if response.OK {
		if len(response.CertificatePEM) == 0 || len(response.CertificatePEM) > MaximumResponse || len(response.PrivateKeyPEM) == 0 || len(response.PrivateKeyPEM) > MaximumResponse || response.Error != "" {
			return ErrInvalid
		}
		return nil
	}
	if len(response.CertificatePEM) != 0 || len(response.PrivateKeyPEM) != 0 || response.Error == "" || len(response.Error) > 128 || strings.ContainsAny(response.Error, "\r\n\x00") {
		return ErrInvalid
	}
	return nil
}

func ValidServerName(serverName string) bool {
	if serverName == "" || strings.TrimSpace(serverName) != serverName {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(serverName, "."))
	if host == "" || len(host) > MaximumServerName || strings.ContainsAny(host, "/:@?#\r\n\x00") {
		return false
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if host == "" || len(host) > MaximumServerName || strings.HasPrefix(host, "*.") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return strings.Contains(host, ".")
}

// Write writes one length-prefixed JSON message.  The maximum includes the
// encoded JSON and is checked before any bytes are sent.
func Write(writer io.Writer, value any, maximum int) error {
	if writer == nil || maximum <= 0 || maximum > MaximumResponse {
		return ErrInvalid
	}
	payload, err := json.Marshal(value)
	if err == nil {
		defer clear(payload)
	}
	if err != nil || len(payload) == 0 || len(payload) > maximum || len(payload) > int(^uint32(0)) {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err = writer.Write(payload)
	return err
}

// Read reads and strictly decodes one length-prefixed JSON message.
func Read(reader io.Reader, target any, maximum int) error {
	if reader == nil || target == nil || maximum <= 0 || maximum > MaximumResponse {
		return ErrInvalid
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || uint64(length) > uint64(maximum) {
		return fmt.Errorf("%w: frame exceeds bound", ErrInvalid)
	}
	payload := make([]byte, int(length))
	defer clear(payload)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: JSON: %v", ErrInvalid, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	return nil
}

func clear(values []byte) {
	for index := range values {
		values[index] = 0
	}
}
