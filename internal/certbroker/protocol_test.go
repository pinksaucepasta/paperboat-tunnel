package certbroker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type retainingWriter struct {
	header  []byte
	payload []byte
}

func (w *retainingWriter) Write(value []byte) (int, error) {
	if len(w.header) == 0 {
		w.header = value
	} else {
		w.payload = value
	}
	return len(value), nil
}

type retainingReader struct {
	data    []byte
	reads   int
	payload []byte
}

func (r *retainingReader) Read(value []byte) (int, error) {
	if r.reads == 0 {
		r.reads++
		copy(value, r.data[:4])
		return len(value), nil
	}
	r.reads++
	r.payload = value
	copy(value, r.data[4:])
	return len(value), nil
}

func TestWriteAndReadWipeFramingPayloadBuffers(t *testing.T) {
	message := Response{Version: Version, OK: true, CertificatePEM: []byte("certificate-private"), PrivateKeyPEM: []byte("key-private")}
	writer := new(retainingWriter)
	if err := Write(writer, message, MaximumResponse); err != nil {
		t.Fatal(err)
	}
	if len(writer.payload) == 0 || !allZero(writer.payload) {
		t.Fatalf("write payload was retained after return: %x", writer.payload)
	}

	var encoded bytes.Buffer
	if err := Write(&encoded, message, MaximumResponse); err != nil {
		t.Fatal(err)
	}
	frame := encoded.Bytes()
	reader := &retainingReader{data: frame}
	var decoded Response
	if err := Read(reader, &decoded, MaximumResponse); err != nil {
		t.Fatal(err)
	}
	if decoded.PrivateKeyPEM == nil || string(decoded.PrivateKeyPEM) != string(message.PrivateKeyPEM) {
		t.Fatalf("decoded response lost key: %q", decoded.PrivateKeyPEM)
	}
	if len(reader.payload) == 0 || !allZero(reader.payload) {
		t.Fatalf("read payload was retained after return: %x", reader.payload)
	}

	// Ensure the retained header was not mistaken for the sensitive JSON body.
	if len(writer.header) != 4 || binary.BigEndian.Uint32(writer.header) == 0 {
		t.Fatalf("invalid retained frame header: %x", writer.header)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
