package usage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

var ErrSignature = errors.New("usage report signature is invalid")

type SignedDocument struct {
	OperationID string    `json:"operation_id"`
	Key         Key       `json:"key"`
	Bytes       uint64    `json:"bytes"`
	Start       time.Time `json:"interval_start"`
	End         time.Time `json:"interval_end"`
}

type signedEnvelope struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewSignedReport(keyID string, private ed25519.PrivateKey, document SignedDocument) (Report, error) {
	if keyID == "" || len(private) != ed25519.PrivateKeySize || validateDocument(document) != nil {
		return Report{}, ErrSignature
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return Report{}, err
	}
	signature := ed25519.Sign(private, payload)
	envelope, err := json.Marshal(signedEnvelope{Algorithm: "EdDSA", KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		return Report{}, err
	}
	return Report{OperationID: document.OperationID, Key: document.Key, Bytes: document.Bytes, Interval: [2]time.Time{document.Start, document.End}, Payload: envelope}, nil
}

func VerifySignedReport(expectedKeyID string, public ed25519.PublicKey, envelopeBytes []byte) (SignedDocument, error) {
	if expectedKeyID == "" || len(public) != ed25519.PublicKeySize || len(envelopeBytes) == 0 || len(envelopeBytes) > 1<<20 {
		return SignedDocument{}, ErrSignature
	}
	var envelope signedEnvelope
	if err := strictDecode(envelopeBytes, &envelope); err != nil || envelope.Algorithm != "EdDSA" || envelope.KeyID != expectedKeyID {
		return SignedDocument{}, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return SignedDocument{}, ErrSignature
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(public, payload, signature) {
		return SignedDocument{}, ErrSignature
	}
	var document SignedDocument
	if err := strictDecode(payload, &document); err != nil || validateDocument(document) != nil {
		return SignedDocument{}, ErrSignature
	}
	return document, nil
}

func VerifySignedReportWithKeys(keys map[string]ed25519.PublicKey, envelopeBytes []byte) (SignedDocument, error) {
	var envelope signedEnvelope
	if err := strictDecode(envelopeBytes, &envelope); err != nil {
		return SignedDocument{}, ErrSignature
	}
	public, ok := keys[envelope.KeyID]
	if !ok {
		return SignedDocument{}, ErrSignature
	}
	return VerifySignedReport(envelope.KeyID, public, envelopeBytes)
}

func validateDocument(document SignedDocument) error {
	if document.OperationID == "" || document.Key.Node == "" || document.Key.Epoch == "" || document.Key.Environment == "" || document.Key.Route == "" || document.Key.Revision == 0 || (document.Key.Direction != "ingress" && document.Key.Direction != "egress") || document.Start.IsZero() || document.End.Before(document.Start) {
		return ErrSignature
	}
	return nil
}

func strictDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrSignature
	}
	return nil
}
