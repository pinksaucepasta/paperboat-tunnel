// Package relaypmtu defines the authenticated UDP probe protocol used to
// measure the path to a Paperboat relay.
package relaypmtu

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	MinimumSize = 1200
	MaximumSize = 1500
	headerSize  = 26
	tagSize     = sha256.Size
	version     = 1
	kindRequest = 1
	kindReply   = 2
)

var (
	magic      = [4]byte{'P', 'B', 'M', 'T'}
	ErrInvalid = errors.New("invalid relay PMTU frame")
	ErrAuth    = errors.New("relay PMTU authentication failed")
)

// BuildRequest creates an exact-size probe carrying a short-lived PMTU-only credential.
func BuildRequest(token string, size int) ([]byte, error) {
	if token == "" || len(token) > MaximumSize-headerSize-tagSize || size < MinimumSize || size > MaximumSize || headerSize+len(token)+tagSize > size {
		return nil, ErrInvalid
	}
	frame := make([]byte, size)
	copy(frame[:4], magic[:])
	frame[4] = version
	frame[5] = kindRequest
	binary.BigEndian.PutUint16(frame[6:8], uint16(size))
	if _, err := rand.Read(frame[8:24]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(frame[24:26], uint16(len(token)))
	copy(frame[headerSize:], token)
	return frame, nil
}

// IsRequest reports only whether a datagram is addressed to this protocol.
func IsRequest(frame []byte) bool {
	return len(frame) >= 6 && subtle.ConstantTimeCompare(frame[:4], magic[:]) == 1 && frame[4] == version && frame[5] == kindRequest
}

// Handle authenticates a request and returns an exact-size response.
func Handle(frame []byte, authenticate func(string) bool) ([]byte, error) {
	if authenticate == nil || !valid(frame, kindRequest) {
		return nil, ErrInvalid
	}
	tokenLength := int(binary.BigEndian.Uint16(frame[24:26]))
	if tokenLength == 0 || headerSize+tokenLength > len(frame) {
		return nil, ErrInvalid
	}
	if !authenticate(string(frame[headerSize : headerSize+tokenLength])) {
		return nil, ErrAuth
	}
	response := make([]byte, len(frame))
	copy(response, frame)
	response[5] = kindReply
	clear(response[24:26])
	clear(response[headerSize:])
	mac := hmac.New(sha256.New, []byte(string(frame[headerSize:headerSize+tokenLength])))
	_, _ = mac.Write(response[:len(response)-tagSize])
	copy(response[len(response)-tagSize:], mac.Sum(nil))
	return response, nil
}

// ParseResponse verifies that response matches the request nonce and exact size.
func ParseResponse(response, request []byte) error {
	if !valid(request, kindRequest) || !valid(response, kindReply) || len(response) != len(request) || subtle.ConstantTimeCompare(response[8:24], request[8:24]) != 1 {
		return ErrInvalid
	}
	tokenLength := int(binary.BigEndian.Uint16(request[24:26]))
	if tokenLength == 0 || headerSize+tokenLength+tagSize > len(request) {
		return ErrInvalid
	}
	mac := hmac.New(sha256.New, request[headerSize:headerSize+tokenLength])
	_, _ = mac.Write(response[:len(response)-tagSize])
	if !hmac.Equal(response[len(response)-tagSize:], mac.Sum(nil)) {
		return ErrAuth
	}
	return nil
}

func valid(frame []byte, kind byte) bool {
	return len(frame) >= MinimumSize && len(frame) <= MaximumSize &&
		subtle.ConstantTimeCompare(frame[:4], magic[:]) == 1 && frame[4] == version && frame[5] == kind &&
		int(binary.BigEndian.Uint16(frame[6:8])) == len(frame)
}
