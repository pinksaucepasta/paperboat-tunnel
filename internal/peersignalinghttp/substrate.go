package peersignalinghttp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/peersignaling"
)

const (
	SubstrateSubprotocol = "paperboat.peer-signaling-substrate.v1"
	substrateHeaderSize  = 10
	substrateMaxChannels = 256
)

type substrateKind uint8

const (
	substrateAttach substrateKind = iota + 1
	substrateReady
	substrateData
	substrateComplete
	substrateAbort
	substrateRejected
)

type substrateFrame struct {
	kind    substrateKind
	channel uint64
	body    []byte
}

type substrateAttachment struct {
	value  *peersignaling.Attachment
	cancel context.CancelFunc
}

func (h Handler) serveSubstrate(writer http.ResponseWriter, request *http.Request) {
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{SubstrateSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	connection.SetReadLimit(substrateHeaderSize + MaximumMessage)
	runCtx, cancel := context.WithCancel(request.Context())
	defer cancel()
	var writeMu sync.Mutex
	write := func(frame substrateFrame) error {
		raw, encodeErr := encodeSubstrate(frame)
		if encodeErr != nil {
			return encodeErr
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return connection.Write(runCtx, websocket.MessageBinary, raw)
	}
	attachments := make(map[uint64]substrateAttachment)
	var attachmentsMu sync.Mutex
	closeChannel := func(channel uint64, complete bool) {
		attachmentsMu.Lock()
		owned, ok := attachments[channel]
		delete(attachments, channel)
		attachmentsMu.Unlock()
		if !ok {
			return
		}
		owned.cancel()
		if complete {
			_ = owned.value.Complete()
		} else {
			_ = owned.value.Close()
		}
	}
	defer func() {
		attachmentsMu.Lock()
		owned := attachments
		attachments = make(map[uint64]substrateAttachment)
		attachmentsMu.Unlock()
		for _, attachment := range owned {
			attachment.cancel()
			_ = attachment.value.Close()
		}
		_ = connection.CloseNow()
	}()
	for {
		messageType, raw, readErr := connection.Read(runCtx)
		if readErr != nil {
			if websocket.CloseStatus(readErr) != websocket.StatusNormalClosure {
				h.observe(readErr)
			}
			return
		}
		if messageType != websocket.MessageBinary {
			h.observe(errMessageType)
			return
		}
		frame, decodeErr := decodeSubstrate(raw)
		if decodeErr != nil {
			h.observe(decodeErr)
			return
		}
		switch frame.kind {
		case substrateAttach:
			attachmentsMu.Lock()
			_, duplicate := attachments[frame.channel]
			full := len(attachments) >= substrateMaxChannels
			attachmentsMu.Unlock()
			if duplicate || full {
				_ = write(substrateFrame{kind: substrateRejected, channel: frame.channel})
				continue
			}
			attachment, attachErr := h.Service.Attach(runCtx, string(frame.body))
			if attachErr != nil {
				_ = write(substrateFrame{kind: substrateRejected, channel: frame.channel})
				continue
			}
			channelCtx, channelCancel := context.WithCancel(runCtx)
			attachmentsMu.Lock()
			attachments[frame.channel] = substrateAttachment{value: attachment, cancel: channelCancel}
			attachmentsMu.Unlock()
			if writeErr := write(substrateFrame{kind: substrateReady, channel: frame.channel}); writeErr != nil {
				closeChannel(frame.channel, false)
				return
			}
			go func(channel uint64, value *peersignaling.Attachment, channelCtx context.Context) {
				for {
					payload, receiveErr := value.Receive(channelCtx)
					if receiveErr != nil {
						return
					}
					if writeErr := write(substrateFrame{kind: substrateData, channel: channel, body: payload}); writeErr != nil {
						cancel()
						return
					}
				}
			}(frame.channel, attachment, channelCtx)
		case substrateData:
			attachmentsMu.Lock()
			owned, ok := attachments[frame.channel]
			attachmentsMu.Unlock()
			if !ok || owned.value.Send(runCtx, frame.body) != nil {
				_ = write(substrateFrame{kind: substrateAbort, channel: frame.channel})
				closeChannel(frame.channel, false)
			}
		case substrateComplete:
			closeChannel(frame.channel, true)
		case substrateAbort:
			closeChannel(frame.channel, false)
		default:
			h.observe(errors.New("invalid client signaling substrate frame"))
			return
		}
	}
}

func encodeSubstrate(frame substrateFrame) ([]byte, error) {
	if frame.channel == 0 || !validSubstrate(frame.kind, frame.body) {
		return nil, errors.New("invalid signaling substrate frame")
	}
	raw := make([]byte, substrateHeaderSize+len(frame.body))
	raw[0], raw[1] = 1, byte(frame.kind)
	binary.BigEndian.PutUint64(raw[2:10], frame.channel)
	copy(raw[10:], frame.body)
	return raw, nil
}

func decodeSubstrate(raw []byte) (substrateFrame, error) {
	if len(raw) < substrateHeaderSize || len(raw) > substrateHeaderSize+MaximumMessage || raw[0] != 1 {
		return substrateFrame{}, errors.New("invalid signaling substrate frame")
	}
	frame := substrateFrame{kind: substrateKind(raw[1]), channel: binary.BigEndian.Uint64(raw[2:10]), body: append([]byte(nil), raw[10:]...)}
	if frame.channel == 0 || !validSubstrate(frame.kind, frame.body) {
		return substrateFrame{}, errors.New("invalid signaling substrate frame")
	}
	return frame, nil
}

func validSubstrate(kind substrateKind, body []byte) bool {
	switch kind {
	case substrateAttach:
		return len(body) > 0 && len(body) <= 8<<10
	case substrateData:
		return len(body) > 0 && len(body) <= MaximumMessage
	case substrateReady, substrateComplete, substrateAbort, substrateRejected:
		return len(body) == 0
	default:
		return false
	}
}
