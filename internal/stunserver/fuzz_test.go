package stunserver

import (
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func FuzzHandleBindingDatagram(f *testing.F) {
	valid, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Raw)
	f.Add([]byte(nil))
	f.Add(make([]byte, 1201))

	f.Fuzz(func(t *testing.T, raw []byte) {
		server, err := New(Config{
			Address:                 "127.0.0.1:3478",
			Burst:                   2,
			RequestsPerSecond:       1,
			GlobalBurst:             2,
			GlobalRequestsPerSecond: 1,
			Now:                     func() time.Time { return time.Unix(100, 0) },
		})
		if err != nil {
			t.Fatal(err)
		}
		connection := &capturePacketConn{}
		remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4567}
		if !server.handle(connection, raw, remote) {
			if len(connection.written) != 0 {
				t.Fatal("rejected datagram emitted a response")
			}
			return
		}
		if len(connection.written) == 0 || len(connection.written) > len(raw)*3 {
			t.Fatalf("response length=%d request length=%d", len(connection.written), len(raw))
		}
		response := &stun.Message{Raw: connection.written}
		if err := response.Decode(); err != nil || response.Type != stun.BindingSuccess {
			t.Fatalf("invalid accepted response type=%v error=%v", response.Type, err)
		}
		var reflected stun.XORMappedAddress
		if err := reflected.GetFrom(response); err != nil {
			t.Fatal(err)
		}
		if !reflected.IP.Equal(remote.IP) || reflected.Port != remote.Port {
			t.Fatalf("reflected=%s remote=%s", reflected.String(), remote.String())
		}
	})
}

type capturePacketConn struct {
	written []byte
}

func (c *capturePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *capturePacketConn) WriteTo(value []byte, _ net.Addr) (int, error) {
	c.written = append(c.written[:0], value...)
	return len(value), nil
}
func (c *capturePacketConn) Close() error                     { return nil }
func (c *capturePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *capturePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *capturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePacketConn) SetWriteDeadline(time.Time) error { return nil }
