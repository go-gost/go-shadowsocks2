package shadowaead

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// aeadSession represents a single UDP relay session for AEAD protocol.
// AEAD is stateless per packet, but we track sessions for NAT mapping.
type aeadSession struct {
	target     socks.Addr
	clientAddr netip.AddrPort
	conn       core.UDPConn
	lastUsed   atomic.Int64
	returning  atomic.Bool
}

// newAEADSession creates a new AEAD session.
func newAEADSession(target socks.Addr, clientAddr netip.AddrPort) *aeadSession {
	s := &aeadSession{
		target:     target,
		clientAddr: clientAddr,
	}
	s.lastUsed.Store(time.Now().Unix())
	return s
}

// Target returns the destination address for this session.
func (s *aeadSession) Target() socks.Addr {
	return s.target
}

// ClientAddr returns the client address for this session.
func (s *aeadSession) ClientAddr() netip.AddrPort {
	return s.clientAddr
}

// Conn returns the outbound connection for this session.
func (s *aeadSession) Conn() core.UDPConn {
	return s.conn
}

// Conn returns the outbound connection for this session.
func (s *aeadSession) SetConn(conn core.UDPConn) {
	s.conn = conn
}

// LastUsed returns when this session was last used.
func (s *aeadSession) LastUsed() time.Time {
	return time.Unix(s.lastUsed.Load(), 0)
}

// Returning returns whether the return goroutine is running.
func (s *aeadSession) Returning() bool {
	return s.returning.Load()
}

// Return sets the returning status.
func (s *aeadSession) Return(running bool) {
	s.returning.Store(running)
}

// Close closes the session and its connection.
func (s *aeadSession) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// touch updates the last used timestamp.
func (s *aeadSession) Touch() {
	s.lastUsed.Store(time.Now().Unix())
}
