package core

import (
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/socks"
)

// UDPSessionManager is the interface that abstracts session management
// for different Shadowsocks protocols (AEAD vs SIP022).
// For server, the dataflow is:
// client encrypted data -> ServerHandleReceive -> target and plaintext -> target server
// target server -> plaintext -> ServerHandleOutbound -> encrypted data -> client
// For Client, the dataflow is:
// app -> plaintext -> ServerHandleReceive -> encrypted -> ss server
// ss server -> encrypted data -> ServerHandleOutbound -> plaintext -> app
type UDPSessionManager interface {
	// This function should complete following things:
	// 1. Decrypt data and send to target
	// 2. Validate session
	ServerHandleReceive(encrypted []byte, clientAddr netip.AddrPort) (UDPSession, error)

	// This function should return data from target, so it's maybe a block function.
	ServerHandleReturn(session UDPSession) ([]byte, error)

	ClientHandleReceive(payload []byte, target socks.Addr, clientAddr netip.AddrPort, serverAddr netip.AddrPort) (UDPSession, error)

	// This function should return data from target, so it's maybe a block function.
	ClientHandleReturn(session UDPSession) ([]byte, error)

	// For client and server, sessions need create coonnections. To adapt flexible
	// configurations, UDPSessionManager will use a connection builder to create conn.
	// For server, each session will create a connection to the target
	// for client, each session will create a connection to the server
	BuildConn(config UDPConfig) (UDPConn, error)
}

// UDPSession represents a single UDP relay session.
// This is used by protocol-specific managers internally.
type UDPSession interface {
	// Target returns the destination address for this session
	Target() socks.Addr

	ClientAddr() netip.AddrPort

	// Conn returns the outbound connection for this session
	Conn() UDPConn

	// LastUsed returns when this session was last used
	LastUsed() time.Time

	// wether the returning behavior is running
	// In client. this behavior should be controled by third apps
	Returning() bool

	Return(bool)

	// update LastUsed
	Touch()

	// Close closes the session and its connection
	Close() error
}
