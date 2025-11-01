package core

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type SessionHash string

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
	ServerHandleInbound(encrypted []byte, clientAddr netip.AddrPort) (UDPSession, []byte, error)

	// This function should return data from target, so it's maybe a block function.
	ServerHandleOutbound(plaintext []byte, session UDPSession) ([]byte, error)

	ClientHandleInbound(payload []byte, target socks.Addr, clientAddr netip.AddrPort) (UDPSession, []byte, error)

	// This function should return data from target, so it's maybe a block function.
	ClientHandleOutbound(encrypted []byte, session UDPSession) ([]byte, error)
}

// UDPSession represents a single UDP relay session.
// This is used by protocol-specific managers internally.
type UDPSession interface {
	// Target returns the destination address for this session
	Target() socks.Addr

	ClientAddr() netip.AddrPort

	// LastUsed returns when this session was last used
	LastUsed() time.Time

	// update LastUsed
	Touch()

	SessionID() uint64

	// unique id for identifying session
	Hash() SessionHash
}

func SessionHashFromAddrPort(addr netip.AddrPort) SessionHash {
	return SessionHash(addr.String())
}

func SessionHashFromSessionID(id uint64) SessionHash {
	return SessionHash(strconv.FormatUint(id, 10))
}
