package shadowaead2022

import (
	"crypto/aes"
	"net"
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/zeebo/blake3"
)

// UDPSessionManager implements UDPSessionManager for Shadowsocks 2022 (UDP).
//
// Design: Stateful session-based relay with anti-replay protection
// - Sessions keyed by session ID (not address)
// - Monotonic packet counters with sliding window validation
// - Handles NAT rebinding (client address can change)
// - Complex but secure: built for real-world hostile networks
type UDPSessionManager struct {
	cipher core.ShadowCipher

	// Server-side state
	serverSessionMgr *ServerSessionManager
	serverConn       *net.UDPConn // Listening connection for sending responses

	// Client-side state
	clientSessionMgr *ClientSessionManager

	timeout     time.Duration
	windowSize  uint64
	isServer    bool
	connBuilder func() core.UDPConn

	userTable map[core.EIHHash]string // Extensible Identity Headers, for server
}

// newUDPSessionManager creates a session manager for UDP protocol.
// role: core.ROLE_SERVER or core.ROLE_CLIENT
func newUDPSessionManager(cipher core.ShadowCipher, userTable map[core.EIHHash]string, timeout time.Duration, windowSize int, role int) *UDPSessionManager {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if windowSize == 0 {
		windowSize = 2000 // UDP default
	}

	mgr := &UDPSessionManager{
		cipher:     cipher,
		timeout:    timeout,
		windowSize: uint64(windowSize),
		isServer:   role == core.ROLE_SERVER,
		userTable:  userTable,
	}

	if role == core.ROLE_SERVER {
		mgr.serverSessionMgr = NewServerSessionManager(timeout, uint64(windowSize))
	} else {
		mgr.clientSessionMgr = NewClientSessionManager(timeout)
	}

	return mgr
}

// SetServerConn sets the server-side listening connection (needed for sending encrypted responses)
func (m *UDPSessionManager) SetServerConn(conn *net.UDPConn) {
	m.serverConn = conn
}

// HandleInbound processes an incoming encrypted packet and forwards it (server-side).
// UDP protocol flow:
// 1. Decrypt separate header (AES) to get session ID + packet ID
// 2. Validate session: anti-replay + NAT rebinding
// 3. Decrypt main body (AEAD) to get target address + payload
func (m *UDPSessionManager) ServerHandleInbound(encrypted []byte, clientAddr netip.AddrPort) (core.UDPSession, []byte, error) {
	if len(encrypted) < 16 {
		return nil, nil, ErrShortPacket
	}

	// Decrypt separate header with AES
	separateHeader, header, payload, key, err := UnpackUDP(m.cipher, m.userTable, encrypted)
	if err != nil {
		return nil, nil, err
	}

	// Validate session: get-or-create + anti-replay + update client address
	session, err := m.serverSessionMgr.ValidatePacket(
		separateHeader.SessionID,
		separateHeader.PacketID,
		clientAddr,
		key,
	)
	if err != nil {
		return nil, nil, err
	}
	session.Touch()

	target := header.Address

	session.SetTarget(target)

	return session, payload, err
}

// UDP protocol: session ID + packet counter + target address.
func (m *UDPSessionManager) ServerHandleOutbound(plaintext []byte, udpSession core.UDPSession) ([]byte, error) {
	session := udpSession.(*ServerSession)

	encrypted, err := PackUDP(m.cipher, false, session.Key(), session.Key(), plaintext, session.Target(), session.SessionID(), session.GetNextPacketID(), session.ClientSessionID())
	if err != nil {
		return nil, err
	}

	session.Touch()

	return encrypted, nil
}

func (m *UDPSessionManager) ClientHandleInbound(payload []byte, target socks.Addr, clientAddr netip.AddrPort) (core.UDPSession, []byte, error) {
	session := m.clientSessionMgr.GetOrCreate(clientAddr, target)

	eih := len(m.cipher.Keys()) > 1
	encrypted, err := PackUDP(m.cipher, eih, m.cipher.FirstKey(), m.cipher.Key(), payload, target, session.SessionID(), session.GetNextPacketID(), 0)
	if err != nil {
		return nil, nil, err
	}

	session.Touch()

	return session, encrypted, nil
}

func (m *UDPSessionManager) ClientHandleOutbound(encrypted []byte, udpSession core.UDPSession) ([]byte, error) {
	session := udpSession.(*ClientSession)

	_, _, payload, _, err := UnpackUDP(m.cipher, nil, encrypted)
	if err != nil {
		return nil, err
	}

	session.Touch()

	return payload, nil
}

// Generate Extensible Identity Headers
func AdditionalHeaders(c core.ShadowCipher, seperateHeaderEncoding []byte) ([]byte, error) {
	psks := c.Keys()
	n := len(psks)
	r := []byte{}
	for i := range n - 1 {
		key := psks[i]
		nextKey := psks[i+1]
		nextKeyHash := blake3.Sum256(nextKey)
		buf, err := core.XORBytes(nextKeyHash[:16], seperateHeaderEncoding)
		if err != nil {
			return nil, err
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		c.Encrypt(buf, buf)
		r = append(r, buf...)
	}

	return r, nil
}
