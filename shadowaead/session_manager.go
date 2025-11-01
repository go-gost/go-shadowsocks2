package shadowaead

import (
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// AEADSessionManager implements UDPSessionManager for classic Shadowsocks AEAD.
//
// Design: Simple NAT-based mapping
// - No session IDs, no packet counters, no replay protection
// - Maps client address -> outbound connection
// - Each incoming packet is decrypted independently (stateless)
// - Target address is extracted from each packet
type AEADSessionManager struct {
	cipher     core.ShadowCipher
	sessionMgr *SessionManager
	timeout    time.Duration
	isServer   bool
}

// NewAEADSessionManager creates a session manager for AEAD protocol.
func NewAEADSessionManager(cipher core.ShadowCipher, timeout time.Duration, role int) *AEADSessionManager {
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &AEADSessionManager{
		cipher:     cipher,
		sessionMgr: NewSessionManager(timeout),
		timeout:    timeout,
		isServer:   role == core.ROLE_SERVER,
	}
}

// ServerHandleReceive processes an incoming encrypted packet from a client and forwards it.
// AEAD protocol flow:
// 1. Decrypt packet: extract salt, decrypt with AEAD
// 2. Parse target address from decrypted payload
func (m *AEADSessionManager) ServerHandleInbound(encrypted []byte, clientAddr netip.AddrPort) (core.UDPSession, []byte, error) {
	// Decrypt packet
	payload, err := Unpack(encrypted[m.cipher.SaltSize():], encrypted, m.cipher)
	if err != nil {
		return nil, nil, err
	}

	// Extract target address (AEAD: target is embedded in each packet)
	target := socks.SplitAddr(payload)
	if target == nil {
		return nil, nil, ErrShortPacket
	}

	// Get actual payload (after target address)
	actualPayload := payload[len(target):]

	session := m.sessionMgr.GetOrCreate(clientAddr, target)

	// Update last used time
	session.Touch()

	return session, actualPayload, err
}

func (m *AEADSessionManager) ServerHandleOutbound(plaintext []byte, session core.UDPSession) ([]byte, error) {
	s := session.(*aeadSession)

	buf := make([]byte, len(plaintext)+m.cipher.SaltSize()+m.cipher.TagSize())

	encrypted, err := Pack(buf, plaintext, m.cipher)
	if err != nil {
		return nil, err
	}

	s.Touch()

	return encrypted, nil
}

// HandleOutbound encrypts a packet for sending to the server (client-side).
// AEAD protocol: prepend target address to payload, then encrypt.
func (m *AEADSessionManager) ClientHandleInbound(payload []byte, target socks.Addr, clientAddr netip.AddrPort) (core.UDPSession, []byte, error) {
	// AEAD format: target address + payload
	plaintext := make([]byte, len(target)+len(payload))
	copy(plaintext, target)
	copy(plaintext[len(target):], payload)

	// Encrypt with random salt
	buf := make([]byte, m.cipher.SaltSize()+len(plaintext)+m.cipher.TagSize()) // 16 = typical AEAD overhead
	encrypted, err := Pack(buf, plaintext, m.cipher)
	if err != nil {
		return nil, nil, err
	}

	session := m.sessionMgr.GetOrCreate(clientAddr, target)
	session.Touch()

	return session, encrypted, nil
}

func (m *AEADSessionManager) ClientHandleOutbound(encrypted []byte, udpSession core.UDPSession) ([]byte, error) {
	session := udpSession.(*aeadSession)

	payload, err := Unpack(encrypted[m.cipher.SaltSize():], encrypted, m.cipher)
	if err != nil {
		return nil, err
	}

	session.Touch()

	return payload, nil
}

// Close cleans up all sessions and connections.
func (m *AEADSessionManager) Close() error {
	return m.sessionMgr.Close()
}
