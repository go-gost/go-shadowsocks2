package shadowaead

import (
	"net"
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

	connBuilder func() core.UDPConn

	// Server-side: the listening connection to send encrypted responses
	serverConn core.UDPConn
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

// SetServerConn sets the server-side listening connection (needed for sending responses)
func (m *AEADSessionManager) SetServerConn(conn core.UDPConn) {
	m.serverConn = conn
}

// ServerHandleReceive processes an incoming encrypted packet from a client and forwards it.
// AEAD protocol flow:
// 1. Decrypt packet: extract salt, decrypt with AEAD
// 2. Parse target address from decrypted payload
// 3. Get or create outbound connection for this client address
// 4. Forward payload to target
func (m *AEADSessionManager) ServerHandleReceive(encrypted []byte, clientAddr netip.AddrPort) (core.UDPSession, error) {
	// Decrypt packet
	payload, err := Unpack(encrypted[m.cipher.SaltSize():], encrypted, m.cipher)
	if err != nil {
		return nil, err
	}

	// Extract target address (AEAD: target is embedded in each packet)
	target := socks.SplitAddr(payload)
	if target == nil {
		return nil, ErrShortPacket
	}

	// Get actual payload (after target address)
	actualPayload := payload[len(target):]

	// Resolve target address
	targetAddr, err := netip.ParseAddrPort(target.String())
	if err != nil {
		return nil, err
	}

	session := m.sessionMgr.GetOrCreate(clientAddr, target)
	outboundConn := session.Conn()
	if outboundConn == nil {
		// Create new outbound connection
		outboundConn, err = m.BuildConn(core.UDPConfig{})
		if err != nil {
			return nil, err
		}

		session.SetConn(outboundConn)

	}

	// Update last used time
	session.Touch()

	// Forward payload to target
	_, err = outboundConn.WriteToUDPAddrPort(actualPayload, targetAddr)
	if err != nil {
		return nil, err
	}

	return session, err
}

func (m *AEADSessionManager) ServerHandleReturn(session core.UDPSession) ([]byte, error) {
	s := session.(*aeadSession)
	saltSize := m.cipher.SaltSize()
	conn := s.Conn()

	conn.SetReadDeadline(time.Now().Add(m.timeout))
	buf := make([]byte, 64*1024)
	n, _, err := conn.ReadFromUDPAddrPort(buf[saltSize:])
	if err != nil {
		return nil, err
	}

	encrypted, err := Pack(buf[0:], buf[saltSize:saltSize+n], m.cipher)
	if err != nil {
		return nil, err
	}

	s.Touch()

	return encrypted, nil
}

// HandleOutbound encrypts a packet for sending to the server (client-side).
// AEAD protocol: prepend target address to payload, then encrypt.
func (m *AEADSessionManager) ClientHandleReceive(payload []byte, target socks.Addr, clientAddr netip.AddrPort, serverAddr netip.AddrPort) (core.UDPSession, error) {
	// AEAD format: target address + payload
	plaintext := make([]byte, len(target)+len(payload))
	copy(plaintext, target)
	copy(plaintext[len(target):], payload)

	// Encrypt with random salt
	buf := make([]byte, m.cipher.SaltSize()+len(plaintext)+16) // 16 = typical AEAD overhead
	encrypted, err := Pack(buf, plaintext, m.cipher)
	if err != nil {
		return nil, err
	}

	session := m.sessionMgr.GetOrCreate(clientAddr, target)
	conn := session.Conn()
	if conn == nil {
		conn, err = m.BuildConn(core.UDPConfig{})
		if err != nil {
			return nil, err
		}
		session.SetConn(conn)
	}

	session.Touch()

	_, err = conn.WriteToUDPAddrPort(encrypted, serverAddr)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (m *AEADSessionManager) ClientHandleReturn(udpSession core.UDPSession) ([]byte, error) {
	session := udpSession.(*aeadSession)
	conn := session.Conn()

	buf := make([]byte, 64*1024)
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	n, _, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, err
	}

	payload, err := Unpack(buf[m.cipher.SaltSize():], buf[:n], m.cipher)
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

func (m *AEADSessionManager) BuildConn(config core.UDPConfig) (core.UDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
