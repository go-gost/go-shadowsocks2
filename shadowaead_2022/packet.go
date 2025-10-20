package shadowaead2022

import (
	"crypto/aes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/internal"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var (
	ErrShortPacket      = errors.New("short packet")
	ErrInvalidSessionID = errors.New("invalid session ID")
	ErrReplayAttack     = errors.New("replay attack detected")
)

// SeparateHeader represents the UDP separate header (16 bytes)
type SeparateHeader struct {
	SessionID uint64 // 8 bytes
	PacketID  uint64 // 8 bytes
}

// EncodeSeparateHeader encodes separate header to bytes
func EncodeSeparateHeader(header *SeparateHeader) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], header.SessionID)
	binary.BigEndian.PutUint64(buf[8:16], header.PacketID)
	return buf
}

// DecodeSeparateHeader decodes separate header from bytes
func DecodeSeparateHeader(data []byte) (*SeparateHeader, error) {
	if len(data) < 16 {
		return nil, ErrShortPacket
	}
	return &SeparateHeader{
		SessionID: binary.BigEndian.Uint64(data[0:8]),
		PacketID:  binary.BigEndian.Uint64(data[8:16]),
	}, nil
}

// UDPHeader represents the UDP header for both request and response
type UDPHeader struct {
	Type            byte       // HeaderTypeClientStream (0) or HeaderTypeServerStream (1)
	Timestamp       int64      // Unix epoch timestamp (8 bytes)
	ClientSessionID uint64     // Client session ID (8 bytes, only for response)
	PaddingLength   uint16     // Padding length (2 bytes)
	Address         socks.Addr // Target address (request) or Source address (response)
	Padding         []byte     // Random padding
}

// EncodeUDPHeader encodes UDP header for both request and response
func EncodeUDPHeader(header *UDPHeader) []byte {
	var totalLen int
	var buf []byte
	pos := 0

	if header.Type == HeaderTypeClientStream {
		// Request: Type (1) + Timestamp (8) + PaddingLength (2) + Address + Padding
		totalLen = 1 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	} else {
		// Response: Type (1) + Timestamp (8) + ClientSessionID (8) + PaddingLength (2) + Padding + Address
		totalLen = 1 + 8 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint64(buf[pos:], header.ClientSessionID)
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	}

	return buf
}

// DecodeUDPHeader decodes UDP header for both request and response
func DecodeUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 11 { // Minimum: 1 + 8 + 2
		return nil, ErrInvalidHeader
	}

	header := &UDPHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	if err := validateTimestamp(header.Timestamp); err != nil {
		return nil, err
	}

	if header.Type == HeaderTypeClientStream {
		// Request: PaddingLength + Padding + Address
		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
		pos += int(header.PaddingLength)

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
	} else {
		// Response: ClientSessionID + PaddingLength + Padding + Address
		if len(data) < 19 { // 1 + 8 + 8 + 2
			return nil, ErrInvalidHeader
		}

		header.ClientSessionID = binary.BigEndian.Uint64(data[pos:])
		pos += 8

		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
		pos += int(header.PaddingLength)

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
	}

	return header, nil
}

// NewSession creates a new UDP session with random session ID

// encryptSeparateHeaderAES encrypts separate header using AES block cipher with PSK
func encryptSeparateHeaderAES(header *SeparateHeader, psk []byte) ([]byte, error) {
	// Separate header is 16 bytes (session ID + packet ID)
	plainHeader := EncodeSeparateHeader(header)

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Encrypt using AES ECB mode (single block)
	encrypted := make([]byte, 16)
	block.Encrypt(encrypted, plainHeader)

	return encrypted, nil
}

// decryptSeparateHeaderAES decrypts separate header using AES block cipher with PSK
func decryptSeparateHeaderAES(encrypted []byte, psk []byte) (*SeparateHeader, error) {
	if len(encrypted) != 16 {
		return nil, ErrShortPacket
	}

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Decrypt using AES ECB mode (single block)
	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, encrypted)

	return DecodeSeparateHeader(decrypted)
}

// PackUDP encrypts plaintext using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
// serverSession: optional, for server responses. If nil, uses c.session (client mode)
func (c *PacketConn) PackUDP(dst, plaintext []byte, serverSession *ServerSession) ([]byte, error) {
	var sessionID, packetID uint64
	var target socks.Addr
	var clientSessionID uint64

	if serverSession != nil {
		// Server mode: use ServerSession
		sessionID = serverSession.ServerSessionID()
		packetID = serverSession.GetNextPacketID()
		target = serverSession.GetTarget()
		clientSessionID = serverSession.ClientSessionID()
	} else {
		// Client mode: use ClientSession
		if c.session == nil {
			return nil, errors.New("no session set")
		}
		sessionID = c.session.SessionID()
		packetID = c.session.GetNextPacketID()
		target = c.session.Target()
	}

	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, sessionID)

	// Derive session subkey from salt for AEAD
	aead, err := c.Encrypter(salt)
	if err != nil {
		return nil, err
	}

	// Create separate header (session ID + packet ID)
	separateHeader := &SeparateHeader{
		SessionID: sessionID,
		PacketID:  packetID,
	}
	separateHeaderEncoding := EncodeSeparateHeader(separateHeader)

	// Encrypt separate header with AES using PSK
	encryptedSeparateHeader, err := encryptSeparateHeaderAES(separateHeader, c.psk)
	if err != nil {
		return nil, err
	}

	pad := rand.Intn(MaxPaddingLength)
	padding := make([]byte, pad)
	_, err = crand.Read(padding)
	if err != nil {
		return nil, errors.New("failed to generate padding")
	}

	var headerType byte
	if serverSession != nil {
		headerType = HeaderTypeServerStream
	} else {
		headerType = HeaderTypeClientStream
	}

	// Encode main header
	header := &UDPHeader{
		Type:            headerType,
		Timestamp:       time.Now().Unix(),
		Address:         target,
		PaddingLength:   uint16(len(padding)),
		Padding:         padding,
		ClientSessionID: clientSessionID, // Only used if headerType == ServerStream
	}

	mainHeader := EncodeUDPHeader(header)

	// Combine main header + payload as body
	body := make([]byte, len(mainHeader)+len(plaintext))
	copy(body, mainHeader)
	copy(body[len(mainHeader):], plaintext)

	// Encrypt body with AEAD
	encryptedBody := aead.Seal(nil, separateHeaderEncoding[4:], body, nil)

	// Combine: encrypted_separate_header + encrypted_body
	totalSize := 16 + len(encryptedBody)
	if len(dst) < totalSize {
		return nil, io.ErrShortBuffer
	}

	pos := 0
	copy(dst[pos:], encryptedSeparateHeader)
	pos += 16
	copy(dst[pos:], encryptedBody)

	return dst[:totalSize], nil
}

// UnpackUDP decrypts pkt using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
// Returns: (header, payload, sessionID, error)
func (c *PacketConn) UnpackUDP(dst, pkt []byte) (*SeparateHeader, *UDPHeader, []byte, error) {
	// Decrypt separate header with AES using PSK
	encryptedSeparateHeader := pkt[:16]
	separateHeader, err := decryptSeparateHeaderAES(encryptedSeparateHeader, c.psk)
	if err != nil {
		return nil, nil, nil, err
	}
	separateHeaderEncoding := EncodeSeparateHeader(separateHeader)
	dst = append(dst, separateHeaderEncoding...)

	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, separateHeader.SessionID)

	// Derive session subkey from salt for AEAD
	aead, err := c.Decrypter(salt)
	if err != nil {
		return nil, nil, nil, err
	}

	// Decrypt body with AEAD
	encryptedBody := pkt[16:]
	if len(encryptedBody) < aead.Overhead() {
		return nil, nil, nil, ErrShortPacket
	}

	body, err := aead.Open(encryptedBody[:0], separateHeaderEncoding[4:], encryptedBody, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Parse main header from body
	header, err := DecodeUDPHeader(body)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract payload (everything after main header)
	var headerLen int
	if header.Type == HeaderTypeClientStream {
		headerLen = 1 + 8 + 2 + len(header.Address) + int(header.PaddingLength)
	} else {
		headerLen = 1 + 8 + 8 + 2 + int(header.PaddingLength) + len(header.Address)
	}
	if len(body) < headerLen {
		return nil, nil, nil, ErrShortPacket
	}
	payload := body[headerLen:]

	return separateHeader, header, payload, nil
}

// packetConn implements SIP022 UDP with session management
type PacketConn struct {
	net.PacketConn
	internal.ShadowCipher
	sync.RWMutex
	buf              []byte // write buffer
	psk              []byte // pre-shared key for AES encryption
	clientSessionMgr *ClientSessionManager
	serverSessionMgr *ServerSessionManager
	session          *ClientSession // Client-side: current session
	isServer         bool
}

// NewPacketConn wraps a net.PacketConn with SIP022 UDP session management
func NewPacketConn(c net.PacketConn, ciph internal.ShadowCipher, psk []byte, role int) *PacketConn {
	const maxPacketSize = 64 * 1024
	conn := &PacketConn{
		PacketConn:   c,
		ShadowCipher: ciph,
		buf:          make([]byte, maxPacketSize),
		isServer:     role == utils.ROLE_SERVER,
		psk:          psk,
	}

	return conn
}

// SetClientSessionManager sets the client-side session manager.
func (c *PacketConn) SetClientSessionManager(m *ClientSessionManager) {
	c.clientSessionMgr = m
}

// SetServerSessionManager sets the server-side session manager.
func (c *PacketConn) SetServerSessionManager(m *ServerSessionManager) {
	c.serverSessionMgr = m
}

// WriteTo encrypts b using SIP022 UDP format and writes to addr
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()

	buf, err := c.PackUDP(c.buf, b, nil)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// WriteToUDPAddrPort encrypts b using SIP022 UDP format and writes to addr
// More efficient than WriteTo for UDP connections - avoids interface allocation
func (c *PacketConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	udpConn, ok := c.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, errors.New("underlying connection is not *net.UDPConn")
	}

	c.Lock()
	defer c.Unlock()

	buf, err := c.PackUDP(c.buf, b, nil)
	if err != nil {
		return 0, err
	}
	_, err = udpConn.WriteToUDPAddrPort(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts using SIP022 UDP format
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}

	c.Lock()
	defer c.Unlock()

	_, _, payload, err := c.UnpackUDP(b[0:], b[:n])
	if err != nil {
		return n, addr, err
	}

	copy(b, payload)
	return len(payload), addr, nil
}

// ReadFromUDPAddrPort reads from UDP and decrypts using SIP022 UDP format.
// More efficient than ReadFrom for UDP connections - avoids interface allocation.
// For server, this is the main entry point for handling UDP packets.
//
// Server-side logic:
// 1. Decrypt packet
// 2. Validate session (anti-replay + NAT handling)
// 3. Get or create outbound connection for this session
// 4. Forward payload to target
//
// This is simple and direct - no goroutines, no complex state management.
func (c *PacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	udpConn, ok := c.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, netip.AddrPort{}, errors.New("underlying connection is not *net.UDPConn")
	}

	n, clientAddr, err := udpConn.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, clientAddr, err
	}

	c.Lock()
	defer c.Unlock()

	separateHeader, udpHeader, payload, err := c.UnpackUDP(b[:0], b[:n])
	if err != nil {
		return n, clientAddr, err
	}

	if c.isServer {
		// Validate session: anti-replay + update client address
		session, err := c.validateSession(*separateHeader, clientAddr)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}

		// Update target address in session
		session.SetTarget(udpHeader.Address)

		// Get or create outbound connection atomically (prevents race conditions)
		conn, isNew, err := session.GetOrCreateConn()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}

		// If this is a new connection, start goroutine to handle return traffic
		if isNew {
			go c.handleReturnTraffic(session, conn)
		}

		// Forward payload to target
		targetAddr, err := net.ResolveUDPAddr("udp", udpHeader.Address.String())
		if err != nil {
			return 0, netip.AddrPort{}, err
		}

		_, err = conn.WriteTo(payload, targetAddr)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
	}

	copy(b, payload)
	return len(payload), clientAddr, nil
}

// SetSession sets the current client session (client-side only).
func (c *PacketConn) SetSession(s *ClientSession) {
	c.session = s
}

// validateSession validates and updates the server session.
// This implements the SIP022 session management logic:
// 1. Get or create session by client session ID
// 2. Validate packet ID using sliding window (anti-replay)
// 3. Update client address (handles NAT rebinding)
func (c *PacketConn) validateSession(sh SeparateHeader, addr netip.AddrPort) (*ServerSession, error) {
	if c.serverSessionMgr == nil {
		return nil, errors.New("server session manager not set")
	}

	// ValidatePacket does: GetOrCreate + ValidatePacketID + UpdateClientAddr
	session, err := c.serverSessionMgr.ValidatePacket(sh.SessionID, sh.PacketID, addr)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// handleReturnTraffic handles return traffic from target server back to client.
// This goroutine reads from the outbound connection and sends encrypted responses
// back to the client. This is THE critical function that makes UDP relay work.
func (c *PacketConn) handleReturnTraffic(session *ServerSession, targetConn net.PacketConn) {
	buf := make([]byte, 64*1024)

	defer func() {
		targetConn.Close()
		if c.serverSessionMgr != nil {
			c.serverSessionMgr.Delete(session.ClientSessionID())
		}
	}()

	for {
		// Read response from target server
		targetConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, _, err := targetConn.ReadFrom(buf)
		if err != nil {
			return // Timeout or error, close session
		}

		// Encrypt and send back to client using PackUDP
		clientAddr := session.GetClientAddr()

		udpConn, ok := c.PacketConn.(*net.UDPConn)
		if !ok {
			return
		}

		// Use PackUDP with serverSession parameter
		encrypted := make([]byte, 64*1024)
		packet, err := c.PackUDP(encrypted, buf[:n], session)
		if err != nil {
			return
		}

		_, err = udpConn.WriteToUDPAddrPort(packet, clientAddr)
		if err != nil {
			return
		}
	}
}
