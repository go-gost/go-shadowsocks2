package shadowaead2022

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// ClientSession represents a UDP relay session on the client side.
// Each session corresponds to one local source address (client application).
//
// In SIP022, the client:
// - Generates a random session ID for each source address
// - Maintains a monotonically increasing packet counter
// - Remembers the target address for this session
type ClientSession struct {
	sessionID uint64         // Randomly generated 8-byte session ID
	packetID  uint64         // Monotonically increasing packet counter
	target    socks.Addr     // Target address this session is relaying to
	conn      net.PacketConn // Outbound connection for this session
	lastUsed  time.Time      // Last time this session was used (for timeout cleanup)
	mu        sync.Mutex     // Protects packetID and lastUsed
}

// NewClientSession creates a new client session with a random session ID.
func NewClientSession(target socks.Addr, conn net.PacketConn) *ClientSession {
	sessionID := make([]byte, 8)
	rand.Read(sessionID)

	return &ClientSession{
		sessionID: binary.BigEndian.Uint64(sessionID),
		packetID:  0,
		target:    target,
		conn:      conn,
		lastUsed:  time.Now(),
	}
}

// GetNextPacketID returns the next packet ID and increments the counter.
// Thread-safe: can be called concurrently.
func (s *ClientSession) GetNextPacketID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	pid := s.packetID
	s.packetID++
	s.lastUsed = time.Now()
	return pid
}

// SessionID returns the session ID.
func (s *ClientSession) SessionID() uint64 {
	return s.sessionID
}

// Target returns the target address for this session.
func (s *ClientSession) Target() socks.Addr {
	return s.target
}

// Conn returns the outbound connection for this session.
func (s *ClientSession) Conn() net.PacketConn {
	return s.conn
}

// LastUsed returns when this session was last used.
func (s *ClientSession) LastUsed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastUsed
}

// Close closes the outbound connection.
func (s *ClientSession) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// ClientSessionManager manages UDP relay sessions on the client side.
// It maps source addresses (local applications) to sessions.
//
// Key design principles:
// 1. One session per source address
// 2. Each session has its own outbound connection
// 3. Sessions timeout after inactivity
// 4. No special cases: simple map lookup
type ClientSessionManager struct {
	sessions map[netip.AddrPort]*ClientSession
	timeout  time.Duration
	mu       sync.RWMutex
}

// NewClientSessionManager creates a new client-side session manager.
func NewClientSessionManager(timeout time.Duration) *ClientSessionManager {
	if timeout == 0 {
		timeout = 60 * time.Second // Default timeout
	}

	mgr := &ClientSessionManager{
		sessions: make(map[netip.AddrPort]*ClientSession),
		timeout:  timeout,
	}

	// Start background cleanup
	go mgr.cleanupLoop()

	return mgr
}

// Get retrieves an existing session for the source address.
// Returns nil if no session exists.
func (m *ClientSessionManager) Get(sourceAddr netip.AddrPort) *ClientSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[sourceAddr]
}

// GetOrCreate retrieves or creates a session for the source address.
// If a new session is created, conn will be used as the outbound connection.
func (m *ClientSessionManager) GetOrCreate(sourceAddr netip.AddrPort, target socks.Addr, conn net.PacketConn) *ClientSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[sourceAddr]; exists {
		return session
	}

	session := NewClientSession(target, conn)
	m.sessions[sourceAddr] = session
	return session
}

// Delete removes a session and closes its connection.
func (m *ClientSessionManager) Delete(sourceAddr netip.AddrPort) {
	m.mu.Lock()
	session, exists := m.sessions[sourceAddr]
	if exists {
		delete(m.sessions, sourceAddr)
	}
	m.mu.Unlock()

	if exists && session != nil {
		session.Close()
	}
}

// cleanupLoop runs in the background to remove expired sessions.
func (m *ClientSessionManager) cleanupLoop() {
	ticker := time.NewTicker(m.timeout / 2)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

// cleanup removes sessions that haven't been used recently.
func (m *ClientSessionManager) cleanup() {
	now := time.Now()

	m.mu.Lock()
	var toClose []*ClientSession
	for addr, session := range m.sessions {
		if now.Sub(session.LastUsed()) > m.timeout {
			toClose = append(toClose, session)
			delete(m.sessions, addr)
		}
	}
	m.mu.Unlock()

	// Close connections outside the lock
	for _, session := range toClose {
		session.Close()
	}
}

// Count returns the number of active sessions (for debugging/monitoring).
func (m *ClientSessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}
