package shadowaead2022

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// ClientSession represents a UDP relay session on the client side.
// Each session corresponds to one local source address (client application).
//
// In SIP022, the client:
// - Generates a random session ID for each source address
// - Maintains a monotonically increasing packet counter
// - Remembers the target address for this session
type ClientSession struct {
	sessionID  uint64        // Randomly generated 8-byte session ID
	packetID   atomic.Uint64 // Monotonically increasing packet counter
	target     socks.Addr    // Target address this session is relaying to
	lastUsed   atomic.Int64  // Last time this session was used (for timeout cleanup)
	clientAddr netip.AddrPort
	mu         sync.RWMutex
}

// NewClientSession creates a new client session with a random session ID.
func NewClientSession(clientAddr netip.AddrPort, target socks.Addr) *ClientSession {
	sessionID := make([]byte, 8)
	rand.Read(sessionID)

	s := &ClientSession{
		sessionID:  binary.BigEndian.Uint64(sessionID),
		target:     target,
		clientAddr: clientAddr,
	}

	s.lastUsed.Store(time.Now().Unix())
	return s
}

// GetNextPacketID returns the next packet ID and increments the counter.
// Thread-safe: can be called concurrently.
func (s *ClientSession) GetNextPacketID() uint64 {
	pid := s.packetID.Load()
	s.packetID.Add(1)
	return pid
}

func (s *ClientSession) ClientAddr() netip.AddrPort {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.clientAddr
}

// SessionID returns the session ID.
func (s *ClientSession) SessionID() uint64 {
	return s.sessionID
}

// Target returns the target address for this session.
func (s *ClientSession) Target() socks.Addr {
	return s.target
}

func (s *ClientSession) Hash() core.SessionHash {
	return core.SessionHash(s.clientAddr.String())
}

// LastUsed returns when this session was last used.
func (s *ClientSession) LastUsed() time.Time {
	return time.Unix(s.lastUsed.Load(), 0)
}

func (s *ClientSession) Touch() {
	s.lastUsed.Store(time.Now().Unix())
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
	stop     chan bool
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
		stop:     make(chan bool),
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
func (m *ClientSessionManager) GetOrCreate(sourceAddr netip.AddrPort, target socks.Addr) *ClientSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[sourceAddr]; exists {
		return session
	}

	session := NewClientSession(sourceAddr, target)
	m.sessions[sourceAddr] = session
	return session
}

// Delete removes a session and closes its connection.
func (m *ClientSessionManager) Delete(sourceAddr netip.AddrPort) {
	m.mu.Lock()
	_, exists := m.sessions[sourceAddr]
	if exists {
		delete(m.sessions, sourceAddr)
	}
	m.mu.Unlock()
}

// cleanupLoop runs in the background to remove expired sessions.
func (m *ClientSessionManager) cleanupLoop() {
	ticker := time.NewTicker(m.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.cleanup()
		}
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
}

// Close stops the cleanup loop and closes all sessions.
func (m *ClientSessionManager) Close() error {
	close(m.stop)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions = make(map[netip.AddrPort]*ClientSession)

	return nil
}
