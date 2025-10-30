package shadowaead2022

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

var (
	ErrReplayPacket    = errors.New("replay packet detected")
	ErrPacketTooOld    = errors.New("packet too old (outside window)")
	ErrInvalidPacketID = errors.New("invalid packet ID")
)

// ServerSession represents a UDP relay session on the server side.
// Each session corresponds to one client session ID.
//
// In SIP022, the server:
// - Tracks sessions by client's session ID
// - Validates packet IDs using sliding window (anti-replay)
// - Updates client address when NAT changes
// - Generates its own packet IDs for responses
type ServerSession struct {
	clientSessionID uint64         // Client's session ID (used as key)
	serverSessionID uint64         // Server's own session ID for responses
	packetID        atomic.Uint64  // Server's packet counter for responses
	clientAddr      netip.AddrPort // Last seen client address (updates on NAT change)
	replayFilter    *SlidingWindow // Anti-replay protection
	target          socks.Addr     // Current target address
	conn            core.UDPConn   // Outbound connection to target
	lastUsed        atomic.Int64   // Last time we received a packet
	returning       atomic.Bool
	key             []byte       // key for encryption
	mu              sync.RWMutex // Protects mutable fields
}

// NewServerSession creates a new server session for a client session ID.
func NewServerSession(clientSessionID uint64, clientAddr netip.AddrPort, windowSize uint64, key []byte) *ServerSession {
	sessionID := make([]byte, 8)
	rand.Read(sessionID)

	s := &ServerSession{
		clientSessionID: clientSessionID,
		serverSessionID: binary.BigEndian.Uint64(sessionID),
		clientAddr:      clientAddr,
		replayFilter:    NewSlidingWindow(windowSize),
		key:             key,
	}
	s.lastUsed.Store(time.Now().Unix())
	return s
}

// ValidatePacket validates a packet ID using the sliding window filter.
// Returns an error if the packet is a replay or too old.
// Thread-safe: can be called concurrently.
func (s *ServerSession) ValidatePacket(packetID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.replayFilter.Validate(packetID) {
		// Check if it's too old or a replay
		if packetID+s.replayFilter.windowSize < s.replayFilter.maxPacketID {
			return ErrPacketTooOld
		}
		return ErrReplayPacket
	}

	return nil
}

// UpdateClientAddr updates the last seen client address.
// This handles NAT rebinding as per SIP022 spec.
func (s *ServerSession) UpdateClientAddr(addr netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientAddr = addr
}

func (s *ServerSession) Touch() {
	s.lastUsed.Store(time.Now().Unix())
}

// GetClientAddr returns the current client address.
func (s *ServerSession) ClientAddr() netip.AddrPort {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientAddr
}

// GetNextPacketID returns the next packet ID for server responses.
func (s *ServerSession) GetNextPacketID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	pid := s.packetID.Load()
	s.packetID.Add(1)
	return pid
}

func (s *ServerSession) Key() []byte {
	return s.key
}

// ClientSessionID returns the client's session ID.
func (s *ServerSession) ClientSessionID() uint64 {
	return s.clientSessionID
}

// ServerSessionID returns the server's session ID.
func (s *ServerSession) ServerSessionID() uint64 {
	return s.serverSessionID
}

// SetTarget sets the target address for this session.
func (s *ServerSession) SetTarget(target socks.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.target = target
}

// GetTarget returns the target address.
func (s *ServerSession) Target() socks.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.target
}

func (s *ServerSession) Return(b bool) {
	s.returning.Store(b)
}

func (s *ServerSession) Returning() bool {
	return s.returning.Load()
}

// GetConn returns the outbound connection.
func (s *ServerSession) Conn() core.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *ServerSession) SetConn(conn core.UDPConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
}

// LastSeen returns when this session last received a packet.
func (s *ServerSession) LastUsed() time.Time {
	return time.Unix(s.lastUsed.Load(), 0)
}

// Close closes the outbound connection.
func (s *ServerSession) Close() error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn != nil {
		return conn.Close()
	}
	return nil
}

// ServerSessionManager manages UDP relay sessions on the server side.
// It maps client session IDs to server sessions.
//
// Key design principles:
// 1. Sessions are keyed by client session ID (not address)
// 2. Each session has its own sliding window for replay protection
// 3. Client addresses update on every valid packet (NAT handling)
// 4. Sessions timeout after inactivity
// 5. No special cases: just a map lookup
type ServerSessionManager struct {
	sessions   map[uint64]*ServerSession
	timeout    time.Duration
	windowSize uint64 // Sliding window size for replay protection
	stop       chan bool
	mu         sync.RWMutex
}

// NewServerSessionManager creates a new server-side session manager.
func NewServerSessionManager(timeout time.Duration, windowSize uint64) *ServerSessionManager {
	if timeout == 0 {
		timeout = 60 * time.Second // Default timeout
	}
	if windowSize == 0 {
		windowSize = 2000 // SIP022 default
	}

	mgr := &ServerSessionManager{
		sessions:   make(map[uint64]*ServerSession),
		timeout:    timeout,
		windowSize: windowSize,
		stop:       make(chan bool),
	}

	// Start background cleanup
	go mgr.cleanupLoop()

	return mgr
}

// Get retrieves an existing session by client session ID.
// Returns nil if no session exists.
func (m *ServerSessionManager) Get(clientSessionID uint64) *ServerSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[clientSessionID]
}

// GetOrCreate retrieves or creates a session for the client session ID.
func (m *ServerSessionManager) GetOrCreate(clientSessionID uint64, clientAddr netip.AddrPort, key []byte) *ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[clientSessionID]; exists {
		return session
	}

	session := NewServerSession(clientSessionID, clientAddr, m.windowSize, key)
	m.sessions[clientSessionID] = session
	return session
}

// ValidatePacket is a convenience method that combines session lookup and packet validation.
// It gets or creates the session, validates the packet ID, and updates the client address.
// Returns the session and an error if validation fails.
func (m *ServerSessionManager) ValidatePacket(clientSessionID, packetID uint64, clientAddr netip.AddrPort, key []byte) (*ServerSession, error) {
	session := m.GetOrCreate(clientSessionID, clientAddr, key)

	// Validate packet ID (anti-replay)
	if err := session.ValidatePacket(packetID); err != nil {
		return session, err
	}

	// Update client address (handles NAT rebinding)
	session.UpdateClientAddr(clientAddr)

	return session, nil
}

// Delete removes a session and closes its connection.
func (m *ServerSessionManager) Delete(clientSessionID uint64) {
	m.mu.Lock()
	session, exists := m.sessions[clientSessionID]
	if exists {
		delete(m.sessions, clientSessionID)
	}
	m.mu.Unlock()

	if exists && session != nil {
		session.Close()
	}
}

// cleanupLoop runs in the background to remove expired sessions.
func (m *ServerSessionManager) cleanupLoop() {
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

// cleanup removes sessions that haven't been seen recently.
// SIP022 spec: "Each relay session MUST be remembered for at least 60 seconds"
func (m *ServerSessionManager) cleanup() {
	now := time.Now()

	m.mu.Lock()
	var toClose []*ServerSession
	for sessionID, session := range m.sessions {
		if now.Sub(session.LastUsed()) > m.timeout {
			toClose = append(toClose, session)
			delete(m.sessions, sessionID)
		}
	}
	m.mu.Unlock()

	// Close connections outside the lock
	for _, session := range toClose {
		session.Close()
	}
}

// Close stops the cleanup loop and closes all sessions.
func (m *ServerSessionManager) Close() error {
	close(m.stop)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		session.Close()
	}
	m.sessions = make(map[uint64]*ServerSession)

	return nil
}
