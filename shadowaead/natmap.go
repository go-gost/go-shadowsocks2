package shadowaead

import (
	"net/netip"
	"sync"
	"time"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type Mode int

const (
	RemoteServer Mode = iota
	RelayClient
	SocksClient
)

// SessionManager is a session table mapping client addresses to sessions.
// For AEAD: stateless NAT, no session IDs.
type SessionManager struct {
	sync.RWMutex
	m       map[netip.AddrPort]*aeadSession
	timeout time.Duration
	stop    chan bool
}

func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		m:       make(map[netip.AddrPort]*aeadSession),
		timeout: timeout,
		stop:    make(chan bool),
	}
	go sm.cleanLoop()
	return sm
}

func (m *SessionManager) Get(key netip.AddrPort) *aeadSession {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *SessionManager) Set(key netip.AddrPort, session *aeadSession) {
	m.Lock()
	defer m.Unlock()
	m.m[key] = session
}

func (m *SessionManager) Del(key netip.AddrPort) *aeadSession {
	m.Lock()
	defer m.Unlock()

	session, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return session
	}
	return nil
}

func (m *SessionManager) GetOrCreate(clientAddr netip.AddrPort, target socks.Addr) *aeadSession {
	m.Lock()
	defer m.Unlock()

	if session, exists := m.m[clientAddr]; exists {
		return session
	}

	session := newAEADSession(target, clientAddr)
	m.m[clientAddr] = session
	return session
}

// Close stops the cleanup loop and closes all sessions.
func (m *SessionManager) Close() error {
	close(m.stop)

	m.Lock()
	defer m.Unlock()

	for _, session := range m.m {
		session.Close()
	}
	m.m = make(map[netip.AddrPort]*aeadSession)

	return nil
}

// cleanLoop periodically removes expired sessions.
// Runs every timeout/2 to ensure timely cleanup.
func (m *SessionManager) cleanLoop() {
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

// cleanup removes sessions that haven't been used for longer than timeout.
func (m *SessionManager) cleanup() {
	now := time.Now()
	var toDelete []*aeadSession

	// Find expired sessions
	m.RLock()
	for _, session := range m.m {
		if now.Sub(session.LastUsed()) > m.timeout {
			toDelete = append(toDelete, session)
		}
	}
	m.RUnlock()

	// Delete and close expired sessions
	if len(toDelete) > 0 {
		m.Lock()
		for _, session := range toDelete {
			if _, ok := m.m[session.ClientAddr()]; ok {
				delete(m.m, session.ClientAddr())
				session.Close()
			}
		}
		m.Unlock()
	}
}
