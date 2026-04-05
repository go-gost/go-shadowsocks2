package shadowaead

import (
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
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
	cache *core.SessionCache[netip.AddrPort, *aeadSession]
}

func NewSessionManager(timeout time.Duration) *SessionManager {
	return &SessionManager{
		cache: core.NewSessionCache[netip.AddrPort, *aeadSession](timeout, func(k netip.AddrPort, v *aeadSession) {
			if v.Conn() != nil {
				v.Conn().Close()
			}
		}),
	}
}

func (m *SessionManager) Get(key netip.AddrPort) *aeadSession {
	session, _ := m.cache.Get(key)
	return session
}

func (m *SessionManager) Set(key netip.AddrPort, session *aeadSession) {
	m.cache.Put(key, session)
}

func (m *SessionManager) Del(key netip.AddrPort) *aeadSession {
	session, ok := m.cache.Get(key)
	if ok {
		m.cache.Delete(key)
		return session
	}
	return nil
}

func (m *SessionManager) GetOrCreate(clientAddr netip.AddrPort, target socks.Addr) *aeadSession {
	if session, exists := m.cache.Get(clientAddr); exists {
		return session
	}

	session := newAEADSession(target, clientAddr)
	m.cache.Put(clientAddr, session)
	return session
}

// Close stops the cleanup loop and closes all sessions.
func (m *SessionManager) Close() error {
	return m.cache.Close()
}
