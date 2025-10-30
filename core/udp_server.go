package core

import (
	"net/netip"
	"time"
)

type UDPServer struct {
	config         ServerConfig
	sessionManager UDPSessionManager
}

func NewUDPServer(config ServerConfig, timeout time.Duration) UDPServer {
	udpConfig := UDPConfig{Users: config.Users}

	return UDPServer{
		config:         config,
		sessionManager: config.Cipher.NewUDPSessionManager(timeout, udpConfig, 2000, ROLE_SERVER),
	}
}

func (s *UDPServer) Init() error {
	return nil
}

func (s *UDPServer) Inbound(encrypted []byte, clientAddr netip.AddrPort) (UDPSession, []byte, error) {
	session, payload, err := s.sessionManager.ServerHandleInbound(encrypted, clientAddr)
	if err != nil {
		return nil, nil, err
	}
	return session, payload, nil
}

func (s *UDPServer) Outbound(plaintext []byte, session UDPSession) ([]byte, error) {
	encrypted, err := s.sessionManager.ServerHandleOutbound(plaintext, session)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}
