package core

import (
	"net"
	"time"
)

type UDPServer struct {
	config         ServerConfig
	conn           UDPConn
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
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(s.config.Addr))
	if err != nil {
		return err
	}

	s.conn = conn

	return nil
}

// All complexity is hidden behind the UDPSessionManager interface.
func (s *UDPServer) Start() error {
	buf := make([]byte, 64*1024)

	// Main relay loop
	for {
		n, clientAddr, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			logWarn("failed to read data from udp connection(from %v): %v", clientAddr, err)
			continue
		}

		session, err := s.sessionManager.ServerHandleReceive(buf[:n], clientAddr)
		if err != nil {
			logWarn("failed to handle data received from %v: %v", clientAddr, err)
			continue
		}

		// Start return traffic handler if not already running
		if !session.Returning() {
			session.Return(true)
			go s.handleReturnTraffic(session)
		}
	}
}

// handleReturnTraffic handles return traffic from target back to client.
// This goroutine reads from the outbound connection and sends encrypted responses.
func (s *UDPServer) handleReturnTraffic(session UDPSession) {
	for {
		encrypted, err := s.sessionManager.ServerHandleReturn(session)
		if err != nil {
			return
		}

		clientAddr := session.ClientAddr()
		_, err = s.conn.WriteToUDPAddrPort(encrypted, clientAddr)
		if err != nil {
			logWarn("failed to write data to %v: %v", clientAddr, err)
			return
		}
	}
}
