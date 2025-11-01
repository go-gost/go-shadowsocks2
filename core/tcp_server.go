package core

import (
	"net"
)

type TCPServer struct {
	config   ServerConfig
	listener *net.TCPListener
}

func NewTCPServer(config ServerConfig) TCPServer {
	server := TCPServer{
		config: config,
	}

	return server
}

// This is a block function
func (s *TCPServer) WrapConn(conn *net.TCPConn) (TCPConn, error) {
	tcpConfig := TCPConfig{Users: s.config.Users}
	sc := s.config.Cipher.TCPConn(conn, tcpConfig, ROLE_SERVER)

	err := sc.InitServer()
	if err != nil {
		return nil, err
	}

	return sc, nil
}

func (s *TCPServer) Init() error {
	return nil
}
