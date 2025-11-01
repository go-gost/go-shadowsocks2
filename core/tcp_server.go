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
// When some errors lead to unexpected closing of conn, the caller MUST act
// in a way that does not exhibit the amount of bytes consumed by the server.
// This defends against probes that send one byte at a time to detect how many
// bytes the server consumes before closing the connection.
func (s *TCPServer) WrapConn(conn net.Conn) (TCPConn, error) {
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
