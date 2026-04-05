package core

import (
	"net"
	"sync"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type TCPServer struct {
	config   ServerConfig
	listener *net.TCPListener
}

func NewTCPServer(config ServerConfig) TCPServer {
	return TCPServer{
		config: config,
	}
}

func (s *TCPServer) WrapConn(conn net.Conn) (net.Conn, error) {
	sc := s.config.Cipher.TCPConn(conn, s.config.Users, ROLE_SERVER)

	return &tcpServerConn{
		Conn: conn,
		core: sc,
	}, nil
}

type tcpServerConn struct {
	net.Conn
	core TCPConn
	init sync.Once
	err  error
}

func (c *tcpServerConn) Read(b []byte) (int, error) {
	c.init.Do(c.doInit)
	if c.err != nil {
		return 0, c.err
	}
	return c.core.Read(b)
}

func (c *tcpServerConn) Write(b []byte) (int, error) {
	c.init.Do(c.doInit)
	if c.err != nil {
		return 0, c.err
	}
	return c.core.Write(b)
}

func (c *tcpServerConn) Target() socks.Addr {
	c.init.Do(c.doInit)
	return c.core.Target()
}

func (c *tcpServerConn) doInit() {
	if err := c.core.InitServer(); err != nil {
		c.err = err
	}
}

func (s *TCPServer) Init() error {
	return nil
}
