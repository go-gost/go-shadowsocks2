package core

import (
	"net"
	"net/netip"
	"sync"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type TCPClient struct {
	config ClientConfig
}

func NewTCPClient(config ClientConfig) TCPClient {
	return TCPClient{
		config: config,
	}
}

func (c *TCPClient) Dial(target socks.Addr, server netip.AddrPort) (net.Conn, error) {
	tcpConn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(server))
	if err != nil {
		return nil, err
	}

	return c.WrapConn(tcpConn, target)
}

func (c *TCPClient) WrapConn(conn net.Conn, target socks.Addr) (net.Conn, error) {
	tcpConn := c.config.Cipher.TCPConn(conn, nil, ROLE_CLIENT)

	return &tcpClientConn{
		Conn:   conn,
		core:   tcpConn,
		target: target,
	}, nil
}

type tcpClientConn struct {
	net.Conn
	core   TCPConn
	target socks.Addr
	init   sync.Once
	err    error
}

func (c *tcpClientConn) Read(b []byte) (int, error) {
	c.init.Do(c.doInit)
	if c.err != nil {
		return 0, c.err
	}
	return c.core.Read(b)
}

func (c *tcpClientConn) Write(b []byte) (int, error) {
	c.init.Do(c.doInit)
	if c.err != nil {
		return 0, c.err
	}
	return c.core.Write(b)
}

func (c *tcpClientConn) doInit() {
	if err := c.core.InitClient(c.target); err != nil {
		c.err = err
		return
	}
	if err := c.core.ClientFirstWrite(); err != nil {
		c.err = err
	}
}
