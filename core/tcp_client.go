package core

import (
	"net"
	"net/netip"

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

func (c *TCPClient) Dial(target socks.Addr, server netip.AddrPort, padding, initialPayload []byte) (TCPConn, error) {
	tcpConn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(server))
	if err != nil {
		return nil, err
	}

	tcpConfig := TCPConfig{}
	conn := c.config.Cipher.TCPConn(tcpConn, tcpConfig, ROLE_CLIENT)
	err = conn.InitClient(target, padding, initialPayload)

	return conn, nil
}
