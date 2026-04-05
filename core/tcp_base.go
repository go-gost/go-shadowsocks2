package core

import (
	"net"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type TCPConn interface {
	net.Conn

	InitServer() error                  // for server side
	InitClient(target socks.Addr) error // for client side
	Target() socks.Addr

	ClientFirstWrite() error // send headers, for fast opening
	ClientID() string
}

type TCPConnCipher interface {
	TCPConn(net.Conn, []UserConfig, int) TCPConn
}
