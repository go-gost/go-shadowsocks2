package core

import (
	"net"

	"github.com/go-gost/go-shadowsocks2/socks"
)

// configurartions for shadowsocks TCP connections
type TCPConfig struct {
	Users []UserConfig
}

type TCPConn interface {
	net.Conn

	InitServer() (socks.Addr, error)                                    // for server side
	InitClient(target socks.Addr, padding, initialPayload []byte) error // for client side
}

type TCPConnCipher interface {
	TCPConn(*net.TCPConn, TCPConfig, int) TCPConn
}
