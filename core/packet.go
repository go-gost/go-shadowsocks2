package core

import (
	"github.com/shadowsocks/go-shadowsocks2/internal"
	"net"
)

func ListenPacket(network, address string, ciph internal.PacketConnCipher) (net.PacketConn, error) {
	c, err := net.ListenPacket(network, address)
	return ciph.PacketConn(c, 0), err
}
