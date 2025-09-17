package utils

import (
	"net"
	"net/netip"
)

const (
	ROLE_UNKNOWN int = 0
	ROLE_CLIENT  int = 1
	ROLE_SERVER  int = 2
)

type UDPConn interface {
	net.PacketConn
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}
