package core

import (
	"net"
	"net/netip"
	"time"
)

type UDPConfig struct {
	Users []UserConfig
}

type UDPConn interface {
	net.PacketConn
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}

type UDPConnCipher interface {
	NewUDPSessionManager(timeout time.Duration, config UDPConfig, windowSize, role int) UDPSessionManager
}
