package shadowaead

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

type Mode int

const (
	RemoteServer Mode = iota
	RelayClient
	SocksClient
)

// Packet NAT table
type NATMap struct {
	sync.RWMutex
	m       map[netip.AddrPort]net.PacketConn
	timeout time.Duration
}

func NewNATmap(timeout time.Duration) *NATMap {
	m := &NATMap{}
	m.m = make(map[netip.AddrPort]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *NATMap) Get(key netip.AddrPort) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *NATMap) Set(key netip.AddrPort, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *NATMap) Del(key netip.AddrPort) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *NATMap) Add(peer netip.AddrPort, dst utils.UDPConn, src net.PacketConn, bufsize int, role Mode) {
	m.Set(peer, src)

	go func() {
		timedCopy(dst, peer, src, m.timeout, bufsize, role)
		if pc := m.Del(peer); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(dst utils.UDPConn, target netip.AddrPort, src net.PacketConn, timeout time.Duration, bufsize int, role Mode) error {
	buf := make([]byte, bufsize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case RemoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteToUDPAddrPort(buf[:len(srcAddr)+n], target)
		case RelayClient: // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.WriteToUDPAddrPort(buf[len(srcAddr):n], target)
		case SocksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.WriteToUDPAddrPort(append([]byte{0, 0, 0}, buf[:n]...), target)
		}

		if err != nil {
			return err
		}
	}
}
