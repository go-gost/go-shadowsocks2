package core

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/go-gost/go-shadowsocks2/socks"
)

// Clients create UDP relay sessions based on source address and port.
// When a client receives a packet from a new source address and port,
// it opens a new relay session, and subsequent packets from that source are sent over the same session.
type UDPClient struct {
	config         ClientConfig
	sessionManager UDPSessionManager
}

func NewUDPClient(config ClientConfig) UDPClient {
	return UDPClient{
		config:         config,
		sessionManager: config.Cipher.NewUDPSessionManager(config.UDPTimeout, nil, 2000, ROLE_CLIENT),
	}
}

func (c *UDPClient) Init() error {
	if c.config.ServerAddr == (netip.AddrPort{}) {
		return errors.New("udp server address is required")
	}
	return nil
}

func (c *UDPClient) handleInbound(payload []byte, clientAddr netip.AddrPort, target socks.Addr) (UDPSession, []byte, error) {
	session, encryted, err := c.sessionManager.ClientHandleInbound(payload, target, clientAddr)
	if err != nil {
		return nil, nil, err
	}

	return session, encryted, nil
}

func (c *UDPClient) handleOutbound(encryted []byte, session UDPSession) ([]byte, error) {
	return c.sessionManager.ClientHandleOutbound(encryted, session)
}

func (c *UDPClient) WrapConn(pc net.PacketConn) net.PacketConn {
	return &udpClientConn{
		PacketConn: pc,
		client:     c,
	}
}

type udpClientConn struct {
	net.PacketConn
	client         *UDPClient
	sessionMap     sync.Map
	mu             sync.RWMutex
	lastSourceAddr netip.AddrPort
}

type udpClientTargetAddr struct {
	targetAddr socks.Addr
	sourceAddr net.Addr
}

func (a udpClientTargetAddr) Network() string {
	if a.targetAddr == nil {
		return "udp"
	}
	return "udp"
}

func (a udpClientTargetAddr) String() string {
	if a.targetAddr == nil {
		return ""
	}
	return a.targetAddr.String()
}

func (a udpClientTargetAddr) TargetAddr() socks.Addr {
	return a.targetAddr
}

func (a udpClientTargetAddr) SourceAddr() net.Addr {
	return a.sourceAddr
}

func NewUDPClientPacketAddr(targetAddr socks.Addr, sourceAddr net.Addr) net.Addr {
	return udpClientTargetAddr{targetAddr: targetAddr, sourceAddr: sourceAddr}
}

func addrPortFromNetAddr(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap
	}
	return netip.AddrPort{}
}

func (c *udpClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 65535)
	nr, _, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	var sourceAddr netip.AddrPort
	c.mu.RLock()
	sourceAddr = c.lastSourceAddr
	c.mu.RUnlock()
	if sourceAddr == (netip.AddrPort{}) {
		return 0, nil, errors.New("udp source address is required")
	}

	s, ok := c.sessionMap.Load(SessionHashFromAddrPort(sourceAddr))
	if !ok {
		return 0, nil, errors.New("udp session not found")
	}
	session := s.(UDPSession)

	payload, err := c.client.handleOutbound(buf[:nr], session)
	if err != nil {
		return 0, nil, err
	}
	if session.Target() == nil {
		return 0, nil, errors.New("udp target address is required")
	}

	n = copy(p, payload)
	addr = NewUDPClientPacketAddr(session.Target(), net.UDPAddrFromAddrPort(session.ClientAddr()))

	return n, addr, nil
}

func (c *udpClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ctx, ok := addr.(udpClientTargetAddr)
	if !ok {
		return 0, errors.New("udp source context not found")
	}
	targetAddr := ctx.TargetAddr()
	sourceAddr := addrPortFromNetAddr(ctx.SourceAddr())
	if sourceAddr == (netip.AddrPort{}) {
		return 0, errors.New("udp source address is required")
	}

	c.mu.RLock()
	lastSourceAddr := c.lastSourceAddr
	c.mu.RUnlock()
	if lastSourceAddr != sourceAddr {
		c.mu.Lock()
		// although we acquire lock to prevent parallel writing, this field should not be changed for every connection
		c.lastSourceAddr = sourceAddr
		c.mu.Unlock()
	}

	session, encrypted, err := c.client.handleInbound(p, sourceAddr, targetAddr)
	if err != nil {
		return 0, err
	}
	c.sessionMap.Store(SessionHashFromAddrPort(sourceAddr), session)

	_, err = c.PacketConn.WriteTo(encrypted, net.UDPAddrFromAddrPort(c.client.config.ServerAddr))
	return len(p), err
}
