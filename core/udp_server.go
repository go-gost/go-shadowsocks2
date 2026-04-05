package core

import (
	"errors"
	"net"
	"net/netip"

	"github.com/go-gost/go-shadowsocks2/socks"
)

// Servers manage UDP relay sessions by session ID.
// Each client session corresponds to one outgoing UDP socket on the server.
type UDPServer struct {
	config         ServerConfig
	sessionManager UDPSessionManager
}

func NewUDPServer(config ServerConfig) UDPServer {
	return UDPServer{
		config:         config,
		sessionManager: config.Cipher.NewUDPSessionManager(config.UDPTimeout, config.Users, 2000, ROLE_SERVER),
	}
}

func (s *UDPServer) Init() error {
	return nil
}

func (s *UDPServer) handleInbound(encrypted []byte, clientAddr netip.AddrPort) (UDPSession, socks.Addr, []byte, error) {
	session, target, payload, err := s.sessionManager.ServerHandleInbound(encrypted, clientAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	return session, target, payload, nil
}

func (s *UDPServer) handleOutbound(plaintext []byte, target socks.Addr, session UDPSession) ([]byte, error) {
	encrypted, err := s.sessionManager.ServerHandleOutbound(plaintext, target, session)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func (s *UDPServer) WrapConn(pc net.PacketConn) net.PacketConn {
	return &udpServerConn{
		PacketConn: pc,
		server:     s,
	}
}

type udpServerConn struct {
	net.PacketConn
	server *UDPServer
}

type udpServerTargetAddr struct {
	targetAddr net.Addr
	clientAddr net.Addr
	session    UDPSession
}

func (a udpServerTargetAddr) Network() string {
	if a.targetAddr == nil {
		return "udp"
	}
	return a.targetAddr.Network()
}

func (a udpServerTargetAddr) String() string {
	if a.targetAddr == nil {
		return ""
	}
	return a.targetAddr.String()
}

func (a udpServerTargetAddr) TargetAddr() net.Addr {
	return a.targetAddr
}

func (a udpServerTargetAddr) ClientAddr() net.Addr {
	return a.clientAddr
}

func (a udpServerTargetAddr) Session() UDPSession {
	return a.session
}

func NewUDPServerPacketAddr(targetAddr, clientAddr net.Addr, session UDPSession) net.Addr {
	return udpServerTargetAddr{targetAddr: targetAddr, clientAddr: clientAddr, session: session}
}

func (c *udpServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 65535)
	nr, raddr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	var clientAddr netip.AddrPort
	if ap, err := netip.ParseAddrPort(raddr.String()); err == nil {
		clientAddr = ap
	}

	session, target, payload, err := c.server.handleInbound(buf[:nr], clientAddr)
	if err != nil {
		return 0, nil, err
	}

	n = copy(p, payload)
	targetAddr := net.Addr(raddr)
	if target != nil {
		if udpAddr, err := net.ResolveUDPAddr("udp", target.String()); err == nil {
			targetAddr = udpAddr
		}
	}
	return n, udpServerTargetAddr{targetAddr: targetAddr, clientAddr: raddr, session: session}, nil
}

func (c *udpServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ctx, ok := addr.(interface {
		Session() UDPSession
		ClientAddr() net.Addr
		TargetAddr() net.Addr
	})
	if !ok {
		return 0, errors.New("udp session context not found")
	}

	session := ctx.Session()
	if session == nil {
		return 0, errors.New("udp session not found")
	}

	target := socks.ParseAddr(ctx.TargetAddr().String())
	if target == nil {
		return 0, errors.New("udp target context not found")
	}

	encrypted, err := c.server.handleOutbound(p, target, session)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(encrypted, ctx.ClientAddr())
	return len(p), err
}
