package main

import (
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

func udpClientAssociationKey(clientAddr netip.AddrPort, target socks.Addr) string {
	return clientAddr.String() + "|" + strconv.Itoa(len(target)) + "|" + string(target)
}

func udpPacketTargetAddr(addr net.Addr) net.Addr {
	if targetCarrier, ok := addr.(interface{ TargetAddr() net.Addr }); ok && targetCarrier.TargetAddr() != nil {
		return targetCarrier.TargetAddr()
	}
	return addr
}

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func udpSocksLocal(laddr, server netip.AddrPort, config core.ClientConfig) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()
	logf("listen udp on: %v", laddr)

	udpClient := core.NewUDPClient(config)
	if err := udpClient.Init(); err != nil {
		logf("failed to init udp client: %v", err)
		return
	}

	var clients sync.Map
	buf := make([]byte, 64*1024)

	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		tgt := socks.SplitAddr(buf[3:])
		if tgt == nil {
			logf("UDP local read error: invalid target header")
			continue
		}

		key := udpClientAssociationKey(raddr, tgt)
		wrappedAny, ok := clients.Load(key)
		if !ok {
			pc, err := net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}
			wrapped := udpClient.WrapConn(pc)
			actual, loaded := clients.LoadOrStore(key, wrapped)
			if loaded {
				wrappedAny = actual
				pc.Close()
			} else {
				wrappedAny = wrapped
				go func(associationKey string, clientAddr netip.AddrPort, conn net.PacketConn) {
					defer func() {
						clients.Delete(associationKey)
						conn.Close()
					}()

					buf := make([]byte, 64*1024)
					for {
						n, addr, err := conn.ReadFrom(buf)
						if err != nil {
							logf("failed to read data from server: %v", err)
							return
						}

						target := socks.ParseAddr(addr.String())
						if target == nil {
							logf("failed to parse returned target address: %v", addr)
							return
						}

						resp := append([]byte{0, 0, 0}, target...)
						resp = append(resp, buf[:n]...)

						if _, err := c.WriteToUDPAddrPort(resp, clientAddr); err != nil {
							logf("failed to writeback data to %v: %v", clientAddr, err)
							return
						}
					}
				}(key, raddr, wrapped)
			}
		}

		wrapped, _ := wrappedAny.(net.PacketConn)
		if _, err := wrapped.WriteTo(buf[3+len(tgt):n], core.NewUDPClientPacketAddr(tgt, net.UDPAddrFromAddrPort(raddr))); err != nil {
			logf("UDP local write error: %v", err)
			continue
		}
	}
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(addr netip.AddrPort, config core.ServerConfig) {
	cc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		logf("UDP remote listen error: %v", err)
		return
	}
	defer cc.Close()

	server := core.NewUDPServer(config)
	if err := server.Init(); err != nil {
		logf("failed to init udp server: %v", err)
	}
	wrapped := server.WrapConn(cc)

	buf := make([]byte, 64*1024)
	for {
		n, targetAddr, err := wrapped.ReadFrom(buf)
		if err != nil {
			logf("UDP remote read error: %v", err)
			continue
		}

		ctx, ok := targetAddr.(interface {
			net.Addr
			Session() core.UDPSession
		})
		if !ok {
			logf("UDP remote read error: missing session context for %v", targetAddr)
			continue
		}
		session := ctx.Session()
		if session == nil {
			logf("UDP remote read error: missing session for %v", targetAddr)
			continue
		}

		pc := session.Conn()
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP remote listen error: %v", err)
				continue
			}
			session.SetConn(pc)

			go func(ctx net.Addr, conn net.PacketConn) {
				buf := make([]byte, 64*1024)
				for {
					n, replyAddr, err := conn.ReadFrom(buf)
					if err != nil {
						logf("failed to read data from target: %v", err)
						return
					}

					replyCtx, ok := ctx.(interface {
						net.Addr
						Session() core.UDPSession
						ClientAddr() net.Addr
					})
					if !ok {
						logf("failed to writeback data to %v: missing session context", ctx)
						return
					}

					if _, err := wrapped.WriteTo(buf[:n], core.NewUDPServerPacketAddr(replyAddr, replyCtx.ClientAddr(), replyCtx.Session())); err != nil {
						logf("failed to writeback data to %v: %v", ctx, err)
						return
					}
				}
			}(targetAddr, pc)
		}

		if _, err := pc.WriteTo(buf[:n], udpPacketTargetAddr(targetAddr)); err != nil {
			logf("UDP remote write error: %v", err)
			continue
		}
	}
}
