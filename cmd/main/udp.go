package main

import (
	"net"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	shadowaead2022 "github.com/shadowsocks/go-shadowsocks2/shadowaead_2022"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

const udpBufSize = 64 * 1024

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func udpSocksLocal(cipher, laddr, server string, shadow func(net.PacketConn, int) net.PacketConn) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}

	lnAddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		logf("UDP listen address error: %v", err)
		return
	}

	c, err := net.ListenUDP("udp", lnAddr)
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	natMap := shadowaead.NewNATmap(config.UDPTimeout)
	clientSessionMgr := shadowaead2022.NewClientSessionManager(config.UDPTimeout)
	buf := make([]byte, udpBufSize)

	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		var pc net.PacketConn
		if strings.HasPrefix(cipher, "2022") {
			session := clientSessionMgr.Get(raddr)
			if session != nil {
				pc = session.Conn()
			}
		} else {
			pc = natMap.Get(raddr)
		}

		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}

			tgt := socks.Addr(buf[3:])
			logf("UDP socks tunnel %s <-> %s <-> %s", laddr, server, tgt)
			pc = shadow(pc, utils.ROLE_CLIENT)

			if strings.HasPrefix(cipher, "2022") {
				conn2022 := pc.(*shadowaead2022.PacketConn)

				session := clientSessionMgr.GetOrCreate(raddr, tgt, pc)
				conn2022.SetSession(session)
			} else {
				natMap.Add(raddr, c, pc, udpBufSize, shadowaead.SocksClient)
			}
		}

		_, err = pc.WriteTo(buf[3:n], srvAddr)
		if err != nil {
			logf("UDP local write error: %v", err)
			continue
		}
	}
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(cipher, addr string, shadow func(net.PacketConn, int) net.PacketConn) {
	nAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}
	cc, err := net.ListenUDP("udp", nAddr)
	if err != nil {
		logf("UDP remote listen error: %v", err)
		return
	}
	defer cc.Close()
	c := shadow(cc, utils.ROLE_SERVER).(utils.UDPConn)

	natMap := shadowaead.NewNATmap(config.UDPTimeout)
	if strings.HasPrefix(cipher, "2022") {
		serverSessionMgr := shadowaead2022.NewServerSessionManager(config.UDPTimeout, 2000)
		conn2022 := c.(*shadowaead2022.PacketConn)
		conn2022.SetServerSessionManager(serverSessionMgr)
	}

	buf := make([]byte, udpBufSize)

	logf("listening UDP on %s", addr)
	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP remote read error: %v", err)
			continue
		}

		if !strings.HasPrefix(cipher, "2022") {
			tgtAddr := socks.SplitAddr(buf[:n])
			if tgtAddr == nil {
				logf("failed to split target address from packet: %q", buf[:n])
				continue
			}

			tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
			if err != nil {
				logf("failed to resolve target UDP address: %v", err)
				continue
			}

			payload := buf[len(tgtAddr):n]

			pc := natMap.Get(raddr)
			if pc == nil {
				pc, err = net.ListenPacket("udp", "")
				if err != nil {
					logf("UDP remote listen error: %v", err)
					continue
				}

				natMap.Add(raddr, c, pc, udpBufSize, shadowaead.RemoteServer)
			}

			_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				logf("UDP remote write error: %v", err)
				continue
			}
		}
	}
}
