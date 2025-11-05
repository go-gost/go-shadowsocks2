package main

import (
	"net"
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func udpSocksLocal(laddr, server netip.AddrPort, config core.ClientConfig) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()
	logf("listen udp on: %v", laddr)

	udpClient := core.NewUDPClient(config, 60)
	buf := make([]byte, 64*1024)

	connMap := make(map[netip.AddrPort]*net.UDPConn)
	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		tgt := socks.SplitAddr(buf[3:])
		session, encrypted, err := udpClient.Inbound(buf[3+len(tgt):n], raddr, tgt)
		if err != nil {
			logf("cannot write data to server: %v", err)
			continue
		}

		pc, _ := connMap[session.ClientAddr()]
		if pc == nil {
			pc, err = net.ListenUDP("udp", nil)
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}
			connMap[session.ClientAddr()] = pc

			go func() {
				buf := make([]byte, 64*1024)
				for {
					n, addr, err := pc.ReadFromUDPAddrPort(buf)
					if err != nil {
						logf("faled to read data from target: %v", err)
						return
					}

					payload, err := udpClient.Outbound(buf[:n], session)
					if err != nil {
						logf("failed to handle returned data from target: %v", err)
						return
					}

					_, err = c.WriteToUDPAddrPort(payload, session.ClientAddr())
					if err != nil {
						logf("failed to writeback data to %v: %v", addr, err)
						return
					}

				}
			}()
		}

		_, err = pc.WriteToUDPAddrPort(encrypted, server)
		if err != nil {
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

	server := core.NewUDPServer(config, 60*time.Second)
	if err := server.Init(); err != nil {
		logf("failed to init udp server: %v", err)
	}

	buf := make([]byte, 64*1024)
	connMap := make(map[uint64]*net.UDPConn)
	for {
		n, raddr, err := cc.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP remote read error: %v", err)
			continue
		}

		session, payload, err := server.Inbound(buf[:n], raddr)
		if err != nil {
			logf("failed to inspect packet: %v", err)
			continue
		}

		pc := connMap[session.SessionID()]
		if pc == nil {
			pc, err = net.ListenUDP("udp", nil)
			if err != nil {
				logf("UDP remote listen error: %v", err)
				continue
			}
			connMap[session.SessionID()] = pc

			go func() {
				buf := make([]byte, 64*1024)
				for {
					n, addr, err := pc.ReadFromUDPAddrPort(buf)
					if err != nil {
						logf("faled to read data from target: %v", err)
						return

					}

					encrypted, err := server.Outbound(buf[:n], session)
					if err != nil {
						logf("failed to handle returned data from target: %v", err)
						return
					}

					_, err = cc.WriteToUDPAddrPort(encrypted, session.ClientAddr())
					if err != nil {
						logf("failed to writeback data to %v: %v", addr, err)
						return
					}

				}
			}()
		}

		targetAddr, _ := session.Target().ToAddrPort()
		_, err = pc.WriteToUDPAddrPort(payload, targetAddr)
		if err != nil {
			logf("UDP remote write error: %v", err)
			continue
		}
	}
}
