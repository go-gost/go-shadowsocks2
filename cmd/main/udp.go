package main

import (
	"net"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func udpSocksLocal(laddr string, config core.ClientConfig) {
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
	logf("listen udp on: %v", laddr)

	udpClient := core.NewUDPClient(config, 60)
	buf := make([]byte, 64*1024)

	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		tgt := socks.SplitAddr(buf[3:])
		session, err := udpClient.WriteTo(buf[3+len(tgt):n], raddr, tgt)
		if err != nil {
			logf("cannot write data to server: %v", err)
			continue
		}

		if !session.Returning() {
			session.Return(true)

			go func() {
				for {
					payload, err := udpClient.ReadFrom(session)
					if err != nil {
						logf("cannot receive data from server: %v", err)
						return
					}
					resp := []byte{0, 0, 0}
					resp = append(resp, tgt...)
					_, err = c.WriteToUDPAddrPort(append(resp, payload...), session.ClientAddr())
					if err != nil {
						logf("cannot write data to app: %v", err)
						return
					}
				}
			}()
		}
	}
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(config core.ServerConfig) {
	server := core.NewUDPServer(config, 60*time.Second)
	err := server.Init()
	if err != nil {
		logf("failed to init udp server: %v", err)
	}

	if err := server.Start(); err != nil {
		logf("server error: %v", err)
	}
}
