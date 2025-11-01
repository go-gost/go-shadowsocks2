package main

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/go-shadowsocks2/utils"
)

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(addr, server netip.AddrPort, config core.ClientConfig) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, config, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(addr, server netip.AddrPort, config core.ClientConfig, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
	logf("listen tcp on: %v", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	tcpClient := core.NewTCPClient(config)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tgt, err := getAddr(c)
			if err != nil {
				// UDP: keep the connection until disconnect then free the UDP socket
				if err == socks.InfoUDPAssociate {
					buf := make([]byte, 1)
					// block here
					for {
						_, err := c.Read(buf)
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						logf("UDP Associate End.")
						return
					}
				}

				logf("failed to get target address: %v", err)
				return
			}

			_, padding, err := utils.GeneratePadding()
			if err != nil {
				logf("failed to generate padding: %v", err)
				return
			}
			rc, err := tcpClient.Dial(tgt, server, padding, nil)
			if err != nil {
				logf("failed to dial server: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			if err = relay(rc, c); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

// Listen on addr for incoming connections.
func tcpRemote(addr netip.AddrPort, config core.ServerConfig) {
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)

	server := core.NewTCPServer(config)
	if err := server.Init(); err != nil {
		logf("failed to init tcp server: %v", err)
		return
	}

	for {
		c, err := l.AcceptTCP()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()

			sc, err := server.WrapConn(c)
			if err != nil {
				logf("failed to create shadowsocks connection: %v", err)
				return
			}

			rc, err := net.Dial("tcp", sc.Target().String())
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logf("proxy %s <-> %s", c.RemoteAddr(), sc.Target())
			if err = relay(sc, rc); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}
