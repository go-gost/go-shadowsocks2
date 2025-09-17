package main

import (
	"bufio"
	crand "crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	shadowaead2022 "github.com/shadowsocks/go-shadowsocks2/shadowaead_2022"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(ciper, addr, server string, shadow func(net.Conn, int) net.Conn) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(ciper, addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(cipher, addr, server string, shadow func(net.Conn, int) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

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

			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			if config.TCPCork {
				rc = timedCork(rc, 10*time.Millisecond, 1280)
			}
			rc = shadow(rc, utils.ROLE_CLIENT)

			if strings.HasPrefix(cipher, "2022") {
				conn2022 := rc.(*shadowaead2022.StreamConn)
				pad := rand.Intn(shadowaead2022.MaxPaddingLength)
				padding := make([]byte, pad)
				_, err := crand.Read(padding)
				if err != nil {
					logf("cannot generate padding")
					return
				}

				conn2022.InitWrite(tgt, padding, nil)

			} else if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
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
func tcpRemote(cipher, addr string, shadow func(net.Conn, int) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			if config.TCPCork {
				c = timedCork(c, 10*time.Millisecond, 1280)
			}
			sc := shadow(c, utils.ROLE_SERVER)

			var tgt socks.Addr
			var err error
			if strings.HasPrefix(cipher, "2022") {
				conn2022 := sc.(*shadowaead2022.StreamConn)
				tgt, err = conn2022.InitRead()
				if err != nil {
					logf("failed to get target address from %v: %v", conn2022.RemoteAddr(), err)
					return
				}
			} else {
				tgt, err = socks.ReadAddr(sc)
				if err != nil {
					logf("failed to get target address from %v: %v", c.RemoteAddr(), err)
					// drain c to avoid leaking server behavioral features
					// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
					_, err = io.Copy(ioutil.Discard, c)
					if err != nil {
						logf("discard error: %v", err)
					}
					return
				}
			}

			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logf("proxy %s <-> %s", c.RemoteAddr(), tgt)
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

type corkedConn struct {
	net.Conn
	bufw   *bufio.Writer
	corked bool
	delay  time.Duration
	err    error
	lock   sync.Mutex
	once   sync.Once
}

func timedCork(c net.Conn, d time.Duration, bufSize int) net.Conn {
	return &corkedConn{
		Conn:   c,
		bufw:   bufio.NewWriterSize(c, bufSize),
		corked: true,
		delay:  d,
	}
}

func (w *corkedConn) Write(p []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.corked {
		w.once.Do(func() {
			time.AfterFunc(w.delay, func() {
				w.lock.Lock()
				defer w.lock.Unlock()
				w.corked = false
				w.err = w.bufw.Flush()
			})
		})
		return w.bufw.Write(p)
	}
	return w.Conn.Write(p)
}
