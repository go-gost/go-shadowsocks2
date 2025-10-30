package core

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type TCPServer struct {
	config   ServerConfig
	listener *net.TCPListener
}

func NewTCPServer(config ServerConfig) TCPServer {
	server := TCPServer{
		config: config,
	}

	return server
}

func (s *TCPServer) Init() error {
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(s.config.Addr))
	if err != nil {
		return err
	}

	s.listener = l

	return nil
}

// TODO: TCPCork
func (s *TCPServer) Start() error {
	for {
		c, err := s.listener.AcceptTCP()
		if err != nil {
			return err
		}

		go func() {
			defer c.Close()

			tcpConfig := TCPConfig{Users: s.config.Users}
			sc := s.config.Cipher.TCPConn(c, tcpConfig, ROLE_SERVER)

			target, err := sc.InitServer()

			if err != nil {
				logWarn("failed to init TCP connection from %v: %v", c.RemoteAddr(), err)
				return
			}

			targetConn, err := net.Dial("tcp", target.String())
			if err != nil {
				logWarn("failed to connect remote target %v: %v", target, err)
				return
			}
			defer targetConn.Close()

			if err = relay(sc, targetConn); err != nil {
				logWarn("relay between %v <--> %v has been broken: %v", sc.RemoteAddr(), targetConn.RemoteAddr(), err)
			}
		}()
	}
}

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
