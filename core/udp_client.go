package core

import (
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/socks"
)

type UDPClient struct {
	config         ClientConfig
	sessionManager UDPSessionManager
}

func NewUDPClient(config ClientConfig, timeout int) UDPClient {
	udpConfig := UDPConfig{}
	return UDPClient{
		config:         config,
		sessionManager: config.Cipher.NewUDPSessionManager(time.Duration(timeout*int(time.Second)), udpConfig, 2000, ROLE_CLIENT),
	}
}

func (c *UDPClient) Init() error {
	return nil
}

func (c *UDPClient) WriteTo(payload []byte, clientAddr netip.AddrPort, target socks.Addr) (UDPSession, error) {
	session, err := c.sessionManager.ClientHandleReceive(payload, target, clientAddr, c.config.Server)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (c *UDPClient) ReadFrom(session UDPSession) ([]byte, error) {
	return c.sessionManager.ClientHandleReturn(session)
}
