package core

import (
	"net/netip"
	"time"

	"github.com/go-gost/go-shadowsocks2/socks"
)

// Clients create UDP relay sessions based on source address and port.
// When a client receives a packet from a new source address and port,
// it opens a new relay session, and subsequent packets from that source are sent over the same session.
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

func (c *UDPClient) Inbound(payload []byte, clientAddr netip.AddrPort, target socks.Addr) (UDPSession, []byte, error) {
	session, encryted, err := c.sessionManager.ClientHandleInbound(payload, target, clientAddr)
	if err != nil {
		return nil, nil, err
	}

	return session, encryted, nil
}

func (c *UDPClient) Outbound(encryted []byte, session UDPSession) ([]byte, error) {
	return c.sessionManager.ClientHandleOutbound(encryted, session)
}
