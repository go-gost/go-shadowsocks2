package core

import (
	"time"
)

type UDPConfig struct {
	Users []UserConfig
}

type UDPConnCipher interface {
	NewUDPSessionManager(timeout time.Duration, config UDPConfig, windowSize, role int) UDPSessionManager
}
