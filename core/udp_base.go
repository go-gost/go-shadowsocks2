package core

import "time"

type UDPConnCipher interface {
	NewUDPSessionManager(timeout time.Duration, users []UserConfig, windowSize, role int) UDPSessionManager
}
