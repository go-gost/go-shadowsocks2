package core

import (
	"log"
	"net/netip"

	"github.com/zeebo/blake3"
)

type EIHHash [16]byte // Extensible Identity Headers hash

type UserConfig struct {
	Name     string
	Password string
}

type ServerConfig struct {
	Cipher ShadowCipher
	Addr   netip.AddrPort
	Users  []UserConfig
	Logger *log.Logger
}

type ClientConfig struct {
	Cipher ShadowCipher
	Server netip.AddrPort
}

func NewUserConfig(name, password string) UserConfig {
	return UserConfig{Name: name, Password: password}
}

func UsersToEIHHash(users []UserConfig) map[EIHHash]string {
	if len(users) == 0 {
		return nil
	}

	t := make(map[EIHHash]string)
	for _, u := range users {
		h, err := Base64Decode(u.Password)
		sum := blake3.Sum256(h)
		if err == nil {
			t[EIHHash(sum[:16])] = u.Password
		}
	}

	return t
}
