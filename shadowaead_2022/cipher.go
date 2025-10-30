package shadowaead2022

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"strings"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type cp struct {
	psk      [][]byte
	meta     core.MetaCipher
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (a *cp) SaltSize() int {
	return a.meta.SaltSize
}

func (a *cp) KeySize() int {
	return a.meta.KeySize
}

func (a *cp) NonceSize() int {
	return a.meta.NonceSize
}

func (a *cp) TagSize() int {
	return a.meta.TagSize
}

func (a *cp) Key() []byte {
	return a.psk[len(a.psk)-1]
}

func (a *cp) FirstKey() []byte {
	return a.psk[0]
}

func (a *cp) Keys() [][]byte {
	return a.psk
}

func (a *cp) Encrypter(key, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.meta.KeySize)
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), subkey)
	return a.makeAEAD(subkey)
}

func (a *cp) Decrypter(key, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.meta.KeySize)
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), subkey)
	return a.makeAEAD(subkey)
}

func (a *cp) TCPConn(c *net.TCPConn, config core.TCPConfig, role int) core.TCPConn {
	return NewConn(c, a, config, role)
}

func (a *cp) NewUDPSessionManager(timeout time.Duration, config core.UDPConfig, windowSize, role int) core.UDPSessionManager {
	userTable := core.UsersToEIHHash(config.Users)
	return newUDPSessionManager(a, userTable, timeout, windowSize, role)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 32 to select AES-128/256-GCM.
func AESGCM(meta core.MetaCipher, password string) (core.ShadowCipher, error) {
	c := cp{psk: make([][]byte, 0), meta: meta, makeAEAD: core.GCMWithAES}
	s := strings.Split(password, ":")
	for _, v := range s {
		p, err := core.Base64Decode(v)
		if err != nil {
			return nil, err
		}

		c.psk = append(c.psk, p)
	}

	switch l := len(c.Key()); l {
	case 16, 32: // AES 128//256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &c, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func Chacha20Poly1305(meta core.MetaCipher, password string) (core.ShadowCipher, error) {
	c := cp{psk: make([][]byte, 0), meta: meta, makeAEAD: chacha20poly1305.New}

	s := strings.Split(password, ":")
	for _, v := range s {
		p, err := core.Base64Decode(v)
		if err != nil {
			return nil, err
		}

		c.psk = append(c.psk, p)
	}

	if len(c.Key()) != chacha20poly1305.KeySize {
		return nil, core.KeySizeError(chacha20poly1305.KeySize)
	}
	return &c, nil
}
