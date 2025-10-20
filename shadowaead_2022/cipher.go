package shadowaead2022

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/shadowsocks/go-shadowsocks2/internal"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
)

type metaCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (a *metaCipher) KeySize() int { return len(a.psk) }
func (a *metaCipher) SaltSize() int {
	return len(a.psk)
}

func (a *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(a.psk, salt...), subkey)
	return a.makeAEAD(subkey)
}
func (a *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(a.psk, salt...), subkey)
	return a.makeAEAD(subkey)
}

func (a *metaCipher) StreamConn(c net.Conn, role int) net.Conn { return NewConn(c, a, role) }
func (a *metaCipher) PacketConn(c net.PacketConn, role int) net.PacketConn {
	return NewPacketConn(c, a, a.psk, role)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 32 to select AES-128/256-GCM.
func AESGCM(psk []byte) (internal.ShadowCipher, error) {
	switch l := len(psk); l {
	case 16, 32: // AES 128//256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher{psk: psk, makeAEAD: internal.GCMWithAES}, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func Chacha20Poly1305(psk []byte) (internal.ShadowCipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, internal.KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.New}, nil
}
