package shadowaead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrRepeatedSalt means detected a reused salt
var ErrRepeatedSalt = errors.New("repeated salt detected")

type cp struct {
	psk      []byte
	meta     core.MetaCipher
	makeAEAD func([]byte) (cipher.AEAD, error)
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

func (a *cp) Key() []byte {
	return a.psk
}

func (a *cp) Keys() [][]byte {
	return nil
}

func (a *cp) FirstKey() []byte {
	return nil
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

func (a *cp) Encrypter(_, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}
func (a *cp) Decrypter(_, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}

func (a *cp) TCPConn(c net.Conn, config core.TCPConfig, role int) core.TCPConn {
	return NewConn(c, a)
}

func (a *cp) NewUDPSessionManager(timeout time.Duration, config core.UDPConfig, windowSize, role int) core.UDPSessionManager {
	return NewAEADSessionManager(a, timeout, role)
}

func (a *cp) AdditionalHeaders(salt []byte) ([]byte, error) { return nil, nil }

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
func AESGCM(meta core.MetaCipher, password string) (core.ShadowCipher, error) {
	psk := kdf(password, meta.KeySize)
	switch l := len(psk); l {
	case 16, 24, 32: // AES 128/196/256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &cp{psk: psk, meta: meta, makeAEAD: core.GCMWithAES}, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func Chacha20Poly1305(meta core.MetaCipher, password string) (core.ShadowCipher, error) {
	psk := kdf(password, meta.KeySize)
	if len(psk) != meta.KeySize {
		return nil, core.KeySizeError(chacha20poly1305.KeySize)
	}
	return &cp{psk: psk, meta: meta, makeAEAD: chacha20poly1305.New}, nil
}

// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
