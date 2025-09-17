package core

import (
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/internal"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead_2022"
)

// ErrCipherNotSupported occurs when a cipher is not supported (likely because of security concerns).
var ErrCipherNotSupported = errors.New("cipher not supported")
var ErrSIP022Key = errors.New("SIP022 cannot derive key from password, user must directly pass the key with base64 encoding")

const (
	aeadAes128Gcm             = "AEAD_AES_128_GCM"
	aeadAes256Gcm             = "AEAD_AES_256_GCM"
	aeadChacha20Poly1305      = "AEAD_CHACHA20_POLY1305"
	aeadAes128Gcm_2022        = "2022_BLAKE3_AES_128_GCM"
	aeadAes256Gcm_2022        = "2022_BLAKE3_AES_256_GCM"
	aeadChacha20Poly1305_2022 = "2022_BLAKE3_CHACHA20_POLY1305"
)

// List of AEAD ciphers: key size in bytes and constructor
var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (internal.ShadowCipher, error)
}{
	aeadAes128Gcm:             {16, shadowaead.AESGCM},
	aeadAes256Gcm:             {32, shadowaead.AESGCM},
	aeadChacha20Poly1305:      {32, shadowaead.Chacha20Poly1305},
	aeadAes128Gcm_2022:        {16, shadowaead2022.AESGCM},
	aeadAes256Gcm_2022:        {32, shadowaead2022.AESGCM},
	aeadChacha20Poly1305_2022: {32, shadowaead2022.Chacha20Poly1305},
}

// ListCipher returns a list of available cipher names sorted alphabetically.
func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
func PickCipher(name string, key []byte, password string) (internal.ShadowCipher, error) {
	name = strings.ToUpper(name)

	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "CHACHA20-IETF-POLY1305":
		name = aeadChacha20Poly1305
	case "AES-128-GCM":
		name = aeadAes128Gcm
	case "AES-256-GCM":
		name = aeadAes256Gcm
	case "2022-BLAKE3-CHACHA20-POLY1305":
		name = aeadChacha20Poly1305_2022
	case "2022-BLAKE3-AES-128-GCM":
		name = aeadAes128Gcm_2022
	case "2022-BLAKE3-AES-256-GCM":
		name = aeadAes256Gcm_2022
	}

	if choice, ok := aeadList[name]; ok {
		// SIP022
		if strings.HasPrefix(name, "2022") {
			if len(key) == 0 {
				new_key := make([]byte, base64.StdEncoding.DecodedLen(len(password)))
				n, err := base64.StdEncoding.Decode(new_key, []byte(password))
				key = new_key[:n]

				if err != nil {
					return nil, err
				}
			}
		} else {
			if len(key) == 0 {
				key = kdf(password, choice.KeySize)
			}
		}

		if len(key) != choice.KeySize {
			return nil, internal.KeySizeError(choice.KeySize)
		}

		return choice.New(key)
	}

	return nil, ErrCipherNotSupported
}

// dummy cipher does not encrypt
type dummy struct{}

func (dummy) KeySize() int { return 0 }
func (dummy) SaltSize() int {
	return 0
}
func (dummy) Encrypter(salt []byte) (cipher.AEAD, error) {
	return nil, nil
}
func (dummy) Decrypter(salt []byte) (cipher.AEAD, error) {
	return nil, nil
}
func (dummy) StreamConn(c net.Conn, role int) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn, role int) net.PacketConn { return c }

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
