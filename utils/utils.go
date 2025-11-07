package utils

import (
	crand "crypto/rand"
	"errors"
	"math/rand"
	"strings"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/shadowaead"
	shadowaead2022 "github.com/go-gost/go-shadowsocks2/shadowaead_2022"
)

var ErrCipherNotSupported = errors.New("cipher not supported")

var SupportedMethods = map[string]struct {
	meta core.MetaCipher
	New  func(meta core.MetaCipher, password string) (core.ShadowCipher, error)
}{
	"chacha20-ietf-poly1305": {
		meta: core.MetaCipher{
			Name:      "chacha20-ietf-poly1305",
			KeySize:   32,
			SaltSize:  32,
			NonceSize: 12,
			TagSize:   16,
		},
		New: shadowaead.Chacha20Poly1305,
	},
	"aes-256-gcm": {
		meta: core.MetaCipher{
			Name:      "aes-256-gcm",
			KeySize:   32,
			SaltSize:  32,
			NonceSize: 12,
			TagSize:   16,
		},
		New: shadowaead.AESGCM,
	},
	"aes-128-gcm": {
		meta: core.MetaCipher{
			Name:      "aes-128-gcm",
			KeySize:   16,
			SaltSize:  16,
			NonceSize: 12,
			TagSize:   16,
		},
		New: shadowaead.AESGCM,
	},
	"2022-blake3-aes-128-gcm": {
		meta: core.MetaCipher{
			Name:      "2022-blake3-aes-128-gcm",
			KeySize:   16,
			SaltSize:  16,
			NonceSize: 12,
			TagSize:   16,
		},
		New: shadowaead2022.AESGCM,
	},
	"2022-blake3-aes-256-gcm": {
		meta: core.MetaCipher{
			Name:      "2022-blake3-aes-256-gcm",
			KeySize:   32,
			SaltSize:  32,
			NonceSize: 12,
			TagSize:   16,
		},
		New: shadowaead2022.AESGCM,
	},
	// "2022-blake3-chacha20-poly1305": {
	// 	meta: core.MetaCipher{
	// 		Name:      "2022-blake3-chacha20-poly1305",
	// 		KeySize:   32,
	// 		SaltSize:  32,
	// 		NonceSize: 12,
	// 		TagSize:   16,
	// 	},
	// 	New: shadowaead2022.Chacha20Poly1305,
	// },
}

func ListCipher() []string {
	var r []string

	for k := range SupportedMethods {
		r = append(r, k)
	}
	return r
}

// PickCipher returns a Cipher of the given name. Derive key from password
func PickCipher(name string, password string) (core.ShadowCipher, error) {
	name = strings.ToLower(name)
	choice, exist := SupportedMethods[name]

	if !exist {
		return nil, ErrCipherNotSupported
	}

	return choice.New(choice.meta, password)
}

func NewServerConfig(method, password string, users []core.UserConfig) (core.ServerConfig, error) {
	cipher, err := PickCipher(method, password)
	if err != nil {
		return core.ServerConfig{}, err
	}

	config := core.ServerConfig{
		Cipher: cipher,
		Users:  users,
	}

	return config, nil
}

func NewClientConfig(method, password string) (core.ClientConfig, error) {
	cipher, err := PickCipher(method, password)
	if err != nil {
		return core.ClientConfig{}, err
	}

	config := core.ClientConfig{
		Cipher: cipher,
	}

	return config, nil
}

func GeneratePadding() (int, []byte, error) {
	length := rand.Intn(shadowaead2022.MaxPaddingLength)
	padding := make([]byte, length)
	n, err := crand.Read(padding)

	if err != nil {
		return 0, nil, err
	}

	return n, padding[:n], nil
}
