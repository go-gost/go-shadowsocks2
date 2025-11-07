package core

import (
	"crypto/cipher"
	"strconv"
)

const (
	ROLE_UNKNOWN int = 0
	ROLE_CLIENT  int = 1
	ROLE_SERVER  int = 2
)

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

type MetaCipher struct {
	Name      string
	KeySize   int
	SaltSize  int
	NonceSize int
	TagSize   int
}

type ShadowCipher interface {
	TCPConnCipher
	UDPConnCipher
	SaltSize() int
	KeySize() int
	NonceSize() int
	TagSize() int
	Encrypter(key, salt []byte) (cipher.AEAD, error)
	Decrypter(key, salt []byte) (cipher.AEAD, error)
	// Start from SIP023, the cipher can hold multiple keys for clients
	// For server, user configuration should bind to implementation, ShadowCipher just save the main key
	Keys() [][]byte
	Key() []byte      // return last key
	FirstKey() []byte // return first key
}
