package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"strconv"
)

type ShadowMethod interface {
	StreamConnCipher
	PacketConnCipher
}

type StreamConnCipher interface {
	StreamConn(net.Conn, int) net.Conn
}

type PacketConnCipher interface {
	PacketConn(net.PacketConn, int) net.PacketConn
}

type ShadowCipher interface {
	StreamConnCipher
	PacketConnCipher
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func GCMWithAES(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
