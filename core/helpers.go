package core

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func Increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func GCMWithAES(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func Base64Decode(password string) ([]byte, error) {
	new_key := make([]byte, base64.StdEncoding.DecodedLen(len(password)))
	n, err := base64.StdEncoding.Decode(new_key, []byte(password))
	if err != nil {
		return nil, err
	}

	return new_key[:n], nil
}

func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("byte slices must have the same length for XOR operation")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}
