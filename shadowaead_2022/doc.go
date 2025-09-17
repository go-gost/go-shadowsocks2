/*
Package shadowaead2022 implements the Shadowsocks 2022 AEAD ciphers.

The Shadowsocks 2022 protocol enhances security over the original shadowaead
implementation through:

1. BLAKE3-based key derivation instead of HKDF-SHA1
2. Pre-shared key (PSK) authentication
3. Salt size equals key size for better security
4. Enhanced replay protection

Supported ciphers:
  - 2022-blake3-aes-128-gcm
  - 2022-blake3-aes-256-gcm
  - 2022-blake3-chacha20-poly1305

The package provides both stream (TCP) and packet (UDP) connection wrappers
that automatically handle encryption/decryption with salt generation and
replay attack mitigation.
*/
package shadowaead2022
