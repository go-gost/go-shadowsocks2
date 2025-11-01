package shadowaead2022

import (
	"crypto/aes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var (
	ErrShortPacket      = errors.New("short packet")
	ErrInvalidSessionID = errors.New("invalid session ID")
	ErrReplayAttack     = errors.New("replay attack detected")
)

// SeparateHeader represents the UDP separate header (16 bytes)
type SeparateHeader struct {
	SessionID uint64 // 8 bytes
	PacketID  uint64 // 8 bytes
}

// EncodeSeparateHeader encodes separate header to bytes
func EncodeSeparateHeader(header *SeparateHeader) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], header.SessionID)
	binary.BigEndian.PutUint64(buf[8:16], header.PacketID)
	return buf
}

// DecodeSeparateHeader decodes separate header from bytes
func DecodeSeparateHeader(data []byte) (*SeparateHeader, error) {
	if len(data) < 16 {
		return nil, ErrShortPacket
	}
	return &SeparateHeader{
		SessionID: binary.BigEndian.Uint64(data[0:8]),
		PacketID:  binary.BigEndian.Uint64(data[8:16]),
	}, nil
}

// UDPHeader represents the UDP header for both request and response
type UDPHeader struct {
	Type            byte       // HeaderTypeClientStream (0) or HeaderTypeServerStream (1)
	Timestamp       int64      // Unix epoch timestamp (8 bytes)
	ClientSessionID uint64     // Client session ID (8 bytes, only for response)
	PaddingLength   uint16     // Padding length (2 bytes)
	Address         socks.Addr // Target address (request) or Source address (response)
	Padding         []byte     // Random padding
}

// EncodeUDPHeader encodes UDP header for both request and response
func EncodeUDPHeader(header *UDPHeader) []byte {
	var totalLen int
	var buf []byte
	pos := 0

	if header.Type == HeaderTypeClientStream {
		// Request: Type (1) + Timestamp (8) + PaddingLength (2) + Address + Padding
		totalLen = 1 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	} else {
		// Response: Type (1) + Timestamp (8) + ClientSessionID (8) + PaddingLength (2) + Padding + Address
		totalLen = 1 + 8 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint64(buf[pos:], header.ClientSessionID)
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	}

	return buf
}

// DecodeUDPHeader decodes UDP header for both request and response
func DecodeUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 11 { // Minimum: 1 + 8 + 2
		return nil, ErrInvalidHeader
	}

	header := &UDPHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	if err := validateTimestamp(header.Timestamp); err != nil {
		return nil, err
	}

	if header.Type == HeaderTypeClientStream {
		// Request: PaddingLength + Padding + Address
		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
		pos += int(header.PaddingLength)

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
	} else {
		// Response: ClientSessionID + PaddingLength + Padding + Address
		if len(data) < 19 { // 1 + 8 + 8 + 2
			return nil, ErrInvalidHeader
		}

		header.ClientSessionID = binary.BigEndian.Uint64(data[pos:])
		pos += 8

		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
		pos += int(header.PaddingLength)

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
	}

	return header, nil
}

// NewSession creates a new UDP session with random session ID

// encryptSeparateHeaderAES encrypts separate header using AES block cipher with PSK
func encryptSeparateHeaderAES(header *SeparateHeader, psk []byte) ([]byte, error) {
	// Separate header is 16 bytes (session ID + packet ID)
	plainHeader := EncodeSeparateHeader(header)

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Encrypt using AES ECB mode (single block)
	encrypted := make([]byte, 16)
	block.Encrypt(encrypted, plainHeader)

	return encrypted, nil
}

// decryptSeparateHeaderAES decrypts separate header using AES block cipher with PSK
func decryptSeparateHeaderAES(encrypted []byte, psk []byte) ([]byte, error) {
	if len(encrypted) != 16 {
		return nil, ErrShortPacket
	}

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Decrypt using AES ECB mode (single block)
	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, encrypted)

	return decrypted, nil
}

// PackUDP encrypts plaintext using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
func PackUDP(c core.ShadowCipher, eih bool, separateHeaderKey, bodyKey []byte, payload []byte, target socks.Addr, sessionID, packetID, clientSessionID uint64) ([]byte, error) {
	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, sessionID)

	// Derive session subkey from salt for AEAD
	aead, err := c.Encrypter(bodyKey, salt)
	if err != nil {
		return nil, err
	}

	// Create separate header (session ID + packet ID)
	separateHeader := &SeparateHeader{
		SessionID: sessionID,
		PacketID:  packetID,
	}
	separateHeaderEncoding := EncodeSeparateHeader(separateHeader)

	// Encrypt separate header with AES using PSK
	encryptedSeparateHeader, err := encryptSeparateHeaderAES(separateHeader, separateHeaderKey)
	if err != nil {
		return nil, err
	}

	pad := rand.Intn(MaxPaddingLength)
	padding := make([]byte, pad)
	_, err = crand.Read(padding)
	if err != nil {
		return nil, errors.New("failed to generate padding")
	}

	var headerType byte
	if clientSessionID != 0 {
		headerType = HeaderTypeServerStream
	} else {
		headerType = HeaderTypeClientStream
	}

	// Encode main header
	header := &UDPHeader{
		Type:            headerType,
		Timestamp:       time.Now().Unix(),
		Address:         target,
		PaddingLength:   uint16(len(padding)),
		Padding:         padding,
		ClientSessionID: clientSessionID, // Only used if headerType == ServerStream
	}

	mainHeader := EncodeUDPHeader(header)

	// Combine main header + payload as body
	body := make([]byte, len(mainHeader)+len(payload))
	copy(body, mainHeader)
	copy(body[len(mainHeader):], payload)

	// Encrypt body with AEAD
	encryptedBody := aead.Seal(nil, separateHeaderEncoding[4:], body, nil)

	var addtionalHeaders []byte
	if eih {
		addtionalHeaders, err = AdditionalHeaders(c, separateHeaderEncoding)
		if err != nil {
			return nil, err
		}
	}

	// Combine: encrypted_separate_header + encrypted_body
	totalSize := 16 + len(encryptedBody) + len(addtionalHeaders)
	dst := make([]byte, totalSize)

	pos := 0
	copy(dst[pos:], encryptedSeparateHeader)
	pos += 16

	if eih {
		copy(dst[pos:], addtionalHeaders)
		pos += len(addtionalHeaders)
	}

	copy(dst[pos:], encryptedBody)

	return dst[:totalSize], nil
}

// UnpackUDP decrypts pkt using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
// Returns: (header, payload, sessionID, key for decryption, error)
//
// The workflow:
// 1. decrypt separateHeader. For server, use the first key of ciph. For client, use the last key of ciph
// 2. decrypt Extensible Identity Headers if userTable is not nil
// 3. decrypt body. For server, use the key from EIH. For client, use the last key of ciph
// NOTE: For server, there is only one key in the ciph
func UnpackUDP(ciph core.ShadowCipher, userTable map[core.EIHHash]string, encrypted []byte) (*SeparateHeader, *UDPHeader, []byte, []byte, error) {
	// Decrypt separate header with AES using PSK
	pos := 0
	decryptKey := ciph.Key()

	encryptedSeparateHeader := encrypted[:16]
	separateHeaderEncoding, err := decryptSeparateHeaderAES(encryptedSeparateHeader, ciph.Key())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pos += 16
	separateHeader, err := DecodeSeparateHeader(separateHeaderEncoding)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// validate Extensible Identity Headers
	if userTable != nil {
		aesKey, err := aes.NewCipher(ciph.Key())
		if err != nil {
			return nil, nil, nil, nil, err
		}

		nextKeyHash := make([]byte, 16)
		aesKey.Decrypt(nextKeyHash, encrypted[pos:pos+16])
		nextKeyHash, err = core.XORBytes(nextKeyHash, separateHeaderEncoding)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if password, ok := userTable[core.EIHHash(nextKeyHash)]; !ok {
			return nil, nil, nil, nil, errors.New("no such user")
		} else {
			k, err := core.Base64Decode(password)
			if err != nil {
				return nil, nil, nil, nil, err
			}

			decryptKey = k
		}
		pos += 16
	}

	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, separateHeader.SessionID)

	// Derive session subkey from salt for AEAD
	aead, err := ciph.Decrypter(decryptKey, salt)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Decrypt body with AEAD
	encryptedBody := encrypted[pos:]
	if len(encryptedBody) < aead.Overhead() {
		return nil, nil, nil, nil, ErrShortPacket
	}

	body, err := aead.Open(encryptedBody[:0], separateHeaderEncoding[4:], encryptedBody, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Parse main header from body
	header, err := DecodeUDPHeader(body)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Extract payload (everything after main header)
	var headerLen int
	if header.Type == HeaderTypeClientStream {
		headerLen = 1 + 8 + 2 + len(header.Address) + int(header.PaddingLength)
	} else {
		headerLen = 1 + 8 + 8 + 2 + int(header.PaddingLength) + len(header.Address)
	}
	if len(body) < headerLen {
		return nil, nil, nil, nil, ErrShortPacket
	}
	payload := body[headerLen:]

	return separateHeader, header, payload, decryptKey, nil
}
