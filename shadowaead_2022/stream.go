package shadowaead2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/zeebo/blake3"
)

// payloadSizeMask is the maximum size of payload in bytes per SIP022.
const payloadSizeMask = 0xFFFF // 64*1024 - 1

// SIP022 constants
const (
	// TimestampTolerance is the maximum allowed timestamp difference (30 seconds)
	TimestampTolerance = 30 * time.Second
	// Stream type constants
	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	// Padding constraints
	MinPaddingLength = 0
	MaxPaddingLength = 900
)

var (
	ErrRepeatedSalt     = errors.New("repeated salt detected")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidHeader    = errors.New("invalid header format")
)

// FixedLengthHeader represents the SIP022 fixed-length header
type FixedLengthHeader struct {
	Type      byte   // HeaderTypeClientStream or HeaderTypeServerStream
	Timestamp int64  // Unix epoch timestamp (8 bytes)
	Length    uint16 // Next chunk's plaintext length
}

// VariableLengthHeader represents the SIP022 variable-length header
type VariableLengthHeader struct {
	Addr          socks.Addr // Target address (includes type, address, and port)
	PaddingLength uint16     // Padding length
	Padding       []byte     // Random padding
	Payload       []byte     // Initial payload
}

// ResponseFixedLengthHeader represents the SIP022 response fixed-length header
type ResponseFixedLengthHeader struct {
	Type        byte   // HeaderTypeServerStream
	Timestamp   int64  // Unix epoch timestamp (8 bytes)
	RequestSalt []byte // 16 or 32 bytes depending on cipher
	Length      uint16 // Next chunk's plaintext length
}

// validateTimestamp checks if the timestamp is within the allowed tolerance
func validateTimestamp(timestamp int64) error {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > TimestampTolerance {
		return ErrInvalidTimestamp
	}
	return nil
}

// EncodeFixedLengthHeader encodes a fixed-length header for transmission
func EncodeFixedLengthHeader(header *FixedLengthHeader) []byte {
	buf := make([]byte, 11) // 1 + 8 + 2
	pos := 0

	buf[pos] = header.Type
	pos++

	binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
	pos += 8

	binary.BigEndian.PutUint16(buf[pos:], header.Length)

	return buf
}

// EncodeVariableLengthHeader encodes a variable-length header for transmission
func EncodeVariableLengthHeader(header *VariableLengthHeader) []byte {
	addrLen := len(header.Addr)
	totalLen := addrLen + 2 + len(header.Padding) + len(header.Payload)
	buf := make([]byte, totalLen)
	pos := 0

	// SOCKS address (includes ATYP, address, and port)
	copy(buf[pos:], header.Addr)
	pos += addrLen

	// Padding length
	binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
	pos += 2

	// Padding
	copy(buf[pos:], header.Padding)
	pos += len(header.Padding)

	// Initial payload
	copy(buf[pos:], header.Payload)

	return buf
}

// EncodeResponseFixedLengthHeader encodes a response fixed-length header
func EncodeResponseFixedLengthHeader(header *ResponseFixedLengthHeader) []byte {
	buf := make([]byte, 1+8+len(header.RequestSalt)+2)
	pos := 0

	buf[pos] = header.Type
	pos++

	binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
	pos += 8

	copy(buf[pos:], header.RequestSalt)
	pos += len(header.RequestSalt)

	binary.BigEndian.PutUint16(buf[pos:], header.Length)

	return buf
}

// DecodeFixedLengthHeader decodes a fixed-length header from encrypted data
func DecodeFixedLengthHeader(data []byte) (*FixedLengthHeader, error) {
	if len(data) < 11 { // 1+8+2
		return nil, ErrInvalidHeader
	}

	header := &FixedLengthHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	header.Length = binary.BigEndian.Uint16(data[pos:])

	return header, validateTimestamp(header.Timestamp)
}

// DecodeVariableLengthHeader decodes a variable-length header from encrypted data
func DecodeVariableLengthHeader(data []byte) (*VariableLengthHeader, error) {
	if len(data) < 7 { // minimum: 1+4+2 for IPv4
		return nil, ErrInvalidHeader
	}

	header := &VariableLengthHeader{}
	pos := 0

	// Extract SOCKS address
	addr := socks.SplitAddr(data[pos:])
	if addr == nil {
		return nil, ErrInvalidHeader
	}
	header.Addr = addr
	pos += len(addr)

	if len(data) < pos+2 {
		return nil, ErrInvalidHeader
	}

	// Padding length
	header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
	pos += 2

	if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
		return nil, ErrInvalidHeader
	}

	if len(data) < pos+int(header.PaddingLength) {
		return nil, ErrInvalidHeader
	}

	// Padding
	header.Padding = make([]byte, header.PaddingLength)
	copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
	pos += int(header.PaddingLength)

	// Initial payload (rest of data)
	if pos < len(data) {
		header.Payload = make([]byte, len(data)-pos)
		copy(header.Payload, data[pos:])
	}

	return header, nil
}

// DecodeResponseFixedLengthHeader decodes a response fixed-length header
func DecodeResponseFixedLengthHeader(data []byte, saltSize int) (*ResponseFixedLengthHeader, error) {
	expectedLen := 1 + 8 + saltSize + 2
	if len(data) < expectedLen {
		return nil, ErrInvalidHeader
	}

	header := &ResponseFixedLengthHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	header.RequestSalt = make([]byte, saltSize)
	copy(header.RequestSalt, data[pos:pos+saltSize])
	pos += saltSize

	header.Length = binary.BigEndian.Uint16(data[pos:])

	return header, validateTimestamp(header.Timestamp)
}

type writer struct {
	io.Writer
	cipher.AEAD
	conn       *streamConn
	nonce      []byte
	buf        []byte
	headerSent bool
	salt       []byte
	clientSalt []byte // For server responses, stores the client's salt
}

// NewWriter wraps an io.Writer with AEAD encryption.
func NewWriter(w io.Writer, aead cipher.AEAD) io.Writer { return newWriter(w, aead) }

func newWriter(w io.Writer, aead cipher.AEAD) *writer {
	return &writer{
		Writer:     w,
		AEAD:       aead,
		buf:        make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce:      make([]byte, aead.NonceSize()),
		headerSent: false,
	}
}

// sendClientHeaders sends salt + fixed header + variable header for client connections
func (w *writer) sendClientHeaders() error {
	// Encode variable-length header first to get its size
	variableHeaderData := EncodeVariableLengthHeader(w.conn.variableHeader)

	// Create fixed-length header automatically
	fixedHeader := &FixedLengthHeader{
		Type:      HeaderTypeClientStream,
		Timestamp: time.Now().Unix(),
		Length:    uint16(len(variableHeaderData)),
	}

	// Encode fixed-length header
	fixedHeaderData := EncodeFixedLengthHeader(fixedHeader)

	// Encrypt both headers WITHOUT length prefix (SIP022 requirement)
	fixedHeaderChunk, err := w.encryptHeaderChunk(fixedHeaderData)
	if err != nil {
		return err
	}

	variableHeaderChunk, err := w.encryptHeaderChunk(variableHeaderData)
	if err != nil {
		return err
	}

	additionalHeaders, err := w.conn.AdditionalHeaders(w.salt)
	if err != nil {
		return err
	}
	// Combine salt + encrypted header chunks into one buffer
	totalLen := len(w.salt) + len(additionalHeaders) + len(fixedHeaderChunk) + len(variableHeaderChunk)
	combinedBuf := make([]byte, totalLen)
	pos := 0

	// Copy salt
	copy(combinedBuf[pos:], w.salt)
	pos += len(w.salt)

	copy(combinedBuf[pos:], additionalHeaders)
	pos += len(additionalHeaders)

	// Copy encrypted fixed header chunk
	copy(combinedBuf[pos:], fixedHeaderChunk)
	pos += len(fixedHeaderChunk)

	// Copy encrypted variable header chunk
	copy(combinedBuf[pos:], variableHeaderChunk)

	// Send everything in one write call (SIP022 requirement)
	_, err = w.Writer.Write(combinedBuf)
	return err
}

// sendServerHeader sends salt + response header for server connections
func (w *writer) sendServerHeader() error {
	// For server, we need the client's salt to include in response
	if len(w.clientSalt) == 0 {
		return errors.New("client salt not set for server response")
	}

	// Create response header
	responseHeader := &ResponseFixedLengthHeader{
		Type:        HeaderTypeServerStream,
		Timestamp:   time.Now().Unix(),
		RequestSalt: w.clientSalt,
		Length:      0, // First response chunk has no payload
	}

	// Encode response header
	responseHeaderData := EncodeResponseFixedLengthHeader(responseHeader)

	// Encrypt header WITHOUT length prefix (SIP022 requirement)
	headerChunk, err := w.encryptHeaderChunk(responseHeaderData)
	if err != nil {
		return err
	}

	// Combine salt + encrypted header chunk
	totalLen := len(w.salt) + len(headerChunk)
	combinedBuf := make([]byte, totalLen)
	pos := 0

	// Copy salt
	copy(combinedBuf[pos:], w.salt)
	pos += len(w.salt)

	// Copy encrypted header chunk
	copy(combinedBuf[pos:], headerChunk)

	// Send everything in one write call
	_, err = w.Writer.Write(combinedBuf)
	return err
}

// Write encrypts b and writes to the embedded io.Writer.
func (w *writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	// Send salt and headers if not sent yet
	if !w.headerSent {
		if !w.conn.isServer {
			// Client side: send salt + fixed header + variable header
			if err := w.sendClientHeaders(); err != nil {
				return 0, err
			}
		} else {
			// Server side: send salt + response header
			if err := w.sendServerHeader(); err != nil {
				return 0, err
			}
		}
		w.headerSent = true
	}

	for {
		buf := w.buf
		payloadBuf := buf[2+w.Overhead() : 2+w.Overhead()+payloadSizeMask]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)
			if err := w.writeChunk(payloadBuf[:nr]); err != nil {
				return n, err
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}

// encryptHeaderChunk encrypts header data without length prefix (SIP022 requirement)
// Headers are encrypted directly: AEAD(header_data)
func (w *writer) encryptHeaderChunk(data []byte) ([]byte, error) {
	encryptedLen := len(data) + w.Overhead()
	buf := make([]byte, encryptedLen)

	// Directly encrypt header data without length prefix
	w.Seal(buf[:0], w.nonce, data, nil)
	core.Increment(w.nonce)

	return buf, nil
}

// encryptPayloadChunk encrypts payload data with length prefix
// Format: AEAD(length) + AEAD(payload)
func (w *writer) encryptPayloadChunk(data []byte) ([]byte, error) {
	if len(data) > payloadSizeMask {
		return nil, errors.New("payload too large")
	}

	encryptedLen := 2 + w.Overhead() + len(data) + w.Overhead()
	buf := w.buf[:encryptedLen]

	// Encrypt length header (2 bytes, big-endian)
	buf[0], buf[1] = byte(len(data)>>8), byte(len(data))
	w.Seal(buf[:0], w.nonce, buf[:2], nil)
	core.Increment(w.nonce)

	// Encrypt payload
	payloadStart := 2 + w.Overhead()
	copy(buf[payloadStart:], data)
	w.Seal(buf[payloadStart:payloadStart], w.nonce, buf[payloadStart:payloadStart+len(data)], nil)
	core.Increment(w.nonce)

	return buf, nil
}

// writeChunk writes an encrypted payload chunk with length prefix
func (w *writer) writeChunk(data []byte) error {
	encryptedChunk, err := w.encryptPayloadChunk(data)
	if err != nil {
		return err
	}
	_, err = w.Writer.Write(encryptedChunk)
	return err
}

type reader struct {
	io.Reader
	cipher.AEAD
	conn       *streamConn
	nonce      []byte
	buf        []byte
	leftover   []byte
	headerRead bool
	saltSize   int
}

// NewReader wraps an io.Reader with AEAD decryption.
func NewReader(r io.Reader, aead cipher.AEAD) io.Reader { return newReader(r, aead, 32) } // Default salt size

func newReader(r io.Reader, aead cipher.AEAD, saltSize int) *reader {
	return &reader{
		Reader:     r,
		AEAD:       aead,
		buf:        make([]byte, payloadSizeMask+aead.Overhead()),
		nonce:      make([]byte, aead.NonceSize()),
		headerRead: false,
		saltSize:   saltSize,
	}
}

// readHeaderChunk reads and decrypts a header chunk (no length prefix)
func (r *reader) readHeaderChunk(expectedSize int) (int, error) {
	// Header chunks are encrypted directly without length prefix
	buf := r.buf[:expectedSize+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	// Decrypt header
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	core.Increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return expectedSize, nil
}

// readPayloadChunk reads and decrypts a payload chunk (with length prefix)
func (r *reader) readPayloadChunk() (int, error) {
	// decrypt payload size
	buf := r.buf[:2+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	core.Increment(r.nonce)
	if err != nil {
		return 0, err
	}

	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask

	// decrypt payload
	buf = r.buf[:size+r.Overhead()]
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	core.Increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// read headers for request stream
func (r *reader) readHeaders() error {
	// First chunk should be fixed-length header (11 bytes)
	size, err := r.readHeaderChunk(11)
	if err != nil {
		return err
	}
	fixedHeader, err := DecodeFixedLengthHeader(r.buf[:size])
	if err != nil {
		return err
	}
	r.conn.fixedHeader = fixedHeader

	// Variable header size is specified in fixed header's Length field
	size, err = r.readHeaderChunk(int(r.conn.fixedHeader.Length))
	if err != nil {
		return err
	}
	variableHeader, err := DecodeVariableLengthHeader(r.buf[:size])
	if err != nil {
		return err
	}
	r.conn.variableHeader = variableHeader

	r.headerRead = true

	// If there's initial payload in the header, return it
	if len(variableHeader.Payload) > 0 {
		copy(r.buf[:len(variableHeader.Payload)], variableHeader.Payload)
	}

	return nil
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered.
func (r *reader) read() (int, error) {
	if !r.headerRead {
		// client side
		size, err := r.readHeaderChunk(11 + r.saltSize)
		if err != nil {
			return 0, err
		}
		_, err = DecodeFixedLengthHeader(r.buf[:size])
		if err != nil {
			return 0, err
		}

		r.headerRead = true
	}

	// Regular payload chunks (with length prefix)
	return r.readPayloadChunk()
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *reader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	for {
		n, err := r.read()
		if err != nil {
			return 0, err
		}

		// If n == 0, it means we read a header chunk, continue to next chunk
		if n == 0 {
			continue
		}

		m := copy(b, r.buf[:n])
		if m < n { // insufficient len(b), keep leftover for next read
			r.leftover = r.buf[m:n]
		}
		return m, nil
	}
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	// write decrypted bytes left over from previous record
	for len(r.leftover) > 0 {
		nw, ew := w.Write(r.leftover)
		r.leftover = r.leftover[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
		nr, er := r.read()
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			break
		}

		// Skip header chunks (nr == 0)
		if nr > 0 {
			nw, ew := w.Write(r.buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}
	}

	return n, err
}

type streamConn struct {
	*net.TCPConn
	core.ShadowCipher
	r              *reader
	w              *writer
	isServer       bool
	variableHeader *VariableLengthHeader
	fixedHeader    *FixedLengthHeader
	clientSalt     []byte                  // Store client salt at connection level
	userTable      map[core.EIHHash]string // Extensible Identity Headers, for server
	key            []byte                  // key for encryption and decryption
}

func (c *streamConn) loadSalt() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.TCPConn, salt); err != nil {
		return err
	}

	// Store client salt at connection level (always safe)
	c.clientSalt = make([]byte, len(salt))
	copy(c.clientSalt, salt)

	return nil
}

func (c *streamConn) initReader() error {
	if len(c.clientSalt) == 0 {
		err := c.loadSalt()
		if err != nil {
			return err
		}
	}

	aead, err := c.Decrypter(c.key, c.clientSalt)
	if err != nil {
		return err
	}

	c.r = newReader(c.TCPConn, aead, c.SaltSize())
	c.r.conn = c

	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *streamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *streamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(c.key, salt)
	if err != nil {
		return err
	}

	c.w = newWriter(c.TCPConn, aead)
	c.w.salt = salt
	c.w.conn = c

	// Pass client salt to writer if we have it
	if len(c.clientSalt) > 0 {
		c.w.clientSalt = c.clientSalt
	}

	return nil
}

// SetVariableHeader sets the variable header for the connection
// Fixed header will be generated automatically when needed
func (c *streamConn) SetVariableHeader(variable *VariableLengthHeader) error {
	c.variableHeader = variable
	return nil
}

func (c *streamConn) validateHeaders() error {
	if c.fixedHeader == nil || c.variableHeader == nil {
		return errors.New("no header received")
	}

	if c.variableHeader.PaddingLength == 0 && len(c.variableHeader.Payload) == 0 {
		return errors.New("one of padding and initial payload must be set")
	}

	packetTime := time.Unix(c.fixedHeader.Timestamp, 0)
	if diffTime := time.Since(packetTime); diffTime > 30*time.Second {
		return errors.New("time difference between server and client is too large")
	}

	return nil
}

// InitServer will read salt + Extensible Identity Headers + fixed length header + variable length header from first packet of connection
// Btw, header validating also be applied
func (c *streamConn) InitServer() (socks.Addr, error) {
	var err error

	if !c.isServer {
		return nil, nil
	}

	defer func() {
		if err != nil {
			conn := c.TCPConn
			// This defends against probes that send one byte at a time to detect
			// how many bytes the server consumes before closing the connection.
			conn.CloseWrite()
		}
	}()

	err = c.loadSalt()
	if err != nil {
		return nil, err
	}

	// validate Extensible Identity Headers
	if c.IsMultiUser() {
		subkey := make([]byte, c.KeySize())
		userPskHash := make([]byte, 16)
		if _, err = io.ReadFull(c.TCPConn, userPskHash); err != nil {
			return nil, err
		}

		blake3.DeriveKey("shadowsocks 2022 identity subkey", append(c.Key(), c.clientSalt...), subkey)
		var aesCipher cipher.Block
		aesCipher, err = aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}

		aesCipher.Decrypt(userPskHash, userPskHash)
		if password, ok := c.userTable[core.EIHHash(userPskHash)]; !ok {
			return nil, errors.New("no such user")
		} else {
			var k []byte
			k, err = core.Base64Decode(password)
			if err != nil {
				return nil, err
			}
			c.key = k
		}
	}

	if c.r == nil {
		if err = c.initReader(); err != nil {
			return nil, err
		}
	}

	if c.variableHeader == nil {
		if !CheckSalt(c.clientSalt) {
			err = ErrRepeatedSalt
			return nil, err
		}

		err = c.r.readHeaders()
		if err != nil {
			return nil, err
		}
	}

	err = c.validateHeaders()
	if err != nil {
		return nil, err
	}

	return c.variableHeader.Addr, nil
}

func (c *streamConn) InitClient(target socks.Addr, padding, initialPayload []byte) error {
	if c.isServer {
		return nil
	}

	if len(padding) == 0 && len(initialPayload) == 0 {
		return errors.New("one of padding and initial payload must be set")
	}

	c.variableHeader = &VariableLengthHeader{
		Addr:          target,
		PaddingLength: uint16(len(padding)),
		Padding:       padding,
		Payload:       initialPayload,
	}

	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *streamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// Generate Extensible Identity Headers
func (c *streamConn) AdditionalHeaders(salt []byte) ([]byte, error) {
	psks := c.Keys()
	n := len(psks)
	r := []byte{}
	subkey := make([]byte, c.KeySize())
	for i := range n - 1 {
		key := psks[i]
		nextKey := psks[i+1]
		blake3.DeriveKey("shadowsocks 2022 identity subkey", append(key, salt...), subkey)
		nextKeyHash := blake3.Sum256(nextKey)
		buf := nextKeyHash[:16]
		c, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}

		c.Encrypt(buf, buf)
		r = append(r, buf...)
	}

	return r, nil
}

func (c *streamConn) IsMultiUser() bool {
	return c.userTable != nil
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c *net.TCPConn, ciph core.ShadowCipher, config core.TCPConfig, role int) core.TCPConn {
	table := core.UsersToEIHHash(config.Users)

	return &streamConn{TCPConn: c, userTable: table, key: ciph.Key(), ShadowCipher: ciph, isServer: role == core.ROLE_SERVER}
}
