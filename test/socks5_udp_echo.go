package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// SOCKS5 UDP Echo Test Tool
// Usage: socks5_udp_echo <socks5_addr> <udp_server_addr> <message>
// Example: socks5_udp_echo 127.0.0.1:1080 127.0.0.1:9999 "hello"

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: socks5_udp_echo <socks5_addr> <udp_server_addr> <message>")
		fmt.Println("Example: socks5_udp_echo 127.0.0.1:1080 127.0.0.1:9999 hello")
		os.Exit(1)
	}

	socksAddr := os.Args[1]
	udpServer := os.Args[2]
	message := os.Args[3]

	if err := sendUDPEcho(socksAddr, udpServer, message); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func sendUDPEcho(socksAddr, udpServer, message string) error {
	// 1. Connect to SOCKS5 proxy (TCP)
	tcpConn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SOCKS5: %w", err)
	}
	defer tcpConn.Close()

	// 2. SOCKS5 handshake
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("handshake write failed: %w", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, buf); err != nil {
		return fmt.Errorf("handshake read failed: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("handshake failed: got %v", buf)
	}

	// 3. UDP ASSOCIATE request
	req := []byte{
		0x05,       // VER
		0x03,       // CMD = UDP ASSOCIATE
		0x00,       // RSV
		0x01,       // ATYP = IPv4
		0, 0, 0, 0, // DST.ADDR = 0.0.0.0
		0, 0, // DST.PORT = 0
	}
	if _, err := tcpConn.Write(req); err != nil {
		return fmt.Errorf("UDP ASSOCIATE request failed: %w", err)
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		return fmt.Errorf("UDP ASSOCIATE response read failed: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("UDP ASSOCIATE failed: reply code %d", resp[1])
	}

	// Parse BND.ADDR based on ATYP
	var bndAddr string
	var bndPort uint16

	switch resp[3] {
	case 0x01: // IPv4
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(tcpConn, addrBuf); err != nil {
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		bndAddr = fmt.Sprintf("%d.%d.%d.%d", addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3])

	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(tcpConn, domainBuf); err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		bndAddr = string(domainBuf)

	case 0x04: // IPv6
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(tcpConn, addrBuf); err != nil {
			return fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		bndAddr = net.IP(addrBuf).String()

	default:
		return fmt.Errorf("unknown address type: %d", resp[3])
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	bndPort = binary.BigEndian.Uint16(portBuf)

	udpRelayAddr := fmt.Sprintf("%s:%d", bndAddr, bndPort)

	// 4. Create UDP socket
	udpConn, err := net.ListenPacket("udp", "")
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer udpConn.Close()

	// 5. Build SOCKS5 UDP request header
	udpReq := []byte{0x00, 0x00, 0x00} // RSV + FRAG

	// Parse UDP server address
	serverHost, serverPortStr, err := net.SplitHostPort(udpServer)
	if err != nil {
		return fmt.Errorf("invalid UDP server address: %w", err)
	}

	// Try to parse as IP
	serverIP := net.ParseIP(serverHost)
	if serverIP != nil {
		if ipv4 := serverIP.To4(); ipv4 != nil {
			// IPv4
			udpReq = append(udpReq, 0x01) // ATYP = IPv4
			udpReq = append(udpReq, ipv4...)
		} else {
			// IPv6
			udpReq = append(udpReq, 0x04) // ATYP = IPv6
			udpReq = append(udpReq, serverIP...)
		}
	} else {
		// Domain name
		udpReq = append(udpReq, 0x03) // ATYP = Domain
		udpReq = append(udpReq, byte(len(serverHost)))
		udpReq = append(udpReq, []byte(serverHost)...)
	}

	// Port
	var serverPort uint16
	fmt.Sscanf(serverPortStr, "%d", &serverPort)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, serverPort)
	udpReq = append(udpReq, portBytes...)

	// Message data
	udpReq = append(udpReq, []byte(message)...)

	// 6. Send UDP packet to relay address
	relayUDPAddr, err := net.ResolveUDPAddr("udp", udpRelayAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve relay address: %w", err)
	}

	if _, err := udpConn.WriteTo(udpReq, relayUDPAddr); err != nil {
		return fmt.Errorf("failed to send UDP packet: %w", err)
	}

	// 7. Receive response
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 4096)
	n, _, err := udpConn.ReadFrom(respBuf)
	if err != nil {
		return fmt.Errorf("failed to receive UDP response: %w", err)
	}

	// 8. Parse SOCKS5 UDP response header
	if n < 10 {
		return fmt.Errorf("response too short: %d bytes", n)
	}

	// Skip RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT
	offset := 3 // RSV + FRAG
	atyp := respBuf[offset]
	offset++

	switch atyp {
	case 0x01: // IPv4
		offset += 4
	case 0x03: // Domain
		domainLen := int(respBuf[offset])
		offset += 1 + domainLen
	case 0x04: // IPv6
		offset += 16
	}
	offset += 2 // Port

	if offset >= n {
		return fmt.Errorf("invalid response format")
	}

	// 9. Extract echo response
	echoResp := string(respBuf[offset:n])

	fmt.Printf("✓ UDP echo successful!\n")
	fmt.Printf("Sent: %s\n", message)
	fmt.Printf("Received: %s\n", echoResp)

	return nil
}
