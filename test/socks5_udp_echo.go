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
		fmt.Println("Usage: socks5_udp_echo <socks5_addr> <udp_server_addr[,udp_server_addr...]> <message>")
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
	targets := splitTargets(udpServer)
	if len(targets) > 1 {
		return sendUDPMultiEcho(socksAddr, targets, message)
	}
	assoc, err := newUDPAssociation(socksAddr)
	if err != nil {
		return err
	}
	defer assoc.Close()

	_, echoResp, err := assoc.send(targets[0], message)
	if err != nil {
		return err
	}

	fmt.Printf("✓ UDP echo successful!\n")
	fmt.Printf("Sent: %s\n", message)
	fmt.Printf("Received: %s\n", echoResp)

	return nil
}

func splitTargets(targets string) []string {
	parts := make([]string, 0)
	start := 0
	for i := 0; i < len(targets); i++ {
		if targets[i] == ',' {
			parts = append(parts, targets[start:i])
			start = i + 1
		}
	}
	parts = append(parts, targets[start:])
	return parts
}

func sendUDPMultiEcho(socksAddr string, targets []string, message string) error {
	assoc, err := newUDPAssociation(socksAddr)
	if err != nil {
		return err
	}
	defer assoc.Close()

	for _, target := range targets {
		responseTarget, _, err := assoc.send(target, message+"@"+target)
		if err != nil {
			return err
		}
		expectedTarget, err := canonicalTarget(target)
		if err != nil {
			return err
		}
		if responseTarget != expectedTarget {
			return fmt.Errorf("response target mismatch: got %s want %s", responseTarget, expectedTarget)
		}
	}

	fmt.Printf("UDP multi-target successful\n")
	return nil
}

type udpAssociation struct {
	tcpConn   net.Conn
	udpConn   net.PacketConn
	relayAddr *net.UDPAddr
}

func newUDPAssociation(socksAddr string) (*udpAssociation, error) {
	tcpConn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5: %w", err)
	}

	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("handshake write failed: %w", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, buf); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("handshake read failed: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("handshake failed: got %v", buf)
	}

	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE request failed: %w", err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE response read failed: %w", err)
	}
	if resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE failed: reply code %d", resp[1])
	}

	bndAddr, bndPort, err := readBoundAddr(tcpConn, resp[3])
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	udpConn, err := net.ListenPacket("udp", "")
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	relayAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", bndAddr, bndPort))
	if err != nil {
		udpConn.Close()
		tcpConn.Close()
		return nil, fmt.Errorf("failed to resolve relay address: %w", err)
	}

	return &udpAssociation{tcpConn: tcpConn, udpConn: udpConn, relayAddr: relayAddr}, nil
}

func (a *udpAssociation) Close() {
	if a.udpConn != nil {
		a.udpConn.Close()
	}
	if a.tcpConn != nil {
		a.tcpConn.Close()
	}
	return
}

func (a *udpAssociation) send(target, message string) (string, string, error) {
	udpReq, err := buildUDPRequest(target, message)
	if err != nil {
		return "", "", err
	}
	if _, err := a.udpConn.WriteTo(udpReq, a.relayAddr); err != nil {
		return "", "", fmt.Errorf("failed to send UDP packet: %w", err)
	}

	a.udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 4096)
	n, _, err := a.udpConn.ReadFrom(respBuf)
	if err != nil {
		return "", "", fmt.Errorf("failed to receive UDP response: %w", err)
	}

	return parseUDPResponse(respBuf[:n])
}

func buildUDPRequest(udpServer, message string) ([]byte, error) {
	udpReq := []byte{0x00, 0x00, 0x00}
	serverHost, serverPortStr, err := net.SplitHostPort(udpServer)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP server address: %w", err)
	}

	serverIP := net.ParseIP(serverHost)
	if serverIP != nil {
		if ipv4 := serverIP.To4(); ipv4 != nil {
			udpReq = append(udpReq, 0x01)
			udpReq = append(udpReq, ipv4...)
		} else {
			udpReq = append(udpReq, 0x04)
			udpReq = append(udpReq, serverIP...)
		}
	} else {
		udpReq = append(udpReq, 0x03)
		udpReq = append(udpReq, byte(len(serverHost)))
		udpReq = append(udpReq, []byte(serverHost)...)
	}

	var serverPort uint16
	fmt.Sscanf(serverPortStr, "%d", &serverPort)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, serverPort)
	udpReq = append(udpReq, portBytes...)
	udpReq = append(udpReq, []byte(message)...)
	return udpReq, nil
}

func parseUDPResponse(resp []byte) (string, string, error) {
	if len(resp) < 10 {
		return "", "", fmt.Errorf("response too short: %d bytes", len(resp))
	}

	offset := 3
	atyp := resp[offset]
	offset++

	var host string
	switch atyp {
	case 0x01:
		host = net.IP(resp[offset : offset+4]).String()
		offset += 4
	case 0x03:
		domainLen := int(resp[offset])
		offset++
		host = string(resp[offset : offset+domainLen])
		offset += domainLen
	case 0x04:
		host = net.IP(resp[offset : offset+16]).String()
		offset += 16
	default:
		return "", "", fmt.Errorf("unknown response address type: %d", atyp)
	}

	port := binary.BigEndian.Uint16(resp[offset : offset+2])
	offset += 2
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), string(resp[offset:]), nil
}

func readBoundAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01:
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		host = fmt.Sprintf("%d.%d.%d.%d", addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3])
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read domain: %w", err)
		}
		host = string(domainBuf)
	case 0x04:
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		host = net.IP(addrBuf).String()
	default:
		return "", 0, fmt.Errorf("unknown address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, fmt.Errorf("failed to read port: %w", err)
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

func canonicalTarget(target string) (string, error) {
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
