package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead_2022"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

func main() {
	var (
		serverAddr = flag.String("s", "127.0.0.1:8488", "SS2022 server address")
		password   = flag.String("p", "", "password in base64(16 bytes AES)")
		targetAddr = flag.String("t", "8.8.8.8:53", "Target address (e.g., DNS server)")
		domain     = flag.String("d", "google.com", "Domain to query")
	)
	flag.Parse()

	if *password == "" {
		log.Fatal("password required: use -p <base64>")
	}

	// Create cipher
	ciph, err := core.PickCipher("2022-BLAKE3-AES-128-GCM", nil, *password)
	if err != nil {
		log.Fatalf("Create cipher failed: %v", err)
	}

	// Create local UDP listener
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		log.Fatalf("ListenUDP failed: %v", err)
	}
	defer localConn.Close()

	// Wrap with PacketConn
	pc := ciph.PacketConn(localConn, utils.ROLE_CLIENT).(*shadowaead2022.PacketConn)

	// Set target (DNS server)
	target := socks.ParseAddr(*targetAddr)
	if target == nil {
		log.Fatalf("Invalid target address: %s", *targetAddr)
	}

	// Create a session for this connection
	session := shadowaead2022.NewClientSession(target, nil)
	pc.SetSession(session)

	// Resolve server address
	serverUDPAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		log.Fatalf("Resolve server failed: %v", err)
	}

	// Build DNS query
	dnsQuery := buildDNSQuery(*domain)
	log.Println("buf: ", dnsQuery)
	fmt.Printf("Sending DNS query for %s to %s via SS2022 server %s\n", *domain, *targetAddr, *serverAddr)
	fmt.Printf("Session ID: %016x\n", session.SessionID())

	// Send query
	start := time.Now()
	_, err = pc.WriteTo(dnsQuery, serverUDPAddr)
	if err != nil {
		log.Fatalf("WriteTo failed: %v", err)
	}

	// Receive response
	localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(respBuf)
	if err != nil {
		log.Fatalf("ReadFrom failed: %v", err)
	}

	duration := time.Since(start)

	// Verify response
	if n < 12 {
		log.Fatalf("Response too short: %d bytes", n)
	}

	// Check transaction ID
	if respBuf[0] != dnsQuery[0] || respBuf[1] != dnsQuery[1] {
		log.Printf("Warning: Transaction ID mismatch")
	}

	// Parse DNS response
	fmt.Printf("\nDNS Response received: %d bytes in %v\n", n, duration)
	fmt.Printf("Transaction ID: %02x%02x\n", respBuf[0], respBuf[1])
	fmt.Printf("Flags: %02x%02x\n", respBuf[2], respBuf[3])

	// Check if response bit is set
	if respBuf[2]&0x80 != 0 {
		fmt.Println("✓ Valid DNS response")
	}

	// Count answers
	answerCount := int(respBuf[6])<<8 | int(respBuf[7])
	fmt.Printf("Answer RRs: %d\n", answerCount)

	if answerCount > 0 {
		// Skip question section to get to answers
		pos := 12 // After header
		// Skip question domain name
		for pos < n && respBuf[pos] != 0 {
			if respBuf[pos]&0xC0 == 0xC0 { // Compression pointer
				pos += 2
				break
			}
			pos += int(respBuf[pos]) + 1
		}
		if pos < n && respBuf[pos] == 0 {
			pos++ // Skip null terminator
		}
		pos += 4 // Skip QTYPE and QCLASS

		// Parse answers
		fmt.Println("\nDNS Records:")
		for i := 0; i < answerCount && pos < n; i++ {
			// Skip name (could be pointer or labels)
			if respBuf[pos]&0xC0 == 0xC0 {
				pos += 2
			} else {
				for pos < n && respBuf[pos] != 0 {
					pos += int(respBuf[pos]) + 1
				}
				pos++
			}

			if pos+10 > n {
				break
			}

			rrType := int(respBuf[pos])<<8 | int(respBuf[pos+1])
			pos += 2
			pos += 2 // Skip class
			ttl := int(respBuf[pos])<<24 | int(respBuf[pos+1])<<16 | int(respBuf[pos+2])<<8 | int(respBuf[pos+3])
			pos += 4
			dataLen := int(respBuf[pos])<<8 | int(respBuf[pos+1])
			pos += 2

			if pos+dataLen > n {
				break
			}

			if rrType == 1 && dataLen == 4 { // A record
				fmt.Printf("  %s  TTL=%d  A  %d.%d.%d.%d\n",
					*domain, ttl,
					respBuf[pos], respBuf[pos+1], respBuf[pos+2], respBuf[pos+3])
			}
			pos += dataLen
		}

		fmt.Println("\n✓ DNS query successful!")
	}
}

// buildDNSQuery creates a simple DNS A record query
func buildDNSQuery(domain string) []byte {
	buf := make([]byte, 0, 512)

	// Transaction ID (random)
	buf = append(buf, 0xab, 0xcd)
	// Flags: standard query, recursion desired
	buf = append(buf, 0x01, 0x00)
	// Questions: 1
	buf = append(buf, 0x00, 0x01)
	// Answer RRs: 0
	buf = append(buf, 0x00, 0x00)
	// Authority RRs: 0
	buf = append(buf, 0x00, 0x00)
	// Additional RRs: 0
	buf = append(buf, 0x00, 0x00)

	// Query: split domain by dots
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			label := domain[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
			start = i + 1
		}
	}
	buf = append(buf, 0x00) // null terminator

	// Type A (0x0001)
	buf = append(buf, 0x00, 0x01)
	// Class IN (0x0001)
	buf = append(buf, 0x00, 0x01)

	return buf
}
