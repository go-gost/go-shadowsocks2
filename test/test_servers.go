package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Test servers for shadowsocks integration testing
// Provides both HTTP and UDP echo servers

var (
	httpPort = flag.Int("http", 8888, "HTTP server port")
	udpPort  = flag.Int("udp", 9999, "UDP echo server port")
	verbose  = flag.Bool("v", false, "Verbose logging")
)

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startHTTPServer(*httpPort, done); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start UDP echo server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startUDPEchoServer(*udpPort, done); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	fmt.Printf("Test servers started:\n")
	fmt.Printf("  HTTP server: http://127.0.0.1:%d\n", *httpPort)
	fmt.Printf("  UDP echo server: 127.0.0.1:%d\n", *udpPort)
	fmt.Printf("Press Ctrl+C to stop\n\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down servers...")
	close(done)

	// Wait for both servers to stop
	shutdownDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		fmt.Println("All servers stopped cleanly")
	case <-time.After(5 * time.Second):
		fmt.Println("Shutdown timeout, forcing exit")
	}
}

// startHTTPServer starts a simple HTTP server for testing TCP connections
func startHTTPServer(port int, done <-chan struct{}) error {
	mux := http.NewServeMux()

	// Root handler - returns basic HTML
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			log.Printf("HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Shadowsocks Test Server</title>
</head>
<body>
    <h1>Shadowsocks Test Server</h1>
    <p>This is a test HTTP server for shadowsocks integration testing.</p>
    <p>Request received at: %s</p>
    <p>Client IP: %s</p>
</body>
</html>
`, time.Now().Format(time.RFC3339), r.RemoteAddr)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			log.Printf("HTTP health check from %s", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-done
		server.Close()
	}()

	log.Printf("HTTP server listening on :%d", port)
	return server.ListenAndServe()
}

// startUDPEchoServer starts a simple UDP echo server for testing UDP connections
func startUDPEchoServer(port int, done <-chan struct{}) error {
	addr := &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("127.0.0.1"),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP server: %w", err)
	}
	defer conn.Close()

	log.Printf("UDP echo server listening on %s", addr)

	// Shutdown handler
	go func() {
		<-done
		conn.Close()
	}()

	buffer := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				log.Printf("UDP read error: %v", err)
				continue
			}
		}

		if *verbose {
			log.Printf("UDP received %d bytes from %s", n, remoteAddr)
		}

		// Echo back with timestamp prefix
		response := fmt.Sprintf("[%s] %s",
			time.Now().Format("15:04:05.000"),
			string(buffer[:n]))

		_, err = conn.WriteToUDP([]byte(response), remoteAddr)
		if err != nil {
			log.Printf("UDP write error: %v", err)
			continue
		}

		if *verbose {
			log.Printf("UDP echoed %d bytes to %s", len(response), remoteAddr)
		}
	}
}
