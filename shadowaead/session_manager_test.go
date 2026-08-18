package shadowaead

import (
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

// Regression tests for go-gost/gost#894: classic-AEAD UDP requires the
// [addr][payload] framing in BOTH directions. The fork's client used to return
// the unstripped [srcaddr][payload] prefix, and its server used to omit the
// address prefix entirely — neither interops with compliant implementations.
// Because a buggy client AND a buggy server mask each other when paired
// together (which is why gost's self-interop e2e never caught this), each side
// is checked here against a protocol-compliant peer.

func newTestCipher(t *testing.T) core.ShadowCipher {
	t.Helper()
	// The client and server run in the same process here, so the global
	// replay-salt bloom filter would flag every freshly-generated salt as a
	// replay. Disable it (separate processes do not share it).
	t.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")

	cipher, err := Chacha20Poly1305(core.MetaCipher{
		Name:      "chacha20-ietf-poly1305",
		KeySize:   32,
		SaltSize:  32,
		NonceSize: 12,
		TagSize:   16,
	}, "123456")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return cipher
}

// encryptAddrPacket builds a packet the way a compliant AEAD peer does:
// [addr][payload] plaintext, salt + AEAD around it.
func encryptAddrPacket(t *testing.T, cipher core.ShadowCipher, addr socks.Addr, payload []byte) []byte {
	t.Helper()
	out := make([]byte, len(addr)+len(payload))
	copy(out, addr)
	copy(out[len(addr):], payload)
	buf := make([]byte, len(out)+cipher.SaltSize()+cipher.TagSize())
	encrypted, err := Pack(buf, out, cipher)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return encrypted
}

func TestClientStripsResponseAddr(t *testing.T) {
	cipher := newTestCipher(t)
	clientMgr := NewAEADSessionManager(cipher, time.Minute, core.ROLE_CLIENT)

	payload := []byte("hello-gost-udp")
	target := socks.ParseAddr("127.0.0.1:8000")
	clientAddr := netip.MustParseAddrPort("10.0.0.1:50000")

	// Get a client session to pass to ClientHandleOutbound.
	clientSession, _, err := clientMgr.ClientHandleInbound(payload, target, clientAddr)
	if err != nil {
		t.Fatalf("client inbound: %v", err)
	}

	// A compliant server prepends the response source address.
	response := encryptAddrPacket(t, cipher, target, payload)

	got, err := clientMgr.ClientHandleOutbound(response, clientSession)
	if err != nil {
		t.Fatalf("client outbound: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("client payload = %q, want %q (addr prefix was not stripped)", got, payload)
	}
}

func TestServerPrependsResponseAddr(t *testing.T) {
	cipher := newTestCipher(t)
	clientMgr := NewAEADSessionManager(cipher, time.Minute, core.ROLE_CLIENT)
	serverMgr := NewAEADSessionManager(cipher, time.Minute, core.ROLE_SERVER)

	payload := []byte("hello-gost-udp")
	target := socks.ParseAddr("127.0.0.1:8000")
	clientAddr := netip.MustParseAddrPort("10.0.0.1:50000")

	// Establish a server session from a client packet.
	_, clientEncrypted, err := clientMgr.ClientHandleInbound(payload, target, clientAddr)
	if err != nil {
		t.Fatalf("client inbound: %v", err)
	}
	serverSession, gotTarget, _, err := serverMgr.ServerHandleInbound(clientEncrypted, clientAddr)
	if err != nil {
		t.Fatalf("server inbound: %v", err)
	}

	response, err := serverMgr.ServerHandleOutbound(payload, gotTarget, serverSession)
	if err != nil {
		t.Fatalf("server outbound: %v", err)
	}

	// Decrypt like a compliant client and require the address prefix.
	pkt, err := Unpack(make([]byte, 4096), response, cipher)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	addr := socks.SplitAddr(pkt)
	if addr == nil {
		t.Fatalf("server response %q has no address prefix", pkt)
	}
	if string(addr) != string(target) {
		t.Fatalf("server response addr = %q, want %q", addr, target)
	}
	if string(pkt[len(addr):]) != string(payload) {
		t.Fatalf("server response payload = %q, want %q", pkt[len(addr):], payload)
	}
}
