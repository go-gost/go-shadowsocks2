#!/usr/bin/env bash

set -e

SCRIPT_PATH=$(dirname "$(readlink -f "$0")")

# Source the run.sh to get functions and variables
source "$(dirname "$0")/service.sh"

# Test servers configuration
HTTP_SERVER_PORT=8888
UDP_SERVER_PORT=9999
UDP_SERVER_PORT_ALT=10000
TEST_SERVERS_PID=""

echo "========================================="
echo "Shadowsocks Integration Test"
echo "========================================="

# Cipher configurations
# Format: "cipher_name|password|extra args|description"
declare -a CIPHERS=(
	"aes-128-gcm|test-password-123| |AES-128-GCM (16-byte key)"
	"aes-256-gcm|test-password-123| |AES-256-GCM (32-byte key)"
	"chacha20-ietf-poly1305|test-password-123| |ChaCha20-Poly1305 (32-byte key)"
	"2022-blake3-aes-128-gcm|MTIzNDU2Nzg5MDEyMzQ1Ng==| |SIP023 AES-128-GCM (single PSK)"
	"2022-blake3-aes-256-gcm|MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=| |SIP023 AES-256-GCM (single PSK)"
	"2022-blake3-aes-128-gcm|MTIzNDU2Nzg5MDEyMzQ1Ng==:Vbwi6yqCwvPMPR1bCi32Dg==|-user test:Vbwi6yqCwvPMPR1bCi32Dg==|SIP023 AES-128-GCM (2-layer identity)"
	"2022-blake3-aes-256-gcm|MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=|-user test:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=|SIP023 AES-256-GCM (2-layer identity)"
)

# Cleanup function
cleanup() {
	echo ""
	echo "Cleaning up all processes..."
	if [ ! -z "$TEST_SERVERS_PID" ]; then
		kill $TEST_SERVERS_PID 2>/dev/null
		echo "  - Test servers stopped"
	fi
	if [ ! -z "$SERVER_PID" ]; then
		kill $SERVER_PID 2>/dev/null
		echo "  - Shadowsocks server stopped"
	fi
	if [ ! -z "$CLIENT_PID" ]; then
		kill $CLIENT_PID 2>/dev/null
		echo "  - SOCKS5 client stopped"
	fi
	pkill -f "go-shadowsocks2" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Wait for a port to be listening
waitForPort() {
	local port=$1
	local timeout=${3:-3}
	local elapsed=0
	local udp=$2
	local udp_args=""

	if [ "$udp" = "true" ]; then
		udp_args="-u"
	fi

	while ! nc -z $udp_args 127.0.0.1 $port 2>/dev/null; do
		sleep 1
		elapsed=$((elapsed + 1))
		if [ $elapsed -gt "$timeout" ]; then
			echo "TIMEOUT"
			return 1
		fi
	done
	return 0
}

# Test TCP connection via SOCKS5
testTCPHealth() {
	echo ""
	echo "----------------------------------------"
	echo "Test 1: TCP Health Check via SOCKS5"
	echo "----------------------------------------"

	echo -n "  Testing HTTP GET to local server via SOCKS5 proxy... "

	# Use curl with SOCKS5 proxy to access local HTTP server
	response=$(curl --socks5 127.0.0.1:${SOCKS_PORT} \
		--connect-timeout 10 \
		--max-time 15 \
		http://127.0.0.1:${HTTP_SERVER_PORT}/health 2>&1 || echo "FAILED")

	if echo "$response" | grep -q "OK"; then
		echo "PASSED"
		return 0
	else
		echo "FAILED"
		echo "  Response: $response"
		return 1
	fi
}

testTCPRootPage() {
	echo ""
	echo "----------------------------------------"
	echo "Test 2: TCP Root Page via SOCKS5"
	echo "----------------------------------------"

	echo -n "  Testing HTTP GET / via SOCKS5 proxy... "

	response=$(curl --socks5 127.0.0.1:${SOCKS_PORT} \
		--connect-timeout 10 \
		--max-time 15 \
		http://127.0.0.1:${HTTP_SERVER_PORT}/ 2>&1 || echo "FAILED")

	if printf '%s' "$response" | grep -q "Shadowsocks Test Server"; then
		echo "PASSED"
		return 0
	else
		echo "FAILED"
		echo "  Response: $response"
		return 1
	fi
}

# Test UDP connection via SOCKS5
testUDPShortPayload() {
	echo ""
	echo "----------------------------------------"
	echo "Test 3: UDP Short Payload via SOCKS5"
	echo "----------------------------------------"

	echo -n "  Testing UDP echo via SOCKS5 proxy... "

	# Use socks5_udp_echo to send UDP packet through SOCKS5 proxy
	result=$("${SOCKS5_UDP_ECHO_BIN}" 127.0.0.1:${SOCKS_PORT} 127.0.0.1:${UDP_SERVER_PORT} "test" 2>&1)

	if printf '%s' "$result" | grep -q "UDP echo successful"; then
		echo "PASSED"
		printf '%s\n' "$result" | grep -E "Sent:|Received:" | sed 's/^/    /'
	else
		echo "FAILED"
		echo "  Output:"
		printf '%s\n' "$result" | sed -n '1,10p' | sed 's/^/    /'
		return 1
	fi

	echo ""
	echo "  ✓ Base UDP SOCKS5 relay functional"

	return 0
}

testUDPLongPayload() {
	local payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"

	echo ""
	echo "----------------------------------------"
	echo "Test 4: UDP Long Payload via SOCKS5"
	echo "----------------------------------------"

	echo -n "  Testing 256-byte UDP echo via SOCKS5 proxy... "

	result=$("${SOCKS5_UDP_ECHO_BIN}" 127.0.0.1:${SOCKS_PORT} 127.0.0.1:${UDP_SERVER_PORT} "$payload" 2>&1)

	if printf '%s' "$result" | grep -q "UDP echo successful"; then
		echo "PASSED"
		return 0
	else
		echo "FAILED"
		echo "  Output:"
		printf '%s\n' "$result" | sed -n '1,10p' | sed 's/^/    /'
		return 1
	fi
	return 0
}

testUDPHostnameTarget() {
	local hostname="localhost.localdomain"
	local resolved

	echo ""
	echo "----------------------------------------"
	echo "Test 5: UDP Hostname Target via SOCKS5"
	echo "----------------------------------------"

	resolved=$(getent ahostsv4 "$hostname" 2>/dev/null | grep "STREAM" | sed -n '1s/ .*//p')
	if [ "$resolved" != "127.0.0.1" ]; then
		echo "  SKIPPED"
		echo "  Reason: $hostname does not resolve to 127.0.0.1 in this environment"
		return 2
	fi

	echo -n "  Testing UDP echo via SOCKS5 proxy using hostname target... "

	result=$("${SOCKS5_UDP_ECHO_BIN}" 127.0.0.1:${SOCKS_PORT} ${hostname}:${UDP_SERVER_PORT} "domain-test" 2>&1)

	if printf '%s' "$result" | grep -q "UDP echo successful"; then
		echo "PASSED"
		return 0
	else
		echo "FAILED"
		echo "  Output:"
		printf '%s\n' "$result" | sed -n '1,10p' | sed 's/^/    /'
		return 1
	fi
	return 0
}

testUDPMultipleTargets() {
	local target_a="127.0.0.1:${UDP_SERVER_PORT}"
	local target_b="127.0.0.1:${UDP_SERVER_PORT_ALT}"
	local result

	echo ""
	echo "----------------------------------------"
	echo "Test 6: UDP Multiple Targets via SOCKS5"
	echo "----------------------------------------"

	echo -n "  Testing alternating UDP targets under one SOCKS5 association... "

	result=$("${SOCKS5_UDP_ECHO_BIN}" 127.0.0.1:${SOCKS_PORT} "$target_a,$target_b,$target_a" "multi-target" 2>&1)

	if printf '%s' "$result" | grep -q "UDP multi-target successful"; then
		echo "PASSED"
		return 0
	else
		echo "FAILED"
		echo "  Output:"
		printf '%s\n' "$result" | sed -n '1,12p' | sed 's/^/    /'
		return 1
	fi
}

runTestCase() {
	local test_name=$1
	local status=0

	if "$test_name"; then
		status=0
	else
		status=$?
	fi

	case "$status" in
	0)
		total_tests=$((total_tests + 1))
		;;
	2)
		total_skipped=$((total_skipped + 1))
		;;
	*)
		total_failed=$((total_failed + 1))
		total_tests=$((total_tests + 1))
		;;
	esac

	return 0
}

# Main test execution
main() {
	# Initialize test counters
	local total_tests=0
	local total_failed=0
	local total_skipped=0
	local expected_tests_per_cipher=6

	# Build executables
	echo -n "Building main executable... "
	cd "${SCRIPT_PATH}/.."
	MAIN_BIN="${SCRIPT_PATH}/main"
	if go build -race -o "${MAIN_BIN}" ./cmd/main >/dev/null 2>&1; then
		echo "done"
	else
		echo "FAILED"
		echo "Error: Failed to build main executable"
		exit 1
	fi

	cd test
	echo -n "Building test servers... "
	TEST_SERVERS_BIN="${SCRIPT_PATH}/test_servers"
	if go build -o "${TEST_SERVERS_BIN}" test_servers.go 2>/dev/null; then
		echo "done"
	else
		echo "FAILED"
		echo "Error: Failed to build test_servers"
		exit 1
	fi

	echo -n "Building SOCKS5 UDP echo tool... "
	SOCKS5_UDP_ECHO_BIN="${SCRIPT_PATH}/socks5_udp_echo"
	if go build -o "${SOCKS5_UDP_ECHO_BIN}" socks5_udp_echo.go 2>/dev/null; then
		echo "done"
	else
		echo "FAILED"
		echo "Error: Failed to build socks5_udp_echo"
		exit 1
	fi

	# Start test servers
	echo -n "Starting test servers (HTTP:${HTTP_SERVER_PORT}, UDP:${UDP_SERVER_PORT}, UDP2:${UDP_SERVER_PORT_ALT})... "
	"${TEST_SERVERS_BIN}" -http ${HTTP_SERVER_PORT} -udp ${UDP_SERVER_PORT} -udp2 ${UDP_SERVER_PORT_ALT} >/dev/null 2>&1 &
	TEST_SERVERS_PID=$!
	sleep 1
	if ! kill -0 $TEST_SERVERS_PID 2>/dev/null; then
		echo "FAILED"
		echo "Error: Test servers failed to start"
		exit 1
	fi
	# Verify servers are listening
	if waitForPort ${HTTP_SERVER_PORT} && waitForPort ${UDP_SERVER_PORT} true && waitForPort ${UDP_SERVER_PORT_ALT} true; then
		echo "done"
	else
		echo "FAILED"
		echo "Error: Test servers not listening on expected ports"
		exit 1
	fi

	echo ""
	echo "========================================="
	echo "Testing All Cipher Methods"
	echo "========================================="

	# Test each cipher
	for cipher_config in "${CIPHERS[@]}"; do
		IFS='|' read -r cipher password extra_args description <<<"$cipher_config"
		CURRENT_CIPHER="$cipher"

		echo ""
		local completed_ciphers=$(((total_tests + total_skipped) / expected_tests_per_cipher))
		echo "[$((completed_ciphers + 1))/${#CIPHERS[@]}] Testing: $description"
		echo "    Cipher: $cipher"

		# Start services for this cipher
		if ! startServices "$cipher" "$password" "$extra_args"; then
			echo "    SKIPPED: Failed to start services"
			total_failed=$((total_failed + expected_tests_per_cipher))
			total_tests=$((total_tests + expected_tests_per_cipher))
			stopServices
			continue
		fi

		runTestCase testTCPHealth
		runTestCase testTCPRootPage
		runTestCase testUDPShortPayload
		runTestCase testUDPLongPayload
		runTestCase testUDPHostnameTarget
		runTestCase testUDPMultipleTargets

		# Stop services for this cipher
		stopServices
	done

	# Summary
	echo ""
	echo "========================================="
	echo "Test Summary"
	echo "========================================="
	local expected_total=$((expected_tests_per_cipher * ${#CIPHERS[@]}))
	if [ $((total_tests + total_skipped)) -ne "$expected_total" ]; then
		echo "Coverage mismatch: ran/skipped $((total_tests + total_skipped)) of $expected_total expected test cases"
		exit 1
	fi
	echo "Total tests: $total_tests"
	echo "Passed: $((total_tests - total_failed))"
	echo "Failed: $total_failed"
	echo "Skipped: $total_skipped"
	echo ""

	if [ "$total_failed" -eq 0 ]; then
		echo "All tests passed!"
		exit 0
	else
		echo "$total_failed test(s) failed"
		exit 1
	fi
}

main "$@"
