#!/usr/bin/env bash

# Shadowsocks server port
SERVER_PORT=8488
# SOCKS5 proxy port
SOCKS_PORT=8080
# Path to executable
MAIN_BIN=./main

# Start server and client for a specific cipher
startServices() {
	local cipher=$1
	local password=$2
	local extra_args=$3

	# Kill any existing processes
	sleep 0.2

	# Start server
	SERVER_LOG="${SCRIPT_PATH}/server_${cipher}.log"
	local server_password="${password%%:*}"
	${MAIN_BIN} -s "ss://${cipher}:${server_password}@127.0.0.1:${SERVER_PORT}" -verbose -udp $extra_args >"${SERVER_LOG}" 2>&1 &
	SERVER_PID=$!
	echo "Shadowsocks server started (PID: $SERVER_PID) on port ${SERVER_PORT}"
	echo "  Log: ${SERVER_LOG}"

	echo -n "  Waiting for server (${cipher})... "
	if waitForPort ${SERVER_PORT} 5; then
		sleep 0.3
		echo "ready"
	else
		echo "failed"
		return 1
	fi

	# Start client
	CLIENT_LOG="${SCRIPT_PATH}/client_${cipher}.log"
	${MAIN_BIN} -c "ss://${cipher}:${password}@127.0.0.1:${SERVER_PORT}" --socks "127.0.0.1:${SOCKS_PORT}" -verbose -udp >"${CLIENT_LOG}" 2>&1 &
	CLIENT_PID=$!
	echo "SOCKS5 client started (PID: $CLIENT_PID) on port ${SOCKS_PORT}"
	echo "  Log: ${CLIENT_LOG}"

	echo -n "  Waiting for client (${cipher})... "
	if waitForPort ${SOCKS_PORT} 5; then
		sleep 0.3
		echo "ready"
	else
		echo "failed"
		return 1
	fi

	return 0
}

# Stop server and client
stopServices() {
	if [ ! -z "$SERVER_PID" ]; then
		kill $SERVER_PID 2>/dev/null || true
		SERVER_PID=""
	fi
	if [ ! -z "$CLIENT_PID" ]; then
		kill $CLIENT_PID 2>/dev/null || true
		CLIENT_PID=""
	fi
	sleep 1
}
