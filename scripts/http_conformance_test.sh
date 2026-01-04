#!/bin/bash
set -e

echo "[INFO] HTTP/1.1 Conformance Test Suite"
echo "======================================="

CONFORMANCE_DIR="tests/integration/http_conformance"
SERVER_BINARY="./conformance_test_server"
SERVER_PID=""

# Cleanup function
cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "[INFO] Stopping conformance test server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    if [ -f "$SERVER_BINARY" ]; then
        rm -f "$SERVER_BINARY"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Build the conformance test server
echo "[INFO] Building conformance test server..."
pixi run mojo build -I . --debug-level full "$CONFORMANCE_DIR/conformance_test_server.mojo" -o "$SERVER_BINARY" || {
    echo "[ERROR] Failed to build conformance test server"
    exit 1
}

# Start the server in background
echo "[INFO] Starting conformance test server on http://127.0.0.1:8080..."
"$SERVER_BINARY" &
SERVER_PID=$!

# Wait for server to be ready
echo "[INFO] Waiting for server to be ready..."
sleep 2

# Check if server is still running
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "[ERROR] Server failed to start"
    exit 1
fi

echo "[INFO] Server is ready (PID: $SERVER_PID)"
echo ""

# Run the conformance test suite
pixi run python3 "$CONFORMANCE_DIR/run_conformance.py" http://127.0.0.1:8080 || {
    TEST_EXIT_CODE=$?
    echo ""
    echo "[ERROR] HTTP conformance tests failed"
    exit $TEST_EXIT_CODE
}

echo ""
echo "======================================="
echo "[SUCCESS] HTTP/1.1 conformance tests completed!"
