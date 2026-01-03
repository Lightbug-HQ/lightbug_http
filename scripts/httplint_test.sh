#!/bin/bash
set -e

echo "[INFO] httplint HTTP/1.1 Compliance Test Suite"
echo "================================================"

# Cleanup function
cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "[INFO] Stopping httplint test server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    if [ -f "./httplint_server" ]; then
        rm ./httplint_server
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Build the httplint test server
echo "[INFO] Building httplint test server..."
pixi run mojo build -I . --debug-level full tests/integration/httplint/httplint_server.mojo || {
    echo "[ERROR] Failed to build httplint test server"
    exit 1
}

# Start the server in background
echo "[INFO] Starting httplint test server on http://127.0.0.1:8080..."
./httplint_server &
SERVER_PID=$!

# Wait for server to be ready
echo "[INFO] Waiting for server to be ready..."
sleep 5

# Check if server is still running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "[ERROR] Server failed to start"
    exit 1
fi

echo "[INFO] Server is ready (PID: $SERVER_PID)"

# Run the httplint test suite
echo "[INFO] Running httplint compliance test suite..."
echo "--------------------------------------"
pixi run python3 tests/integration/httplint/httplint_suite.py --host 127.0.0.1 --port 8080 || {
    TEST_EXIT_CODE=$?
    echo "[ERROR] httplint tests failed with exit code $TEST_EXIT_CODE"
    exit $TEST_EXIT_CODE
}

echo "================================================"
echo "[SUCCESS] httplint compliance tests completed!"
