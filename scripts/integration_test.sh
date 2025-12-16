#!/bin/bash
echo "[INFO] Building mojo binaries.."

kill_server() {
    pid=$(ps aux | grep "$1" | grep -v grep | awk '{print $2}' | head -n 1)
    kill $pid
    wait $pid 2>/dev/null
}

test_server() {
    (pixi run mojo build -I . --debug-level full tests/integration/integration_test_server.mojo) || exit 1

    echo "[INFO] Starting Mojo server..."
    ./integration_test_server &

    sleep 5

    echo "[INFO] Testing server with Python client"
    pixi run python3 tests/integration/integration_client.py

    rm ./integration_test_server
    kill_server "integration_test_server" || echo "Failed to kill Mojo server"
}

test_server
