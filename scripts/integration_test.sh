#!/bin/bash
echo "[INFO] Building mojo binaries.."

kill_server() {
    pid=$(ps aux | grep "$1" | grep -v grep | awk '{print $2}' | head -n 1)
    kill $pid
    wait $pid 2>/dev/null
}

test_server() {
    (pixi run mojo build -D LB_LOG_LEVEL=DEBUG -I . --debug-level full tests/integration/integration_test_server.mojo) || exit 1

    echo "[INFO] Starting Mojo server..."
    ./integration_test_server &

    sleep 5

    echo "[INFO] Testing server with Python client"
    pixi run python3 tests/integration/integration_client.py

    rm ./integration_test_server
    kill_server "integration_test_server" || echo "Failed to kill Mojo server"
}

test_client() {
    echo "[INFO] Testing Mojo client with Python server"
    (pixi run mojo build -D LB_LOG_LEVEL=DEBUG -I . --debug-level full tests/integration/integration_test_client.mojo) || exit 1

    echo "[INFO] Starting Python server..."
    pixi run fastapi run tests/integration/integration_server.py &
    sleep 5

    ./integration_test_client
    rm ./integration_test_client
    kill_server "fastapi run" || echo "Failed to kill fastapi server"
}

test_server
test_client
