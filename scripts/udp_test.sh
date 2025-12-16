#!/bin/bash
echo "[INFO] Building mojo binaries.."

kill_server() {
    pid=$(ps aux | grep "$1" | grep -v grep | awk '{print $2}' | head -n 1)
    kill $pid
    wait $pid 2>/dev/null
}

(pixi run mojo build -I . --debug-level full tests/integration/udp/udp_server.mojo)
(pixi run mojo build -I . --debug-level full tests/integration/udp/udp_client.mojo)

echo "[INFO] Starting UDP server..."
./udp_server &
sleep 5

echo "[INFO] Testing server with UDP client"
./udp_client

rm ./udp_server
rm ./udp_client
kill_server "udp_server" || echo "Failed to kill udp server"
