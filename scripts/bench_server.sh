

pixi run mojo build -I . benchmark/bench_server.mojo || exit 1

echo "running server..."
./bench_server&

sleep 2

echo "Running benchmark"
wrk -t1 -c1 -d10s http://localhost:8080/ --header "User-Agent: wrk"

kill $!
wait $! 2>/dev/null

rm bench_server
