from lightbug_http.address import UDPAddr
from lightbug_http.connection import listen_udp


fn main() raises:
    var listener = listen_udp("127.0.0.1", 12000)

    while True:
        var response_host_port = listener.read_from(16)
        var message = StringSlice(unsafe_from_utf8=response_host_port[0])
        print("Message received:", message)

        # Response with the same message in uppercase
        _ = listener.write_to(String.upper(String(message)).as_bytes(), response_host_port[1], response_host_port[2])
