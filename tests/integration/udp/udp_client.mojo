from lightbug_http.address import UDPAddr
from lightbug_http.connection import dial_udp


fn main() raises:
    print("Dialing UDP server...")
    var test_string = "Hello, lightbug!"
    var host = "127.0.0.1"
    comptime port = 12000
    var udp = dial_udp(host, port)

    print("Sending", len(test_string), "messages to the server...")
    for i in range(len(test_string)):
        _ = udp.write_to(test_string[i].as_bytes(), host, port)

        try:
            print("Response received:", StringSlice(unsafe_from_utf8=udp.read_from(16)[0]))
        except e:
            if String(e) != String("EOF"):
                raise e
