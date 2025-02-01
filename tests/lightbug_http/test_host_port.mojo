import testing
from lightbug_http.address import join_host_port, parse_address, TCPAddr
from lightbug_http.strings import NetworkType


def test_split_host_port():
    # TCP4
    var hp = parse_address(NetworkType.tcp4, "127.0.0.1:8080")
    testing.assert_equal(hp[0], "127.0.0.1")
    testing.assert_equal(hp[1], 8080)

    # TCP4 with localhost
    hp = parse_address(NetworkType.tcp4, "localhost:8080")
    testing.assert_equal(hp[0], "127.0.0.1")
    testing.assert_equal(hp[1], 8080)

    # TCP6
    hp = parse_address(NetworkType.tcp6, "[::1]:8080")
    testing.assert_equal(hp[0], "::1")
    testing.assert_equal(hp[1], 8080)

    # TCP6 with localhost
    hp = parse_address(NetworkType.tcp6, "localhost:8080")
    testing.assert_equal(hp[0], "::1")
    testing.assert_equal(hp[1], 8080)

    # UDP4
    hp = parse_address(NetworkType.udp4, "192.168.1.1:53")
    testing.assert_equal(hp[0], "192.168.1.1")
    testing.assert_equal(hp[1], 53)

    # UDP4 with localhost
    hp = parse_address(NetworkType.udp4, "localhost:53")
    testing.assert_equal(hp[0], "127.0.0.1")
    testing.assert_equal(hp[1], 53)

    # UDP6
    hp = parse_address(NetworkType.udp6, "[2001:db8::1]:53")
    testing.assert_equal(hp[0], "2001:db8::1")
    testing.assert_equal(hp[1], 53)

    # UDP6 with localhost
    hp = parse_address(NetworkType.udp6, "localhost:53")
    testing.assert_equal(hp[0], "::1")
    testing.assert_equal(hp[1], 53)

    # IP4 (no port)
    hp = parse_address(NetworkType.ip4, "192.168.1.1")
    testing.assert_equal(hp[0], "192.168.1.1")
    testing.assert_equal(hp[1], 0)

    # IP4 with localhost
    hp = parse_address(NetworkType.ip4, "localhost")
    testing.assert_equal(hp[0], "127.0.0.1")
    testing.assert_equal(hp[1], 0)

    # IP6 (no port)
    hp = parse_address(NetworkType.ip6, "2001:db8::1")
    testing.assert_equal(hp[0], "2001:db8::1")
    testing.assert_equal(hp[1], 0)

    # IP6 with localhost
    hp = parse_address(NetworkType.ip6, "localhost")
    testing.assert_equal(hp[0], "::1")
    testing.assert_equal(hp[1], 0)

    # TODO: IPv6 long form - Not supported yet.
    # hp = parse_address("0:0:0:0:0:0:0:1:8080")
    # testing.assert_equal(hp[0], "0:0:0:0:0:0:0:1")
    # testing.assert_equal(hp[1], 8080)

    # Error cases
    # IP protocol with port
    try:
        _ = parse_address(NetworkType.ip4, "192.168.1.1:80")
        testing.assert_false("Should have raised an error for IP protocol with port")
    except Error:
        testing.assert_true(True)

    # Missing port
    try:
        _ = parse_address(NetworkType.tcp4, "192.168.1.1")
        testing.assert_false("Should have raised MissingPortError")
    except MissingPortError:
        testing.assert_true(True)

    # Missing port
    try:
        _ = parse_address(NetworkType.tcp6, "[::1]")
        testing.assert_false("Should have raised MissingPortError")
    except MissingPortError:
        testing.assert_true(True)

    # Port out of range
    try:
        _ = parse_address(NetworkType.tcp4, "192.168.1.1:70000")
        testing.assert_false("Should have raised error for invalid port")
    except Error:
        testing.assert_true(True)
    
    # Missing closing bracket
    try:
        _ = parse_address(NetworkType.tcp6, "[::1:8080")
        testing.assert_false("Should have raised error for missing bracket")
    except Error:
        testing.assert_true(True)


def test_join_host_port():
    # IPv4
    testing.assert_equal(join_host_port("127.0.0.1", "8080"), "127.0.0.1:8080")

    # IPv6
    testing.assert_equal(join_host_port("::1", "8080"), "[::1]:8080")

    # TODO: IPv6 long form - Not supported yet.
