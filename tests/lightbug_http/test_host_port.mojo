from lightbug_http.address import (
    HostPort,
    NetworkType,
    ParseError,
    TCPAddr,
    join_host_port,
    parse_address,
)
from testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)


fn test_split_host_port_tcp4() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.tcp4]("127.0.0.1:8080")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "127.0.0.1")
    assert_equal(hp.port, 8080)


fn test_split_host_port_tcp4_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.tcp4]("localhost:8080")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "127.0.0.1")
    assert_equal(hp.port, 8080)


fn test_split_host_port_tcp6() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.tcp6]("[::1]:8080")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "::1")
    assert_equal(hp.port, 8080)


fn test_split_host_port_tcp6_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.tcp6]("localhost:8080")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "::1")
    assert_equal(hp.port, 8080)


fn test_split_host_port_udp4() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.udp4]("192.168.1.1:53")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "192.168.1.1")
    assert_equal(hp.port, 53)


fn test_split_host_port_udp4_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.udp4]("localhost:53")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "127.0.0.1")
    assert_equal(hp.port, 53)


fn test_split_host_port_udp6() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.udp6]("[2001:db8::1]:53")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "2001:db8::1")
    assert_equal(hp.port, 53)


fn test_split_host_port_udp6_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.udp6]("localhost:53")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "::1")
    assert_equal(hp.port, 53)


fn test_split_host_port_ip4() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.ip4]("192.168.1.1")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "192.168.1.1")
    assert_equal(hp.port, 0)


fn test_split_host_port_ip4_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.ip4]("localhost")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "127.0.0.1")
    assert_equal(hp.port, 0)


fn test_split_host_port_ip6() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.ip6]("2001:db8::1")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "2001:db8::1")
    assert_equal(hp.port, 0)


fn test_split_host_port_ip6_localhost() raises:
    var hp: HostPort
    try:
        hp = parse_address[NetworkType.ip6]("localhost")
    except e:
        raise Error("Error in parse_address:", e)

    assert_equal(hp.host, "::1")
    assert_equal(hp.port, 0)


fn test_split_host_port_error_ip_with_port() raises:
    with assert_raises(
        contains="IP protocol addresses should not include ports"
    ):
        _ = parse_address[NetworkType.ip4]("192.168.1.1:80")


fn test_split_host_port_error_missing_port_ipv4() raises:
    with assert_raises(
        contains=(
            "Failed to parse address: missing port separator ':' in address."
        )
    ):
        _ = parse_address[NetworkType.tcp4]("192.168.1.1")


fn test_split_host_port_error_missing_port_ipv6() raises:
    with assert_raises(
        contains="Failed to parse ipv6 address: missing port in address"
    ):
        _ = parse_address[NetworkType.tcp6]("[::1]")


fn test_split_host_port_error_port_out_of_range() raises:
    with assert_raises(
        contains=(
            "Failed to parse port: Port number out of range (0-65535)."
            " Received: 70000"
        )
    ):
        _ = parse_address[NetworkType.tcp4]("192.168.1.1:70000")


fn test_split_host_port_error_missing_bracket() raises:
    with assert_raises(contains="Failed to parse ipv6 address: missing ']'"):
        _ = parse_address[NetworkType.tcp6]("[::1:8080")


def test_join_host_port():
    # IPv4
    assert_equal(join_host_port("127.0.0.1", "8080"), "127.0.0.1:8080")

    # IPv6
    assert_equal(join_host_port("::1", "8080"), "[::1]:8080")

    # TODO: IPv6 long form - Not supported yet.


fn main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
