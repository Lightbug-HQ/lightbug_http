from lightbug_http.header import Header, Headers, encode_latin1_header_value, write_header_latin1
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter
from testing import TestSuite, assert_equal, assert_true


def test_header_case_insensitive():
    var headers = Headers(Header("Host", "SomeHost"))
    assert_true("host" in headers)
    assert_true("HOST" in headers)
    assert_true("hOST" in headers)
    assert_equal(headers["Host"], "SomeHost")
    assert_equal(headers["host"], "SomeHost")


# def test_parse_request_header():
#     var headers_str = "GET /index.html HTTP/1.1\r\nHost:example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"
#     var header = Headers()
#     var reader = ByteReader(headers_str.as_bytes())
#     var properties = header.parse_raw_request(reader)
#     assert_equal(properties.path, "/index.html")
#     assert_equal(properties.protocol, "HTTP/1.1")
#     assert_equal(properties.method, "GET")
#     assert_equal(header["Host"], "example.com")
#     assert_equal(header["User-Agent"], "Mozilla/5.0")
#     assert_equal(header["Content-Type"], "text/html")
#     assert_equal(header["Content-Length"], "1234")
#     assert_equal(header["Connection"], "close")


# def test_parse_response_header():
#     var headers_str = "HTTP/1.1 200 OK\r\nServer: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"
#     var header = Headers()
#     var reader = ByteReader(headers_str.as_bytes())
#     var properties = header.parse_raw_response(reader)
#     assert_equal(properties.protocol, "HTTP/1.1")
#     assert_equal(properties.status, 200)
#     assert_equal(properties.msg, "OK")
#     assert_equal(header["Server"], "example.com")
#     assert_equal(header["Content-Type"], "text/html")
#     assert_equal(header["Content-Encoding"], "gzip")
#     assert_equal(header["Content-Length"], "1234")
#     assert_equal(header["Connection"], "close")
#     assert_equal(header["Trailer"], "end-of-message")


def test_encode_latin1_ascii():
    """ASCII values are passed through unchanged."""
    var result = encode_latin1_header_value("hello, world")
    assert_equal(len(result), 12)
    assert_equal(result[0], UInt8(0x68))  # 'h'
    assert_equal(result[5], UInt8(0x2C))  # ','


def test_encode_latin1_supplement():
    """UTF-8 codepoints U+0080–U+00FF are transcoded to single ISO-8859-1 bytes."""
    # "é" = U+00E9, UTF-8: 0xC3 0xA9 → ISO-8859-1: 0xE9
    var result = encode_latin1_header_value("é")
    assert_equal(len(result), 1)
    assert_equal(result[0], UInt8(0xE9))

    # "ä" = U+00E4, UTF-8: 0xC3 0xA4 → ISO-8859-1: 0xE4
    result = encode_latin1_header_value("ä")
    assert_equal(len(result), 1)
    assert_equal(result[0], UInt8(0xE4))

    # "café": ASCII 'c','a','f' + U+00E9 → 4 bytes in ISO-8859-1
    result = encode_latin1_header_value("café")
    assert_equal(len(result), 4)
    assert_equal(result[3], UInt8(0xE9))


def test_encode_latin1_obs_text():
    """Raw obs-text bytes (0x80–0xFF, not part of a valid UTF-8 sequence) pass through as-is."""
    # 0xA2 alone is not a valid UTF-8 lead byte → treated as obs-text
    var result = encode_latin1_header_value("c\xa2y")
    assert_equal(len(result), 3)
    assert_equal(result[0], UInt8(0x63))  # 'c'
    assert_equal(result[1], UInt8(0xA2))  # obs-text byte preserved
    assert_equal(result[2], UInt8(0x79))  # 'y'


def test_encode_latin1_above_latin1():
    """Codepoints above U+00FF fall back to raw UTF-8 bytes (best-effort)."""
    # "€" = U+20AC, UTF-8: 0xE2 0x82 0xAC — codepoint > 0xFF → raw passthrough
    var result = encode_latin1_header_value("€")
    assert_equal(len(result), 3)
    assert_equal(result[0], UInt8(0xE2))
    assert_equal(result[1], UInt8(0x82))
    assert_equal(result[2], UInt8(0xAC))


def test_write_header_latin1_encodes_value():
    """Values with Latin-1 supplement characters are encoded as single bytes on the wire."""
    # "é" (U+00E9, UTF-8: 0xC3 0xA9) must appear as single byte 0xE9
    var writer = ByteWriter()
    write_header_latin1(writer, "x-test", "café")
    var bytes = writer^.consume()
    # "x-test: caf" = 11 bytes, then 0xE9 = 1 byte, then "\r\n" = 2 bytes → 14 total
    assert_equal(len(bytes), 14)
    assert_equal(bytes[11], UInt8(0xE9))  # single Latin-1 byte for 'é'
    assert_equal(bytes[12], UInt8(0x0D))  # \r
    assert_equal(bytes[13], UInt8(0x0A))  # \n


def test_headers_write_latin1_to():
    """Headers.write_latin1_to transcodes values for HTTP wire format."""
    var headers = Headers(Header("x-lang", "café"))
    var writer = ByteWriter()
    headers.write_latin1_to(writer)
    var bytes = writer^.consume()
    # "x-lang: caf" = 11 bytes, then 0xE9 = 1 byte, then "\r\n" = 2 bytes → 14 total
    assert_equal(len(bytes), 14)
    assert_equal(bytes[11], UInt8(0xE9))  # single Latin-1 byte for 'é'


def main():
    TestSuite.discover_tests[__functions_in_module()]().run()
