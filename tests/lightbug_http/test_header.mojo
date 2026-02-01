from lightbug_http.header import Header, Headers
from lightbug_http.io.bytes import ByteReader, Bytes
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


def main():
    TestSuite.discover_tests[__functions_in_module()]().run()
