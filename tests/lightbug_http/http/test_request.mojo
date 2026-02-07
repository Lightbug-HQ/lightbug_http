import testing
from lightbug_http.header import parse_request_headers
from lightbug_http.io.bytes import Bytes

from lightbug_http.http import HTTPRequest, StatusCode

# Constants from ServerConfig defaults
comptime default_max_request_body_size = 4 * 1024 * 1024  # 4MB
comptime default_max_request_uri_length = 8192


def test_request_from_bytes():
    comptime data = "GET /redirect HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept: */*\r\nconnection: keep-alive\r\n\r\n"
    var parsed = parse_request_headers(data.as_bytes())
    var request: HTTPRequest
    try:
        request = HTTPRequest.from_parsed(
            "127.0.0.1",
            parsed^,
            Bytes(),
            default_max_request_uri_length,
        )
    except _:
        testing.assert_true(False, "Failed to parse HTTP request")
        return

    testing.assert_equal(request.protocol, "HTTP/1.1")
    testing.assert_equal(request.method, "GET")
    testing.assert_equal(request.uri.request_uri, "/redirect")
    testing.assert_equal(request.headers["host"], "127.0.0.1:8080")
    testing.assert_equal(
        request.headers["user-agent"], "python-requests/2.32.3"
    )

    testing.assert_false(request.connection_close())
    request.set_connection_close()
    testing.assert_true(request.connection_close())


def test_read_body():
    comptime data = "GET /redirect HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept: */*\r\nContent-Length: 17\r\nconnection: keep-alive\r\n\r\nThis is the body!"
    # Parse headers first
    var data_span = data.as_bytes()
    var parsed = parse_request_headers(data_span)

    # Extract body (starts after headers)
    var body_start = parsed.bytes_consumed
    var body = Bytes()
    for i in range(body_start, len(data_span)):
        body.append(data_span[i])

    var request: HTTPRequest
    try:
        request = HTTPRequest.from_parsed(
            "127.0.0.1",
            parsed^,
            body^,
            default_max_request_uri_length,
        )
    except _:
        testing.assert_true(False, "Failed to parse HTTP request")
        return

    testing.assert_equal(request.protocol, "HTTP/1.1")
    testing.assert_equal(request.method, "GET")
    testing.assert_equal(request.uri.request_uri, "/redirect")
    testing.assert_equal(request.headers["host"], "127.0.0.1:8080")
    testing.assert_equal(
        request.headers["user-agent"], "python-requests/2.32.3"
    )
    testing.assert_equal(
        String(request.get_body()), String("This is the body!")
    )


def test_encode():
    ...


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
