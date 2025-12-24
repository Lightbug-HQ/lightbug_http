import testing
from lightbug_http.server import default_max_request_body_size, default_max_request_uri_length

from lightbug_http.http import HTTPRequest, StatusCode


def test_request_from_bytes():
    comptime data = "GET /redirect HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept: */*\r\nconnection: keep-alive\r\n\r\n"
    var request: HTTPRequest
    try:
        request = HTTPRequest.from_bytes(
            "127.0.0.1",
            default_max_request_body_size,
            default_max_request_uri_length,
            data.as_bytes(),
        )
        if request is not None:
            testing.assert_equal(request.protocol, "HTTP/1.1")
            testing.assert_equal(request.method, "GET")
            testing.assert_equal(request.uri.request_uri, "/redirect")
            testing.assert_equal(request.headers["Host"], "127.0.0.1:8080")
            testing.assert_equal(
                request.headers["User-Agent"], "python-requests/2.32.3"
            )

            testing.assert_false(request.connection_close())
            request.set_connection_close()
            testing.assert_true(request.connection_close())
    except e:
        testing.assert_true(False, "Failed to parse HTTP request: " + String(e))


def test_read_body():
    comptime data = "GET /redirect HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept: */\r\nContent-Length: 17\r\nconnection: keep-alive\r\n\r\nThis is the body!"
    var request: HTTPRequest
    try:
        request = HTTPRequest.from_bytes(
            "127.0.0.1",
            default_max_request_body_size,
            default_max_request_uri_length,
            data.as_bytes(),
        )
        if request is not None:
            testing.assert_equal(request.protocol, "HTTP/1.1")
            testing.assert_equal(request.method, "GET")
            testing.assert_equal(request.uri.request_uri, "/redirect")
            testing.assert_equal(request.headers["Host"], "127.0.0.1:8080")
            testing.assert_equal(
                request.headers["User-Agent"], "python-requests/2.32.3"
            )
            testing.assert_equal(
                String(request.get_body()), String("This is the body!")
            )
    except e:
        testing.assert_true(False, "Failed to parse HTTP request: " + String(e))


def test_encode():
    ...


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
