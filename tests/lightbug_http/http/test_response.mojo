import testing
from lightbug_http.http import HTTPResponse, StatusCode
from lightbug_http.strings import to_string


def test_response_from_bytes():
    alias data = "HTTP/1.1 200 OK\r\nServer: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 17\r\n\r\nThis is the body!"
    var response = HTTPResponse.from_bytes(data.as_bytes())
    testing.assert_equal(response.protocol, "HTTP/1.1")
    testing.assert_equal(response.status_code, 200)
    testing.assert_equal(response.status_text, "OK")
    testing.assert_equal(response.headers["Server"], "example.com")
    testing.assert_equal(response.headers["Content-Type"], "text/html")
    testing.assert_equal(response.headers["Content-Encoding"], "gzip")

    testing.assert_equal(response.content_length(), 17)
    response.set_content_length(10)
    testing.assert_equal(response.content_length(), 10)

    testing.assert_false(response.connection_close())
    response.set_connection_close()
    testing.assert_true(response.connection_close())
    response.set_connection_keep_alive()
    testing.assert_false(response.connection_close())
    testing.assert_equal(String(response.get_body()), String("This is the body!"))


def test_is_redirect():
    alias data = "HTTP/1.1 200 OK\r\nServer: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 17\r\n\r\nThis is the body!"
    var response = HTTPResponse.from_bytes(data.as_bytes())
    testing.assert_false(response.is_redirect())

    response.status_code = StatusCode.MOVED_PERMANENTLY
    testing.assert_true(response.is_redirect())

    response.status_code = StatusCode.FOUND
    testing.assert_true(response.is_redirect())

    response.status_code = StatusCode.TEMPORARY_REDIRECT
    testing.assert_true(response.is_redirect())

    response.status_code = StatusCode.PERMANENT_REDIRECT
    testing.assert_true(response.is_redirect())


def test_read_body():
    ...


def test_read_chunks():
    ...


def test_encode():
    ...


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()