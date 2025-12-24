from collections import Dict, List

import testing
from lightbug_http.header import Header, HeaderKey, Headers
from lightbug_http.io.bytes import Bytes
from lightbug_http.uri import URI
from testing import assert_equal, assert_true

from lightbug_http.cookie import Cookie, Duration, RequestCookieJar, ResponseCookieJar, ResponseCookieKey
from lightbug_http.http import HTTPRequest, HTTPResponse, encode


comptime default_server_conn_string = "http://localhost:8080"


def test_encode_http_request():
    var uri: URI
    try:
        uri = URI.parse(default_server_conn_string + "/foobar?baz")
    except e:
        raise Error("Failed to parse URI: ", e)

    var req = HTTPRequest(
        uri=uri^,
        body=Bytes(String("Hello world!").as_bytes()),
        cookies=RequestCookieJar(
            Cookie(
                name="session_id",
                value="123",
                path=String("/"),
                secure=True,
                max_age=Duration(minutes=10),
            ),
            Cookie(
                name="token",
                value="abc",
                domain=String("localhost"),
                path=String("/api"),
                http_only=True,
            ),
        ),
        headers=Headers(Header("Connection", "keep-alive")),
    )

    var as_str = String(req)
    var req_encoded = String(bytes=encode(req^))

    var expected = "GET /foobar?baz HTTP/1.1\r\nconnection: keep-alive\r\ncontent-length: 12\r\nhost: localhost:8080\r\ncookie: session_id=123; token=abc\r\n\r\nHello world!"

    testing.assert_equal(req_encoded, expected)
    testing.assert_equal(req_encoded, as_str)


def test_encode_http_response():
    var res = HTTPResponse("Hello, World!".as_bytes())
    res.headers[HeaderKey.DATE] = "2024-06-02T13:41:50.766880+00:00"

    res.cookies = ResponseCookieJar(
        Cookie(
            name="session_id", value="123", path=String("/api"), secure=True
        ),
        Cookie(
            name="session_id",
            value="abc",
            path=String("/"),
            secure=True,
            max_age=Duration(minutes=10),
        ),
        Cookie(
            name="token",
            value="123",
            domain=String("localhost"),
            path=String("/api"),
            http_only=True,
        ),
    )
    var as_str = String(res)
    var res_encoded = String(bytes=encode(res^))
    var expected_full = "HTTP/1.1 200 OK\r\nserver: lightbug_http\r\ncontent-type: application/octet-stream\r\nconnection: keep-alive\r\ncontent-length: 13\r\ndate: 2024-06-02T13:41:50.766880+00:00\r\nset-cookie: session_id=123; Path=/api; Secure\r\nset-cookie: session_id=abc; Max-Age=600; Path=/; Secure\r\nset-cookie: token=123; Domain=localhost; Path=/api; HttpOnly\r\n\r\nHello, World!"

    testing.assert_equal(res_encoded, expected_full)
    testing.assert_equal(res_encoded, as_str)


def test_decoding_http_response():
    var res = String(
        "HTTP/1.1 200 OK\r\n"
        "server: lightbug_http\r\n"
        "content-type: application/octet-stream\r\n"
        "connection: keep-alive\r\ncontent-length: 13\r\n"
        "date: 2024-06-02T13:41:50.766880+00:00\r\n"
        "set-cookie: session_id=123; Path=/; Secure\r\n"
        "\r\n"
        "Hello, World!"
    ).as_bytes()

    var response = HTTPResponse.from_bytes(res)
    var expected_cookie_key = ResponseCookieKey("session_id", "", "/")

    assert_equal(1, len(response.cookies))
    assert_true(
        expected_cookie_key in response.cookies,
        msg="request should contain a session_id header",
    )
    var session_id = response.cookies.get(expected_cookie_key)
    assert_true(session_id is not None)
    assert_equal(session_id.value().path.value(), "/")
    assert_equal(200, response.status_code)
    assert_equal("OK", response.status_text)


# def test_http_version_parse():
#     var v1 = HttpVersion("HTTP/1.1")
#     testing.assert_equal(v1._v, 1)
#     var v2 = HttpVersion("HTTP/2")
#     testing.assert_equal(v2._v, 2)


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
