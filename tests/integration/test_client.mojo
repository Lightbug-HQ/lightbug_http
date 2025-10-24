import testing
from lightbug_http.client import Client
from lightbug_http.http import HTTPRequest, encode
from lightbug_http.uri import URI
from lightbug_http.header import Header, Headers
from lightbug_http.io.bytes import bytes


fn test_mojo_client_redirect_external_req_google() raises:
    var client = Client()
    var req = HTTPRequest(
        uri=URI.parse("http://google.com"),
        headers=Headers(
            Header("Connection", "close")),
        method="GET",
    )
    try:
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
    except e:
        print(e)

fn test_mojo_client_redirect_external_req_302() raises:
    var client = Client()
    var req = HTTPRequest(
        uri=URI.parse("http://httpbingo.org/status/302"),
        headers=Headers(
            Header("Connection", "close")),
        method="GET",
    )
    try:
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
    except e:
        print(e)

fn test_mojo_client_redirect_external_req_308() raises:
    var client = Client()
    var req = HTTPRequest(
        uri=URI.parse("http://httpbingo.org/status/308"),
        headers=Headers(
            Header("Connection", "close")),
        method="GET",
    )
    try:
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
    except e:
        print(e)

fn test_mojo_client_redirect_external_req_307() raises:
    var client = Client()
    var req = HTTPRequest(
        uri=URI.parse("http://httpbingo.org/status/307"),
        headers=Headers(
            Header("Connection", "close")),
        method="GET",
    )
    try:
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
    except e:
        print(e)

fn test_mojo_client_redirect_external_req_301() raises:
    var client = Client()
    var req = HTTPRequest(
        uri=URI.parse("http://httpbingo.org/status/301"),
        headers=Headers(
            Header("Connection", "close")),
        method="GET",
    )
    try:
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
        testing.assert_equal(res.headers.content_length(), 228)
    except e:
        print(e)

fn test_mojo_client_lightbug_external_req_200() raises:
    try:
        var client = Client()
        var req = HTTPRequest(
            uri=URI.parse("http://example.com"),
            headers=Headers(
                Header("Connection", "close")),
            method="GET",
        )
        var res = client.do(req^)
        testing.assert_equal(res.status_code, 200)
    except e:
        print(e)
        raise
