from lightbug_http.http.parsing import (
    HTTPHeader,
    http_parse_headers,
    http_parse_request,
    http_parse_response,
)
from testing import TestSuite, assert_equal, assert_false, assert_true


# Test helper structures
@fieldwise_init
struct ParseRequestResult(Copyable, ImplicitlyCopyable):
    var ret: Int
    var method: String
    var method_len: Int
    var path: String
    var path_len: Int
    var minor_version: Int
    var num_headers: Int


@fieldwise_init
struct ParseResponseResult(Copyable, ImplicitlyCopyable):
    var ret: Int
    var minor_version: Int
    var status: Int
    var msg: String
    var msg_len: Int
    var num_headers: Int


@fieldwise_init
struct ParseHeadersResult(Copyable, ImplicitlyCopyable):
    var ret: Int
    var num_headers: Int


fn parse_request_test[
    origin: MutOrigin
](
    data: String, last_len: Int, headers: Span[HTTPHeader, origin]
) -> ParseRequestResult:
    """Helper to parse request and return results."""
    var result = ParseRequestResult(0, String(), 0, String(), 0, -1, 0)

    var buf = data.as_bytes()
    var buf_ptr = alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = http_parse_request(
        buf_ptr,
        len(buf),
        result.method,
        result.path,
        result.minor_version,
        headers,
        result.num_headers,
        last_len,
    )

    buf_ptr.free()
    return result


fn parse_response_test[
    origin: MutOrigin
](
    data: String, last_len: Int, headers: Span[HTTPHeader, origin]
) -> ParseResponseResult:
    """Helper to parse response and return results."""
    var result = ParseResponseResult(-1, -1, 0, String(), 0, 0)

    var buf = data.as_bytes()
    var buf_ptr = alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = http_parse_response(
        buf_ptr,
        len(buf),
        result.minor_version,
        result.status,
        result.msg,
        headers,
        result.num_headers,
        last_len,
    )

    buf_ptr.free()
    return result


fn parse_headers_test[
    origin: MutOrigin
](
    data: String, last_len: Int, headers: Span[HTTPHeader, origin]
) -> ParseHeadersResult:
    """Helper to parse headers and return results."""
    var result = ParseHeadersResult(0, 0)

    var buf = data.as_bytes()
    var buf_ptr = alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = http_parse_headers(
        buf_ptr, len(buf), headers, result.num_headers, last_len
    )

    buf_ptr.free()
    return result


fn test_request() raises:
    """Test HTTP request parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Simple request
    var result = parse_request_test("GET / HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, 18)
    assert_equal(result.num_headers, 0)
    assert_equal(result.method, "GET")
    assert_equal(result.path, "/")
    assert_equal(result.minor_version, 0)


fn test_request_partial() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Partial request
    result = parse_request_test("GET / HTTP/1.0\r\n\r", 0, headers)
    assert_equal(result.ret, -2)


fn test_request_with_headers() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Request with headers
    result = parse_request_test(
        "GET /hoge HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
        0,
        headers,
    )
    assert_equal(result.num_headers, 2)
    assert_equal(result.method, "GET")
    assert_equal(result.path, "/hoge")
    assert_equal(result.minor_version, 1)
    assert_equal(headers[0].name, "Host")
    assert_equal(headers[0].value, "example.com")
    assert_equal(headers[1].name, "Cookie")
    assert_equal(headers[1].value, "")


fn test_request_with_multiline_headers() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Multiline headers
    result = parse_request_test(
        "GET / HTTP/1.0\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n", 0, headers
    )
    assert_equal(result.num_headers, 3)
    assert_equal(result.method, "GET")
    assert_equal(result.path, "/")
    assert_equal(result.minor_version, 0)
    assert_equal(headers[0].name, "foo")
    assert_equal(headers[0].value, "")
    assert_equal(headers[1].name, "foo")
    assert_equal(headers[1].value, "b")
    assert_equal(headers[2].name_len, 0)  # Continuation line has no name
    assert_equal(headers[2].value, "  \tc")


fn test_request_invalid_header_trailing_space() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Invalid header name with trailing space
    result = parse_request_test(
        "GET / HTTP/1.0\r\nfoo : ab\r\n\r\n", 0, headers
    )
    assert_equal(result.ret, -1)


fn test_request_incomplete_request() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Various incomplete requests
    result = parse_request_test("GET", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_request_test("GET ", 0, headers)
    assert_equal(result.ret, -2)
    assert_equal(result.method, "GET")

    result = parse_request_test("GET /", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_request_test("GET / ", 0, headers)
    assert_equal(result.ret, -2)
    assert_equal(result.path, "/")

    result = parse_request_test("GET / H", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_request_test("GET / HTTP/1.", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_request_test("GET / HTTP/1.0", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_request_test("GET / HTTP/1.0\r", 0, headers)
    assert_equal(result.ret, -2)
    assert_equal(result.minor_version, 0)


fn test_request_slowloris() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Slowloris tests
    var test_str = "GET /hoge HTTP/1.0\r\n\r"
    result = parse_request_test(test_str, len(test_str) - 1, headers)
    assert_equal(result.ret, -2)

    var test_str_complete = "GET /hoge HTTP/1.0\r\n\r\n"
    result = parse_request_test(
        test_str_complete, len(test_str_complete) - 1, headers
    )
    assert_true(result.ret > 0)

    # Invalid requests
    result = parse_request_test(" / HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_request_test("GET  HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_request_test("GET / HTTP/1.0\r\n:a\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_request_test("GET / HTTP/1.0\r\n :a\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_additional_spaces() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Multiple spaces between tokens
    result = parse_request_test("GET   /   HTTP/1.0\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)


fn test_request_nul_in_method() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Additional test cases from C version

    # NUL in method
    result = parse_request_test("G\0T / HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_tab_in_method() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Tab in method
    result = parse_request_test("G\tT / HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_invalid_method() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Invalid method starting with colon
    result = parse_request_test(":GET / HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_del_in_path() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # DEL in uri-path
    result = parse_request_test("GET /\x7fhello HTTP/1.0\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_invalid_header_name_char() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Invalid char in header name
    result = parse_request_test("GET / HTTP/1.0\r\n/: 1\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_extended_chars() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Accept MSB chars
    result = parse_request_test(
        "GET /\xa0 HTTP/1.0\r\nh: c\xa2y\r\n\r\n", 0, headers
    )
    assert_true(result.ret > 0)
    assert_equal(result.num_headers, 1)
    assert_equal(result.method, "GET")
    assert_equal(result.path, "/\xa0")
    assert_equal(result.minor_version, 0)
    assert_equal(headers[0].name, "h")
    assert_equal(headers[0].value, "c\xa2y")


fn test_request_allowed_special_header_name_chars() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Accept |~ (though forbidden by SSE)
    result = parse_request_test(
        "GET / HTTP/1.0\r\n\x7c\x7e: 1\r\n\r\n", 0, headers
    )
    assert_true(result.ret > 0)
    assert_equal(result.num_headers, 1)
    assert_equal(headers[0].name, "\x7c\x7e")
    assert_equal(headers[0].value, "1")


fn test_request_disallowed_special_header_name_chars() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Disallow {
    result = parse_request_test("GET / HTTP/1.0\r\n\x7b: 1\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_exclude_leading_trailing_spaces_in_header_value() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Exclude leading and trailing spaces in header value
    result = parse_request_test(
        "GET / HTTP/1.0\r\nfoo: a \t \r\n\r\n", 0, headers
    )
    assert_true(result.ret > 0)
    assert_equal(headers[0].value, "a")


fn test_response() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Simple response
    var result = parse_response_test("HTTP/1.0 200 OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, 19)
    assert_equal(result.num_headers, 0)
    assert_equal(result.status, 200)
    assert_equal(result.minor_version, 0)
    assert_equal(result.msg, "OK")


fn test_partial_response() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Partial response
    result = parse_response_test("HTTP/1.0 200 OK\r\n\r", 0, headers)
    assert_equal(result.ret, -2)


fn test_response_with_headers() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Response with headers
    result = parse_response_test(
        "HTTP/1.1 200 OK\r\nHost: example.com\r\nCookie: \r\n\r\n", 0, headers
    )
    assert_equal(result.num_headers, 2)
    assert_equal(result.minor_version, 1)
    assert_equal(result.status, 200)
    assert_equal(result.msg, "OK")
    assert_equal(headers[0].name, "Host")
    assert_equal(headers[0].value, "example.com")
    assert_equal(headers[1].name, "Cookie")
    assert_equal(headers[1].value, "")


fn test_500_response() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Internal server error
    result = parse_response_test(
        "HTTP/1.0 500 Internal Server Error\r\n\r\n", 0, headers
    )
    assert_equal(result.num_headers, 0)
    assert_equal(result.minor_version, 0)
    assert_equal(result.status, 500)
    assert_equal(result.msg, "Internal Server Error")


fn test_incomplete_response() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Various incomplete responses
    result = parse_response_test("H", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.1", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.1 ", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.1 2", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.1 200", 0, headers)
    assert_equal(result.ret, -2)

    result = parse_response_test("HTTP/1.1 200 ", 0, headers)
    assert_equal(result.ret, -2)


fn test_response_accept_missing_trailing_whitespace() raises:
    """Test HTTP response parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Accept missing trailing whitespace in status-line
    result = parse_response_test("HTTP/1.1 200\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)
    assert_equal(result.msg, "")


fn test_response_invalid() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Invalid responses
    result = parse_response_test("HTTP/1. 200 OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.2z 200 OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1  OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_response_garbage_after_status() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Garbage after status code
    result = parse_response_test("HTTP/1.1 200X\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1 200X \r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1 200X OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_response_exclude_leading_and_trailing_spaces_in_header_value() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Exclude leading and trailing spaces in header value
    result = parse_response_test(
        "HTTP/1.1 200 OK\r\nbar: \t b\t \t\r\n\r\n", 0, headers
    )
    assert_true(result.ret > 0)
    assert_equal(headers[0].value, "b")


fn test_response_accept_multiple_spaces_between_tokens() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Accept multiple spaces between tokens
    result = parse_response_test("HTTP/1.1   200   OK\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)


fn test_response_with_multiline_headers() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Multiline headers
    result = parse_response_test(
        "HTTP/1.0 200 OK\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n", 0, headers
    )
    assert_equal(result.num_headers, 3)
    assert_equal(result.minor_version, 0)
    assert_equal(result.status, 200)
    assert_equal(result.msg, "OK")
    assert_equal(headers[0].name, "foo")
    assert_equal(headers[0].value, "")
    assert_equal(headers[1].name, "foo")
    assert_equal(headers[1].value, "b")
    assert_equal(headers[2].name_len, 0)
    assert_equal(headers[2].value, "  \tc")


fn test_response_slowloris() raises:
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Slowloris tests
    var test_str = "HTTP/1.0 200 OK\r\n\r"
    result = parse_response_test(test_str, len(test_str) - 1, headers)
    assert_equal(result.ret, -2)

    var test_str_complete = "HTTP/1.0 200 OK\r\n\r\n"
    result = parse_response_test(
        test_str_complete, len(test_str_complete) - 1, headers
    )
    assert_true(result.ret > 0)


fn test_headers() raises:
    """Test header parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())

    # Simple headers
    var result = parse_headers_test(
        "Host: example.com\r\nCookie: \r\n\r\n", 0, headers
    )
    assert_equal(result.ret, 31)
    assert_equal(result.num_headers, 2)
    assert_equal(headers[0].name, "Host")
    assert_equal(headers[0].value, "example.com")
    assert_equal(headers[1].name, "Cookie")
    assert_equal(headers[1].value, "")


fn test_headers_slowloris() raises:
    """Test header parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Slowloris test
    result = parse_headers_test(
        "Host: example.com\r\nCookie: \r\n\r\n", 1, headers
    )
    assert_equal(result.num_headers, 2)
    assert_true(result.ret > 0)


fn test_headers_partial() raises:
    """Test header parsing."""
    var headers = InlineArray[HTTPHeader, 4](fill=HTTPHeader())
    # Partial headers
    result = parse_headers_test(
        "Host: example.com\r\nCookie: \r\n\r", 0, headers
    )
    assert_equal(result.ret, -2)


fn main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
