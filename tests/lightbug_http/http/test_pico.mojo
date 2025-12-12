from lightbug_http.http.pico import (
    PhrChunkedDecoder,
    PhrHeader,
    phr_decode_chunked,
    phr_parse_headers,
    phr_parse_request,
    phr_parse_response,
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

fn parse_request_test[origin: MutOrigin](
    data: String,
    last_len: Int,
    headers: Span[PhrHeader, origin]
) -> ParseRequestResult:
    """Helper to parse request and return results."""
    var result = ParseRequestResult(0, String(), 0, String(), 0, -1, 0)

    var buf = data.as_bytes()
    var buf_ptr = alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = phr_parse_request(
        buf_ptr,
        len(buf),
        result.method,
        result.path,
        result.minor_version,
        headers,
        result.num_headers,
        last_len
    )

    buf_ptr.free()
    return result

fn parse_response_test[origin: MutOrigin](
    data: String,
    last_len: Int,
    headers: Span[PhrHeader, origin]
) -> ParseResponseResult:
    """Helper to parse response and return results."""
    var result = ParseResponseResult(-1, -1, 0, String(), 0, 0)

    var buf = data.as_bytes()
    var buf_ptr =  alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = phr_parse_response(
        buf_ptr,
        len(buf),
        result.minor_version,
        result.status,
        result.msg,
        headers,
        result.num_headers,
        last_len
    )

    buf_ptr.free()
    return result

fn parse_headers_test[origin: MutOrigin](
    data: String,
    last_len: Int,
    headers: Span[PhrHeader, origin]
) -> ParseHeadersResult:
    """Helper to parse headers and return results."""
    var result = ParseHeadersResult(0, 0)

    var buf = data.as_bytes()
    var buf_ptr =  alloc[UInt8](count=len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = phr_parse_headers(
       buf_ptr,
       len(buf),
       headers,
       result.num_headers,
       last_len
    )

    buf_ptr.free()
    return result

fn test_request() raises:
   """Test HTTP request parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Simple request
   var result = parse_request_test("GET / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, 18)
   assert_equal(result.num_headers, 0)
   assert_equal(result.method, "GET")
   assert_equal(result.path, "/")
   assert_equal(result.minor_version, 0)


fn test_request_partial() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Partial request
   result = parse_request_test("GET / HTTP/1.0\r\n\r", 0, headers)
   assert_equal(result.ret, -2)


fn test_request_with_headers() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Request with headers
   result = parse_request_test(
       "GET /hoge HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
       0, headers
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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Multiline headers
   result = parse_request_test(
       "GET / HTTP/1.0\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n",
       0, headers
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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Invalid header name with trailing space
   result = parse_request_test(
       "GET / HTTP/1.0\r\nfoo : ab\r\n\r\n",
       0, headers
   )
   assert_equal(result.ret, -1)


fn test_request_incomplete_request() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Slowloris tests
   var test_str = "GET /hoge HTTP/1.0\r\n\r"
   result = parse_request_test(test_str, len(test_str) - 1, headers)
   assert_equal(result.ret, -2)

   var test_str_complete = "GET /hoge HTTP/1.0\r\n\r\n"
   result = parse_request_test(test_str_complete, len(test_str_complete) - 1, headers)
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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Multiple spaces between tokens
   result = parse_request_test("GET   /   HTTP/1.0\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)


fn test_request_nul_in_method() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Additional test cases from C version

   # NUL in method
   result = parse_request_test("G\0T / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)


fn test_request_tab_in_method() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Tab in method
   result = parse_request_test("G\tT / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)


fn test_request_invalid_method() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Invalid method starting with colon
   result = parse_request_test(":GET / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)


fn test_request_del_in_path() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # DEL in uri-path
   result = parse_request_test("GET /\x7fhello HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)


fn test_request_invalid_header_name_char() raises:
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Invalid char in header name
   result = parse_request_test("GET / HTTP/1.0\r\n/: 1\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)


fn test_request_extended_chars() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Accept MSB chars
    result = parse_request_test("GET /\xa0 HTTP/1.0\r\nh: c\xa2y\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)
    assert_equal(result.num_headers, 1)
    assert_equal(result.method, "GET")
    assert_equal(result.path, "/\xa0")
    assert_equal(result.minor_version, 0)
    assert_equal(headers[0].name, "h")
    assert_equal(headers[0].value, "c\xa2y")


fn test_request_allowed_special_header_name_chars() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Accept |~ (though forbidden by SSE)
    result = parse_request_test("GET / HTTP/1.0\r\n\x7c\x7e: 1\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)
    assert_equal(result.num_headers, 1)
    assert_equal(headers[0].name, "\x7c\x7e")
    assert_equal(headers[0].value, "1")


fn test_request_disallowed_special_header_name_chars() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Disallow {
    result = parse_request_test("GET / HTTP/1.0\r\n\x7b: 1\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_request_exclude_leading_trailing_spaces_in_header_value() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Exclude leading and trailing spaces in header value
    result = parse_request_test("GET / HTTP/1.0\r\nfoo: a \t \r\n\r\n", 0, headers)
    assert_true(result.ret > 0)
    assert_equal(headers[0].value, "a")


fn test_response() raises:
   """Test HTTP response parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Simple response
   var result = parse_response_test("HTTP/1.0 200 OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, 19)
   assert_equal(result.num_headers, 0)
   assert_equal(result.status, 200)
   assert_equal(result.minor_version, 0)
   assert_equal(result.msg, "OK")


fn test_partial_response() raises:
   """Test HTTP response parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Partial response
   result = parse_response_test("HTTP/1.0 200 OK\r\n\r", 0, headers)
   assert_equal(result.ret, -2)


fn test_response_with_headers() raises:
   """Test HTTP response parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Response with headers
   result = parse_response_test(
       "HTTP/1.1 200 OK\r\nHost: example.com\r\nCookie: \r\n\r\n",
       0, headers
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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Internal server error
   result = parse_response_test(
       "HTTP/1.0 500 Internal Server Error\r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 0)
   assert_equal(result.minor_version, 0)
   assert_equal(result.status, 500)
   assert_equal(result.msg, "Internal Server Error")


fn test_incomplete_response() raises:
   """Test HTTP response parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
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
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Accept missing trailing whitespace in status-line
   result = parse_response_test("HTTP/1.1 200\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_equal(result.msg, "")


fn test_response_invalid() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Invalid responses
    result = parse_response_test("HTTP/1. 200 OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.2z 200 OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1  OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_response_garbage_after_status() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Garbage after status code
    result = parse_response_test("HTTP/1.1 200X\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1 200X \r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)

    result = parse_response_test("HTTP/1.1 200X OK\r\n\r\n", 0, headers)
    assert_equal(result.ret, -1)


fn test_response_exclude_leading_and_trailing_spaces_in_header_value() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Exclude leading and trailing spaces in header value
    result = parse_response_test("HTTP/1.1 200 OK\r\nbar: \t b\t \t\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)
    assert_equal(headers[0].value, "b")


fn test_response_accept_multiple_spaces_between_tokens() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Accept multiple spaces between tokens
    result = parse_response_test("HTTP/1.1   200   OK\r\n\r\n", 0, headers)
    assert_true(result.ret > 0)


fn test_response_with_multiline_headers() raises:
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Multiline headers
    result = parse_response_test(
        "HTTP/1.0 200 OK\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n",
        0, headers
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
    var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
    # Slowloris tests
    var test_str = "HTTP/1.0 200 OK\r\n\r"
    result = parse_response_test(test_str, len(test_str) - 1, headers)
    assert_equal(result.ret, -2)

    var test_str_complete = "HTTP/1.0 200 OK\r\n\r\n"
    result = parse_response_test(test_str_complete, len(test_str_complete) - 1, headers)
    assert_true(result.ret > 0)


fn test_headers() raises:
   """Test header parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())

   # Simple headers
   var result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r\n",
       0, headers
   )
   assert_equal(result.ret, 31)
   assert_equal(result.num_headers, 2)
   assert_equal(headers[0].name, "Host")
   assert_equal(headers[0].value, "example.com")
   assert_equal(headers[1].name, "Cookie")
   assert_equal(headers[1].value, "")


fn test_headers_slowloris() raises:
   """Test header parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Slowloris test
   result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r\n",
       1, headers
   )
   assert_equal(result.num_headers, 2)
   assert_true(result.ret > 0)


fn test_headers_partial() raises:
   """Test header parsing."""
   var headers = InlineArray[PhrHeader, 4](fill=PhrHeader())
   # Partial headers
   result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r",
       0, headers
   )
   assert_equal(result.ret, -2)


fn chunked_at_once_test(line: Int,
   consume_trailer: Bool,
   var encoded: String,
   decoded: String,
   expected: Int
) raises:
   """Test chunked decoding all at once."""
   var decoder = PhrChunkedDecoder()
   decoder.consume_trailer = consume_trailer

   var buf = List[Byte](encoded.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf)
   var ret = result[0]
   var new_bufsz = result[1]

   assert_equal(ret, expected)
   assert_equal(new_bufsz, len(decoded))

   # Check decoded content
   var decoded_bytes = decoded.as_bytes()
   for i in range(new_bufsz):
       assert_equal(buf[i], decoded_bytes[i])


fn chunked_per_byte_test(line: Int,
   consume_trailer: Bool,
   encoded: String,
   decoded: String,
   expected: Int
) raises:
   """Test chunked decoding byte by byte."""
   var decoder = PhrChunkedDecoder()
   decoder.consume_trailer = consume_trailer

   var encoded_bytes = encoded.as_bytes()
   var decoded_bytes = decoded.as_bytes()
   var bytes_to_consume = len(encoded) - (expected if expected >= 0 else 0)
   var buf = List[UInt8](capacity=len(encoded) + 1)
   var bytes_ready = 0

   # Feed bytes one at a time
   for i in range(bytes_to_consume - 1):
        buf.unsafe_ptr()[bytes_ready] = encoded_bytes[i]
        buf._len += 1
        var result = phr_decode_chunked(decoder, Span(buf)[bytes_ready:bytes_ready+1])
        var ret = result[0]
        var new_bufsz = result[1]
        if ret != -2:
            assert_false(True, "Unexpected return value during byte-by-byte parsing")
            return
        bytes_ready += new_bufsz

   # Feed the last byte(s)
   for i in range(bytes_to_consume - 1, len(encoded)):
       buf.unsafe_ptr()[bytes_ready + i - (bytes_to_consume - 1)] = encoded_bytes[i]

#    var bufsz = len(encoded) - (bytes_to_consume - 1)
   var result = phr_decode_chunked(decoder, Span(buf)[bytes_ready:bytes_ready + len(encoded) - (bytes_to_consume - 1)])
   var ret = result[0]
   var new_bufsz = result[1]

   assert_equal(ret, expected)
   bytes_ready += new_bufsz
   assert_equal(bytes_ready, len(decoded))

   # Check decoded content
   for i in range(bytes_ready):
       assert_equal(buf[i], decoded_bytes[i])


fn chunked_failure_test(line: Int, encoded: String, expected: Int) raises:
   """Test chunked decoding failure cases."""
   # Test at-once
   var decoder = PhrChunkedDecoder()
   var buf = List[Byte](encoded.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf)
   var ret = result[0]
   assert_equal(ret, expected)

   # Test per-byte
   decoder = PhrChunkedDecoder()
   var encoded_bytes = encoded.as_bytes()
   buf_ptr = InlineArray[UInt8, 1](fill=0)

   for i in range(len(encoded)):
       buf_ptr[0] = encoded_bytes[i]
    #    bufsz = 1
       result = phr_decode_chunked(decoder, buf_ptr)
       ret = result[0]
       if ret == -1:
           assert_equal(ret, expected)
           return
       elif ret == -2:
           continue
       else:
           assert_false(True, "Unexpected success in failure test")
           return

   assert_equal(ret, expected)


fn test_chunked() raises:
   """Test chunked transfer encoding."""
   # Test successful chunked decoding
   chunked_at_once_test(
       0, False,
       String("b\r\nhello world\r\n0\r\n"),
       "hello world", 0
   )
   chunked_per_byte_test(
       0, False,
       String("b\r\nhello world\r\n0\r\n"),
       "hello world", 0
   )

   chunked_at_once_test(
       0, False,
       String("6\r\nhello \r\n5\r\nworld\r\n0\r\n"),
       "hello world", 0
   )
   chunked_per_byte_test(
       0, False,
       String("6\r\nhello \r\n5\r\nworld\r\n0\r\n"),
       "hello world", 0
   )

   chunked_at_once_test(
       0, False,
       String("6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n"),
       "hello world", 0
   )
   chunked_per_byte_test(
       0, False,
       String("6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n"),
       "hello world", 0
   )

   chunked_at_once_test(
       0, False,
       String("6 ; comment\r\nhello \r\n5\r\nworld\r\n0\r\n"),
       "hello world", 0
   )


fn test_chunked_with_trailers() raises:
   # Test with trailers
   chunked_at_once_test(
       0, False,
       String("6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n"),
       "hello world", 14
   )


fn test_chunked_failures() raises:
   # Test failures
   chunked_failure_test(0, "z\r\nabcdefg", -1)
   chunked_failure_test(0, "1x\r\na\r\n0\r\n", -1)


fn test_chunked_failure_line_feed_present() raises:
   # Bare LF cannot be used in chunk header
   chunked_failure_test(0, "6\nhello \r\n5\r\nworld\r\n0\r\n", -1)
   chunked_failure_test(0, "6\r\nhello \n5\r\nworld\r\n0\r\n", -1)
   chunked_failure_test(0, "6\r\nhello \r\n5\r\nworld\n0\r\n", -1)
   chunked_failure_test(0, "6\r\nhello \r\n5\r\nworld\r\n0\n", -1)


fn test_chunked_consume_trailer() raises:
   """Test chunked decoding with consume_trailer flag."""
   chunked_at_once_test(
       0, True,
       "b\r\nhello world\r\n0\r\n",
       "hello world", -2
   )
#    chunked_per_byte_test(
#        0, True,
#        "b\r\nhello world\r\n0\r\n",
#        "hello world", -2
#    )

#    chunked_at_once_test(
#        0, True,
#        "b\r\nhello world\r\n0\r\n\r\n",
#        "hello world", 0
#    )
#    chunked_per_byte_test(
#        0, True,
#        "b\r\nhello world\r\n0\r\n\r\n",
#        "hello world", 0
#    )

#    chunked_at_once_test(
#        0, True,
#        String("6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n"),
#        "hello world", 0
#    )


fn test_chunked_consume_trailer_with_line_feed() raises:
   # Bare LF in trailers
   chunked_at_once_test(
        0, True,
        String("b\r\nhello world\r\n0\r\n\n"),
        "hello world", 0
   )


fn test_chunked_leftdata() raises:
   """Test chunked decoding with leftover data."""
   comptime NEXT_REQ = "GET / HTTP/1.1\r\n\r\n"

   var decoder = PhrChunkedDecoder()
   decoder.consume_trailer = True

   var test_data = String("5\r\nabcde\r\n0\r\n\r\n", NEXT_REQ)
   var buf = List[Byte](test_data.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf)
   var ret = result[0]
   var new_bufsz = result[1]

   assert_true(ret >= 0)
   assert_equal(new_bufsz, 5)

   # Check decoded content
   var expected = "abcde"
   var expected_bytes = expected.as_bytes()
   for i in range(5):
       assert_equal(buf[i], expected_bytes[i])

   # Check leftover data
   assert_equal(ret, len(NEXT_REQ))
   var next_req_bytes = NEXT_REQ.as_bytes()
   for i in range(len(NEXT_REQ)):
       assert_equal(buf[new_bufsz + i], next_req_bytes[i])


fn main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
