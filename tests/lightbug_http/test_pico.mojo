from lightbug_http.pico import (
    PhrChunkedDecoder,
    PhrHeader,
    phr_decode_chunked,
    phr_parse_headers,
    phr_parse_request,
    phr_parse_response,
)
from testing import assert_equal, assert_false, assert_true


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

fn parse_request_test(
    data: String,
    last_len: Int,
    headers: UnsafePointer[PhrHeader]
) -> ParseRequestResult:
    """Helper to parse request and return results."""
    var result = ParseRequestResult(0, String(), 0, String(), 0, -1, 0)

    var buf = data.as_bytes()
    var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = phr_parse_request(
        buf_ptr,
        len(buf),
        result.method,
        result.method_len,
        result.path,
        result.path_len,
        result.minor_version,
        headers,
        result.num_headers,
        last_len
    )

    buf_ptr.free()
    return result

fn parse_response_test(
    data: String,
    last_len: Int,
    headers: UnsafePointer[PhrHeader]
) -> ParseResponseResult:
    """Helper to parse response and return results."""
    var result = ParseResponseResult(-1, -1, 0, String(), 0, 0)

    var buf = data.as_bytes()
    var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]

    result.num_headers = 4
    result.ret = phr_parse_response(
        buf_ptr,
        len(buf),
        result.minor_version,
        result.status,
        result.msg,
        result.msg_len,
        headers,
        result.num_headers,
        last_len
    )

    buf_ptr.free()
    return result

fn parse_headers_test(
    data: String,
    last_len: Int,
    headers: UnsafePointer[PhrHeader]
) -> ParseHeadersResult:
    """Helper to parse headers and return results."""
    var result = ParseHeadersResult(0, 0)

    var buf = data.as_bytes()
    var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
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
   var headers = UnsafePointer[PhrHeader].alloc(4)

   # Simple request
   var result = parse_request_test("GET / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, 18)
   assert_equal(result.num_headers, 0)
   assert_true(bufis(result.method, "GET"))
   assert_true(bufis(result.path, "/"))
   assert_equal(result.minor_version, 0)

   # Partial request
   result = parse_request_test("GET / HTTP/1.0\r\n\r", 0, headers)
   assert_equal(result.ret, -2)

   # Request with headers
   result = parse_request_test(
       "GET /hoge HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 2)
   assert_true(bufis(result.method, "GET"))
   assert_true(bufis(result.path, "/hoge"))
   assert_equal(result.minor_version, 1)
   assert_true(bufis(headers[0].name, "Host"))
   assert_true(bufis(headers[0].value, "example.com"))
   assert_true(bufis(headers[1].name, "Cookie"))
   assert_true(bufis(headers[1].value, ""))

   # Multiline headers
   result = parse_request_test(
       "GET / HTTP/1.0\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 3)
   assert_true(bufis(result.method, "GET"))
   assert_true(bufis(result.path, "/"))
   assert_equal(result.minor_version, 0)
   assert_true(bufis(headers[0].name, "foo"))
   assert_true(bufis(headers[0].value, ""))
   assert_true(bufis(headers[1].name, "foo"))
   assert_true(bufis(headers[1].value, "b"))
   assert_equal(headers[2].name_len, 0)  # Continuation line has no name
   assert_true(bufis(headers[2].value, "  \tc"))

   # Invalid header name with trailing space
   result = parse_request_test(
       "GET / HTTP/1.0\r\nfoo : ab\r\n\r\n",
       0, headers
   )
   assert_equal(result.ret, -1)

   # Various incomplete requests
   result = parse_request_test("GET", 0, headers)
   assert_equal(result.ret, -2)

   result = parse_request_test("GET ", 0, headers)
   assert_equal(result.ret, -2)
   assert_true(bufis(result.method, "GET"))

   result = parse_request_test("GET /", 0, headers)
   assert_equal(result.ret, -2)

   result = parse_request_test("GET / ", 0, headers)
   assert_equal(result.ret, -2)
   assert_true(bufis(result.path, "/"))

   result = parse_request_test("GET / H", 0, headers)
   assert_equal(result.ret, -2)

   result = parse_request_test("GET / HTTP/1.", 0, headers)
   assert_equal(result.ret, -2)

   result = parse_request_test("GET / HTTP/1.0", 0, headers)
   assert_equal(result.ret, -2)

   result = parse_request_test("GET / HTTP/1.0\r", 0, headers)
   assert_equal(result.ret, -2)
   assert_equal(result.minor_version, 0)

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

   # Multiple spaces between tokens
   result = parse_request_test("GET   /   HTTP/1.0\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)

   # Additional test cases from C version

   # NUL in method
   result = parse_request_test("G\0T / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Tab in method
   result = parse_request_test("G\tT / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Invalid method starting with colon
   result = parse_request_test(":GET / HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # DEL in uri-path
   result = parse_request_test("GET /\x7fhello HTTP/1.0\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Invalid char in header name
   result = parse_request_test("GET / HTTP/1.0\r\n/: 1\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Accept MSB chars
   result = parse_request_test("GET /\xa0 HTTP/1.0\r\nh: c\xa2y\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_equal(result.num_headers, 1)
   assert_true(bufis(result.method, "GET"))
   assert_true(bufis(result.path, "/\xa0"))
   assert_equal(result.minor_version, 0)
   assert_true(bufis(headers[0].name, "h"))
   assert_true(bufis(headers[0].value, "c\xa2y"))

   # Accept |~ (though forbidden by SSE)
   result = parse_request_test("GET / HTTP/1.0\r\n\x7c\x7e: 1\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_equal(result.num_headers, 1)
   assert_true(bufis(headers[0].name, "\x7c\x7e"))
   assert_true(bufis(headers[0].value, "1"))

   # Disallow {
   result = parse_request_test("GET / HTTP/1.0\r\n\x7b: 1\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Exclude leading and trailing spaces in header value
   result = parse_request_test("GET / HTTP/1.0\r\nfoo: a \t \r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_true(bufis(headers[0].value, "a"))

   headers.free()

fn test_response() raises:
   """Test HTTP response parsing."""
   var headers = UnsafePointer[PhrHeader].alloc(4)

   # Simple response
   var result = parse_response_test("HTTP/1.0 200 OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, 19)
   assert_equal(result.num_headers, 0)
   assert_equal(result.status, 200)
   assert_equal(result.minor_version, 0)
   assert_true(bufis(result.msg, "OK"))

   # Partial response
   result = parse_response_test("HTTP/1.0 200 OK\r\n\r", 0, headers)
   assert_equal(result.ret, -2)

   # Response with headers
   result = parse_response_test(
       "HTTP/1.1 200 OK\r\nHost: example.com\r\nCookie: \r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 2)
   assert_equal(result.minor_version, 1)
   assert_equal(result.status, 200)
   assert_true(bufis(result.msg, "OK"))
   assert_true(bufis(headers[0].name, "Host"))
   assert_true(bufis(headers[0].value, "example.com"))
   assert_true(bufis(headers[1].name, "Cookie"))
   assert_true(bufis(headers[1].value, ""))

   # Internal server error
   result = parse_response_test(
       "HTTP/1.0 500 Internal Server Error\r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 0)
   assert_equal(result.minor_version, 0)
   assert_equal(result.status, 500)
   assert_true(bufis(result.msg, "Internal Server Error"))

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

   # Accept missing trailing whitespace in status-line
   result = parse_response_test("HTTP/1.1 200\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_true(bufis(result.msg, ""))

   # Invalid responses
   result = parse_response_test("HTTP/1. 200 OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   result = parse_response_test("HTTP/1.2z 200 OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   result = parse_response_test("HTTP/1.1  OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Garbage after status code
   result = parse_response_test("HTTP/1.1 200X\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   result = parse_response_test("HTTP/1.1 200X \r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   result = parse_response_test("HTTP/1.1 200X OK\r\n\r\n", 0, headers)
   assert_equal(result.ret, -1)

   # Exclude leading and trailing spaces in header value
   result = parse_response_test("HTTP/1.1 200 OK\r\nbar: \t b\t \t\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)
   assert_true(bufis(headers[0].value, "b"))

   # Accept multiple spaces between tokens
   result = parse_response_test("HTTP/1.1   200   OK\r\n\r\n", 0, headers)
   assert_true(result.ret > 0)

   # Multiline headers
   result = parse_response_test(
       "HTTP/1.0 200 OK\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n",
       0, headers
   )
   assert_equal(result.num_headers, 3)
   assert_equal(result.minor_version, 0)
   assert_equal(result.status, 200)
   assert_true(bufis(result.msg, "OK"))
   assert_true(bufis(headers[0].name, "foo"))
   assert_true(bufis(headers[0].value, ""))
   assert_true(bufis(headers[1].name, "foo"))
   assert_true(bufis(headers[1].value, "b"))
   assert_equal(headers[2].name_len, 0)
   assert_true(bufis(headers[2].value, "  \tc"))

   # Slowloris tests
   var test_str = "HTTP/1.0 200 OK\r\n\r"
   result = parse_response_test(test_str, len(test_str) - 1, headers)
   assert_equal(result.ret, -2)

   var test_str_complete = "HTTP/1.0 200 OK\r\n\r\n"
   result = parse_response_test(test_str_complete, len(test_str_complete) - 1, headers)
   assert_true(result.ret > 0)

   headers.free()

fn test_headers() raises:
   """Test header parsing."""
   var headers = UnsafePointer[PhrHeader].alloc(4)

   # Simple headers
   var result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r\n",
       0, headers
   )
   assert_equal(result.ret, 31)
   assert_equal(result.num_headers, 2)
   assert_true(bufis(headers[0].name, "Host"))
   assert_true(bufis(headers[0].value, "example.com"))
   assert_true(bufis(headers[1].name, "Cookie"))
   assert_true(bufis(headers[1].value, ""))

   # Slowloris test
   result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r\n",
       1, headers
   )
   assert_equal(result.num_headers, 2)
   assert_true(result.ret > 0)

   # Partial headers
   result = parse_headers_test(
       "Host: example.com\r\nCookie: \r\n\r",
       0, headers
   )
   assert_equal(result.ret, -2)

   headers.free()

fn test_chunked_at_once(line: Int,
   consume_trailer: Bool,
   encoded: String,
   decoded: String,
   expected: Int
) raises:
   """Test chunked decoding all at once."""
   var decoder = PhrChunkedDecoder()
   decoder.consume_trailer = consume_trailer

   var buf = encoded.as_bytes()
   var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
   for i in range(len(buf)):
       buf_ptr[i] = buf[i]

   var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf_ptr, bufsz)
   var ret = result[0]
   var new_bufsz = result[1]

   assert_equal(ret, expected)
   assert_equal(new_bufsz, len(decoded))

   # Check decoded content
   var decoded_bytes = decoded.as_bytes()
   for i in range(new_bufsz):
       assert_equal(buf_ptr[i], decoded_bytes[i])

   buf_ptr.free()

fn test_chunked_per_byte(line: Int,
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
   var buf = UnsafePointer[UInt8].alloc(len(encoded) + 1)
   var bytes_ready = 0

   # Feed bytes one at a time
   for i in range(bytes_to_consume - 1):
       buf[bytes_ready] = encoded_bytes[i]
       var bufsz = 1
       var result = phr_decode_chunked(decoder, buf + bytes_ready, bufsz)
       var ret = result[0]
       var new_bufsz = result[1]
       if ret != -2:
           assert_false(True, "Unexpected return value during byte-by-byte parsing")
           buf.free()
           return
       bytes_ready += new_bufsz

   # Feed the last byte(s)
   for i in range(bytes_to_consume - 1, len(encoded)):
       buf[bytes_ready + i - (bytes_to_consume - 1)] = encoded_bytes[i]

   var bufsz = len(encoded) - (bytes_to_consume - 1)
   var result = phr_decode_chunked(decoder, buf + bytes_ready, bufsz)
   var ret = result[0]
   var new_bufsz = result[1]

   assert_equal(ret, expected)
   bytes_ready += new_bufsz
   assert_equal(bytes_ready, len(decoded))

   # Check decoded content
   for i in range(bytes_ready):
       assert_equal(buf[i], decoded_bytes[i])

   buf.free()

fn test_chunked_failure(line: Int, encoded: String, expected: Int) raises:
   """Test chunked decoding failure cases."""
   # Test at-once
   var decoder = PhrChunkedDecoder()
   var buf = encoded.as_bytes()
   var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
   for i in range(len(buf)):
       buf_ptr[i] = buf[i]

   var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf_ptr, bufsz)
   var ret = result[0]
   assert_equal(ret, expected)
   buf_ptr.free()

   # Test per-byte
   decoder = PhrChunkedDecoder()
   var encoded_bytes = encoded.as_bytes()
   buf_ptr = UnsafePointer[UInt8].alloc(1)

   for i in range(len(encoded)):
       buf_ptr[0] = encoded_bytes[i]
       bufsz = 1
       result = phr_decode_chunked(decoder, buf_ptr, bufsz)
       ret = result[0]
       if ret == -1:
           assert_equal(ret, expected)
           buf_ptr.free()
           return
       elif ret == -2:
           continue
       else:
           assert_false(True, "Unexpected success in failure test")
           buf_ptr.free()
           return

   assert_equal(ret, expected)
   buf_ptr.free()

fn test_chunked() raises:
   """Test chunked transfer encoding."""
   # Test successful chunked decoding
   test_chunked_at_once(
       0, False,
       "b\r\nhello world\r\n0\r\n",
       "hello world", 0
   )
   test_chunked_per_byte(
       0, False,
       "b\r\nhello world\r\n0\r\n",
       "hello world", 0
   )

   test_chunked_at_once(
       0, False,
       "6\r\nhello \r\n5\r\nworld\r\n0\r\n",
       "hello world", 0
   )
   test_chunked_per_byte(
       0, False,
       "6\r\nhello \r\n5\r\nworld\r\n0\r\n",
       "hello world", 0
   )

   test_chunked_at_once(
       0, False,
       "6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n",
       "hello world", 0
   )
   test_chunked_per_byte(
       0, False,
       "6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n",
       "hello world", 0
   )

   test_chunked_at_once(
       0, False,
       "6 ; comment\r\nhello \r\n5\r\nworld\r\n0\r\n",
       "hello world", 0
   )

   # Test with trailers
   test_chunked_at_once(
       0, False,
       "6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n",
       "hello world", 14
   )

   # Test failures
   test_chunked_failure(0, "z\r\nabcdefg", -1)
   test_chunked_failure(0, "1x\r\na\r\n0\r\n", -1)

   # Bare LF cannot be used in chunk header
   test_chunked_failure(0, "6\nhello \r\n5\r\nworld\r\n0\r\n", -1)
   test_chunked_failure(0, "6\r\nhello \n5\r\nworld\r\n0\r\n", -1)
   test_chunked_failure(0, "6\r\nhello \r\n5\r\nworld\n0\r\n", -1)
   test_chunked_failure(0, "6\r\nhello \r\n5\r\nworld\r\n0\n", -1)

fn test_chunked_consume_trailer() raises:
   """Test chunked decoding with consume_trailer flag."""
   test_chunked_at_once(
       0, True,
       "b\r\nhello world\r\n0\r\n",
       "hello world", -2
   )
   test_chunked_per_byte(
       0, True,
       "b\r\nhello world\r\n0\r\n",
       "hello world", -2
   )

   test_chunked_at_once(
       0, True,
       "b\r\nhello world\r\n0\r\n\r\n",
       "hello world", 0
   )
   test_chunked_per_byte(
       0, True,
       "b\r\nhello world\r\n0\r\n\r\n",
       "hello world", 0
   )

   test_chunked_at_once(
       0, True,
       "6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n",
       "hello world", 0
   )

   # Bare LF in trailers
   test_chunked_at_once(
       0, True,
       "b\r\nhello world\r\n0\r\n\n",
       "hello world", 0
   )

fn test_chunked_leftdata() raises:
   """Test chunked decoding with leftover data."""
   alias NEXT_REQ = "GET / HTTP/1.1\r\n\r\n"

   var decoder = PhrChunkedDecoder()
   decoder.consume_trailer = True

   var test_data = "5\r\nabcde\r\n0\r\n\r\n" + NEXT_REQ
   var buf = test_data.as_bytes()
   var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
   for i in range(len(buf)):
       buf_ptr[i] = buf[i]

   var bufsz = len(buf)
   var result = phr_decode_chunked(decoder, buf_ptr, bufsz)
   var ret = result[0]
   var new_bufsz = result[1]

   assert_true(ret >= 0)
   assert_equal(new_bufsz, 5)

   # Check decoded content
   var expected = "abcde"
   var expected_bytes = expected.as_bytes()
   for i in range(5):
       assert_equal(buf_ptr[i], expected_bytes[i])

   # Check leftover data
   assert_equal(ret, len(NEXT_REQ))
   var next_req_bytes = NEXT_REQ.as_bytes()
   for i in range(len(NEXT_REQ)):
       assert_equal(buf_ptr[new_bufsz + i], next_req_bytes[i])

   buf_ptr.free()

fn run_tests():
   """Run all tests."""
   print("Running picohttpparser tests...")

   try:
       test_request()
       test_response()
       test_headers()
       test_chunked()
       test_chunked_consume_trailer()
       test_chunked_leftdata()
       print("All tests passed!")
   except e:
       print("Test failed:", e)
