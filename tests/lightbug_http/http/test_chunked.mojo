from lightbug_http.http.chunked import HTTPChunkedDecoder, http_decode_chunked
from testing import TestSuite, assert_equal, assert_false, assert_true


fn chunked_at_once_test(line: Int,
   consume_trailer: Bool,
   var encoded: String,
   decoded: String,
   expected: Int
) raises:
   """Test chunked decoding all at once."""
   var decoder = HTTPChunkedDecoder()
   decoder.consume_trailer = consume_trailer

   var buf = List[Byte](encoded.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = http_decode_chunked(decoder, buf)
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
   var decoder = HTTPChunkedDecoder()
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
        var result = http_decode_chunked(decoder, Span(buf)[bytes_ready:bytes_ready+1])
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
   var result = http_decode_chunked(decoder, Span(buf)[bytes_ready:bytes_ready + len(encoded) - (bytes_to_consume - 1)])
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
   var decoder = HTTPChunkedDecoder()
   var buf = List[Byte](encoded.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = http_decode_chunked(decoder, buf)
   var ret = result[0]
   assert_equal(ret, expected)

   # Test per-byte
   decoder = HTTPChunkedDecoder()
   var encoded_bytes = encoded.as_bytes()
   buf_ptr = InlineArray[UInt8, 1](fill=0)

   for i in range(len(encoded)):
       buf_ptr[0] = encoded_bytes[i]
    #    bufsz = 1
       result = http_decode_chunked(decoder, buf_ptr)
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

   var decoder = HTTPChunkedDecoder()
   decoder.consume_trailer = True

   var test_data = String("5\r\nabcde\r\n0\r\n\r\n", NEXT_REQ)
   var buf = List[Byte](test_data.as_bytes())
#    var buf_ptr =  alloc[UInt8](count=len(buf))
#    for i in range(len(buf)):
#        buf_ptr[i] = buf[i]

#    var bufsz = len(buf)
   var result = http_decode_chunked(decoder, buf)
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
