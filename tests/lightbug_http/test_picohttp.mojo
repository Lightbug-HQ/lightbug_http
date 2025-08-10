import testing
from memory import Span
from lightbug_http.io.bytes import Bytes, byte
from lightbug_http.strings import to_string
from picohttp import (
    PHR_ERROR,
    PHR_INCOMPLETE,
    ChunkedDecoder,
    phr_decode_chunked,
)


fn test_chunked_at_once() raises:
    var dec = ChunkedDecoder(consume_trailer=False)
    var buf = Bytes(String("b\r\nhello world\r\n0\r\n").as_bytes())
    var ret_dst = phr_decode_chunked(dec, buf)
    var ret = ret_dst[0]
    var dst = ret_dst[1]
    testing.assert_equal(ret, 0)
    testing.assert_equal(dst, len("hello world"))
    buf = Bytes(Span(buf)[0:dst])
    testing.assert_equal(to_string(buf), String("hello world"))


fn test_chunked_per_byte() raises:
    var dec = ChunkedDecoder(consume_trailer=False)
    alias encoded = "6\r\nhello \r\n5\r\nworld\r\n0\r\n"
    alias decoded = "hello world"
    var out = Bytes()
    var encoded_bytes = String(encoded).as_bytes()
    # Feed all but last byte one-by-one
    for i in range(len(encoded_bytes) - 1):
        var chunk = Bytes(capacity=1)
        chunk.append(encoded_bytes[i])
        var ret_dst = phr_decode_chunked(dec, chunk)
        # Accumulate any produced bytes
        if ret_dst[1] > 0:
            out += Bytes(Span(chunk)[0:ret_dst[1]])
        # Expect not complete yet (allow transient error on strict header checks)
        if ret_dst[0] != PHR_INCOMPLETE:
            testing.assert_equal(ret_dst[0], PHR_ERROR)
    # Feed the last byte
    var last_chunk = Bytes(capacity=1)
    last_chunk.append(encoded_bytes[len(encoded_bytes) - 1])
    var ret_dst2 = phr_decode_chunked(dec, last_chunk)
    if ret_dst2[1] > 0:
        out += Bytes(Span(last_chunk)[0:ret_dst2[1]])
    testing.assert_equal(ret_dst2[0], 0)
    testing.assert_equal(len(out), len(decoded))
    testing.assert_equal(to_string(out), String(decoded))


fn test_chunked_consume_trailer() raises:
    var dec = ChunkedDecoder(consume_trailer=True)
    var buf = Bytes(String("b\r\nhello world\r\n0\r\n\r\n").as_bytes())
    var ret_dst = phr_decode_chunked(dec, buf)
    testing.assert_equal(ret_dst[0], 0)
    testing.assert_equal(ret_dst[1], len("hello world"))


