import sys
from sys import size_of

from lightbug_http.io.bytes import Bytes, memmove
from lightbug_http.strings import BytesConstant
from memory import memcpy


# Chunked decoder states
comptime CHUNKED_IN_CHUNK_SIZE = 0
comptime CHUNKED_IN_CHUNK_EXT = 1
comptime CHUNKED_IN_CHUNK_HEADER_EXPECT_LF = 2
comptime CHUNKED_IN_CHUNK_DATA = 3
comptime CHUNKED_IN_CHUNK_DATA_EXPECT_CR = 4
comptime CHUNKED_IN_CHUNK_DATA_EXPECT_LF = 5
comptime CHUNKED_IN_TRAILERS_LINE_HEAD = 6
comptime CHUNKED_IN_TRAILERS_LINE_MIDDLE = 7


struct HTTPChunkedDecoder:
    var bytes_left_in_chunk: Int
    var consume_trailer: Bool
    var _hex_count: Int
    var _state: Int
    var _total_read: Int
    var _total_overhead: Int

    fn __init__(out self):
        self.bytes_left_in_chunk = 0
        self.consume_trailer = False
        self._hex_count = 0
        self._state = CHUNKED_IN_CHUNK_SIZE
        self._total_read = 0
        self._total_overhead = 0

fn decode_hex(ch: UInt8) -> Int:
    """Decode hexadecimal character."""
    if ch >= BytesConstant.ZERO and ch <= BytesConstant.NINE:
        return Int(ch - BytesConstant.ZERO)
    elif ch >= BytesConstant.A_UPPER and ch <= BytesConstant.F_UPPER:
        return Int(ch - BytesConstant.A_UPPER + 10)
    elif ch >= BytesConstant.A_LOWER and ch <= BytesConstant.F_LOWER:
        return Int(ch - BytesConstant.A_LOWER + 10)
    else:
        return -1


fn http_decode_chunked[
    buf_origin: MutOrigin
](mut decoder: HTTPChunkedDecoder, buf: Span[UInt8, buf_origin]) -> Tuple[Int, Int]:
    """Decode chunked transfer encoding.

    Returns (ret, new_bufsz) where:
    - ret: number of bytes left after chunked data, -1 for error, -2 for incomplete
    - new_bufsz: the new buffer size (decoded data length)
    """
    var dst = 0
    var src = 0
    var ret = -2  # incomplete
    var buffer_len = len(buf)

    decoder._total_read += buffer_len

    while True:
        if decoder._state == CHUNKED_IN_CHUNK_SIZE:
            while src < buffer_len:
                var v = decode_hex(buf[src])
                if v == -1:
                    if decoder._hex_count == 0:
                        return (-1, dst)
                    # Check for valid characters after chunk size
                    var c = buf[src]
                    if (
                        c != BytesConstant.whitespace
                        and c != BytesConstant.TAB
                        and c != BytesConstant.SEMICOLON
                        and c != BytesConstant.LF
                        and c != BytesConstant.CR
                    ):
                        return (-1, dst)
                    break

                if decoder._hex_count == 16:  # size_of(size_t) * 2
                    return (-1, dst)

                decoder.bytes_left_in_chunk = decoder.bytes_left_in_chunk * 16 + v
                decoder._hex_count += 1
                src += 1

            if src >= buffer_len:
                break

            decoder._hex_count = 0
            decoder._state = CHUNKED_IN_CHUNK_EXT

        elif decoder._state == CHUNKED_IN_CHUNK_EXT:
            while src < buffer_len:
                if buf[src] == BytesConstant.CR:
                    break
                elif buf[src] == BytesConstant.LF:
                    return (-1, dst)
                src += 1

            if src >= buffer_len:
                break

            src += 1
            decoder._state = CHUNKED_IN_CHUNK_HEADER_EXPECT_LF

        elif decoder._state == CHUNKED_IN_CHUNK_HEADER_EXPECT_LF:
            if src >= buffer_len:
                break

            if buf[src] != BytesConstant.LF:
                return (-1, dst)

            src += 1

            if decoder.bytes_left_in_chunk == 0:
                if decoder.consume_trailer:
                    decoder._state = CHUNKED_IN_TRAILERS_LINE_HEAD
                    continue
                else:
                    ret = buffer_len - src
                    break

            decoder._state = CHUNKED_IN_CHUNK_DATA

        elif decoder._state == CHUNKED_IN_CHUNK_DATA:
            var avail = buffer_len - src
            if avail < decoder.bytes_left_in_chunk:
                if dst != src:
                    memmove(buf.unsafe_ptr() + dst, buf.unsafe_ptr() + src, avail)
                src += avail
                dst += avail
                decoder.bytes_left_in_chunk -= avail
                break

            if dst != src:
                memmove(buf.unsafe_ptr() + dst, buf.unsafe_ptr() + src, decoder.bytes_left_in_chunk)

            src += decoder.bytes_left_in_chunk
            dst += decoder.bytes_left_in_chunk
            decoder.bytes_left_in_chunk = 0
            decoder._state = CHUNKED_IN_CHUNK_DATA_EXPECT_CR

        elif decoder._state == CHUNKED_IN_CHUNK_DATA_EXPECT_CR:
            if src >= len(buf):
                break

            if buf[src] != BytesConstant.CR:
                return (-1, dst)

            src += 1
            decoder._state = CHUNKED_IN_CHUNK_DATA_EXPECT_LF

        elif decoder._state == CHUNKED_IN_CHUNK_DATA_EXPECT_LF:
            if src >= buffer_len:
                break

            if buf[src] != BytesConstant.LF:
                return (-1, dst)

            src += 1
            decoder._state = CHUNKED_IN_CHUNK_SIZE

        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_HEAD:
            while src < buffer_len:
                if buf[src] != BytesConstant.CR:
                    break
                src += 1

            if src >= buffer_len:
                break

            if buf[src] == BytesConstant.LF:
                src += 1
                ret = buffer_len - src
                break

            decoder._state = CHUNKED_IN_TRAILERS_LINE_MIDDLE

        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_MIDDLE:
            while src < buffer_len:
                if buf[src] == BytesConstant.LF:
                    break
                src += 1

            if src >= buffer_len:
                break

            src += 1
            decoder._state = CHUNKED_IN_TRAILERS_LINE_HEAD

    # Move remaining data to beginning of buffer
    if dst != src and src < buffer_len:
        memmove(buf.unsafe_ptr() + dst, buf.unsafe_ptr() + src, buffer_len - src)

    var new_bufsz = dst

    # Check for excessive overhead
    if ret == -2:
        decoder._total_overhead += buffer_len - dst
        if (
            decoder._total_overhead >= 100 * 1024
            and decoder._total_read - decoder._total_overhead < decoder._total_read // 4
        ):
            ret = -1

    return (ret, new_bufsz)


fn http_decode_chunked_is_in_data(decoder: HTTPChunkedDecoder) -> Bool:
    """Check if decoder is currently in chunk data state."""
    return decoder._state == CHUNKED_IN_CHUNK_DATA

