import sys
from sys import size_of

from lightbug_http.io.bytes import Bytes, memmove
from lightbug_http.strings import BytesConstant
from memory import memcpy


# Chunked decoder states
@fieldwise_init
struct DecoderState(Equatable, ImplicitlyCopyable):
    var value: UInt8
    comptime IN_CHUNK_SIZE = Self(0)
    comptime IN_CHUNK_EXT = Self(1)
    comptime IN_CHUNK_HEADER_EXPECT_LF = Self(2)
    comptime IN_CHUNK_DATA = Self(3)
    comptime IN_CHUNK_DATA_EXPECT_CR = Self(4)
    comptime IN_CHUNK_DATA_EXPECT_LF = Self(5)
    comptime IN_TRAILERS_LINE_HEAD = Self(6)
    comptime IN_TRAILERS_LINE_MIDDLE = Self(7)

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value


struct HTTPChunkedDecoder(Defaultable):
    var bytes_left_in_chunk: Int
    var consume_trailer: Bool
    var _hex_count: Int
    var _state: DecoderState
    var _total_read: Int
    var _total_overhead: Int

    fn __init__(out self):
        self.bytes_left_in_chunk = 0
        self.consume_trailer = False
        self._hex_count = 0
        self._state = DecoderState.IN_CHUNK_SIZE
        self._total_read = 0
        self._total_overhead = 0

    fn decode[origin: MutOrigin](mut self, buf: Span[Byte, origin]) -> Tuple[Int, Int]:
        """Decode chunked transfer encoding.

        Parameters:
            origin: Origin of the buffer, must be mutable.

        Args:
            buf: The buffer containing chunked data.

        Returns:
            The number of bytes left after chunked data, -1 for error, -2 for incomplete
            The new buffer size (decoded data length).
        """
        var dst = 0
        var src = 0
        var ret = -2  # incomplete
        var buffer_len = len(buf)

        self._total_read += buffer_len

        while True:
            if self._state == DecoderState.IN_CHUNK_SIZE:
                while src < buffer_len:
                    ref byte = buf[src]
                    var v = decode_hex(byte)
                    if v == -1:
                        if self._hex_count == 0:
                            return (-1, dst)

                        # Check for valid characters after chunk size
                        if (
                            byte != BytesConstant.whitespace
                            and byte != BytesConstant.TAB
                            and byte != BytesConstant.SEMICOLON
                            and byte != BytesConstant.LF
                            and byte != BytesConstant.CR
                        ):
                            return (-1, dst)
                        break

                    if self._hex_count == 16:  # size_of(size_t) * 2
                        return (-1, dst)

                    self.bytes_left_in_chunk = self.bytes_left_in_chunk * 16 + v
                    self._hex_count += 1
                    src += 1

                if src >= buffer_len:
                    break

                self._hex_count = 0
                self._state = DecoderState.IN_CHUNK_EXT

            elif self._state == DecoderState.IN_CHUNK_EXT:
                ref byte = buf[src]
                while src < buffer_len:
                    if byte == BytesConstant.CR:
                        break
                    elif byte == BytesConstant.LF:
                        return (-1, dst)
                    src += 1

                if src >= buffer_len:
                    break

                src += 1
                self._state = DecoderState.IN_CHUNK_HEADER_EXPECT_LF

            elif self._state == DecoderState.IN_CHUNK_HEADER_EXPECT_LF:
                if src >= buffer_len:
                    break

                if buf[src] != BytesConstant.LF:
                    return (-1, dst)

                src += 1

                if self.bytes_left_in_chunk == 0:
                    if self.consume_trailer:
                        self._state = DecoderState.IN_TRAILERS_LINE_HEAD
                        continue
                    else:
                        ret = buffer_len - src
                        break

                self._state = DecoderState.IN_CHUNK_DATA

            elif self._state == DecoderState.IN_CHUNK_DATA:
                var avail = buffer_len - src
                if avail < self.bytes_left_in_chunk:
                    if dst != src:
                        memmove(buf.unsafe_ptr() + dst, buf.unsafe_ptr() + src, avail)
                    src += avail
                    dst += avail
                    self.bytes_left_in_chunk -= avail
                    break

                if dst != src:
                    memmove(
                        buf.unsafe_ptr() + dst,
                        buf.unsafe_ptr() + src,
                        self.bytes_left_in_chunk,
                    )

                src += self.bytes_left_in_chunk
                dst += self.bytes_left_in_chunk
                self.bytes_left_in_chunk = 0
                self._state = DecoderState.IN_CHUNK_DATA_EXPECT_CR

            elif self._state == DecoderState.IN_CHUNK_DATA_EXPECT_CR:
                if src >= len(buf):
                    break

                if buf[src] != BytesConstant.CR:
                    return (-1, dst)

                src += 1
                self._state = DecoderState.IN_CHUNK_DATA_EXPECT_LF

            elif self._state == DecoderState.IN_CHUNK_DATA_EXPECT_LF:
                if src >= buffer_len:
                    break

                if buf[src] != BytesConstant.LF:
                    return (-1, dst)

                src += 1
                self._state = DecoderState.IN_CHUNK_SIZE

            elif self._state == DecoderState.IN_TRAILERS_LINE_HEAD:
                ref byte = buf[src]
                while src < buffer_len:
                    if byte != BytesConstant.CR:
                        break
                    src += 1

                if src >= buffer_len:
                    break

                if byte == BytesConstant.LF:
                    src += 1
                    ret = buffer_len - src
                    break

                self._state = DecoderState.IN_TRAILERS_LINE_MIDDLE

            elif self._state == DecoderState.IN_TRAILERS_LINE_MIDDLE:
                while src < buffer_len:
                    if buf[src] == BytesConstant.LF:
                        break
                    src += 1

                if src >= buffer_len:
                    break

                src += 1
                self._state = DecoderState.IN_TRAILERS_LINE_HEAD

        # Move remaining data to beginning of buffer
        if dst != src and src < buffer_len:
            memmove(buf.unsafe_ptr() + dst, buf.unsafe_ptr() + src, buffer_len - src)

        var new_bufsz = dst

        # Check for excessive overhead
        if ret == -2:
            self._total_overhead += buffer_len - dst
            if self._total_overhead >= 100 * 1024 and self._total_read - self._total_overhead < self._total_read // 4:
                ret = -1

        return (ret, new_bufsz)

    fn is_in_chunk_data(self) -> Bool:
        """Check if decoder is currently in chunk data state."""
        return self._state == DecoderState.IN_CHUNK_DATA


fn decode_hex(ch: Byte) -> Int:
    """Decode hexadecimal character."""
    if ch >= BytesConstant.ZERO and ch <= BytesConstant.NINE:
        return Int(ch - BytesConstant.ZERO)
    elif ch >= BytesConstant.A_UPPER and ch <= BytesConstant.F_UPPER:
        return Int(ch - BytesConstant.A_UPPER + 10)
    elif ch >= BytesConstant.A_LOWER and ch <= BytesConstant.F_LOWER:
        return Int(ch - BytesConstant.A_LOWER + 10)
    else:
        return -1
