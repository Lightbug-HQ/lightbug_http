from memory import Span
from lightbug_http.io.bytes import Bytes, byte

alias PHR_ERROR = -1
alias PHR_INCOMPLETE = -2


struct ChunkState:
    alias CHUNKED_IN_CHUNK_SIZE = 0
    alias CHUNKED_IN_CHUNK_EXT = 1
    alias CHUNKED_IN_CHUNK_HEADER_EXPECT_LF = 2
    alias CHUNKED_IN_CHUNK_DATA = 3
    alias CHUNKED_IN_CHUNK_DATA_EXPECT_CR = 4
    alias CHUNKED_IN_CHUNK_DATA_EXPECT_LF = 5
    alias CHUNKED_IN_TRAILERS_LINE_HEAD = 6
    alias CHUNKED_IN_TRAILERS_LINE_MIDDLE = 7


@fieldwise_init
struct ChunkedDecoder(Copyable, Movable):
    var consume_trailer: Bool
    var bytes_left_in_chunk: Int
    var _state: Int
    var _hex_count: Int
    var _total_read: Int
    var _total_overhead: Int

    fn __init__(out self, consume_trailer: Bool = True):
        self.consume_trailer = consume_trailer
        self.bytes_left_in_chunk = 0
        self._state = ChunkState.CHUNKED_IN_CHUNK_SIZE
        self._hex_count = 0
        self._total_read = 0
        self._total_overhead = 0


@always_inline
fn hex_value(b: Byte) -> Int:
    if b >= byte("0") and b <= byte("9"):
        return Int(b - byte("0"))
    if b >= byte("A") and b <= byte("F"):
        return 10 + Int(b - byte("A"))
    if b >= byte("a") and b <= byte("f"):
        return 10 + Int(b - byte("a"))
    return -1


fn phr_decode_chunked_is_in_data(decoder: ChunkedDecoder) -> Int:
    if decoder._state == ChunkState.CHUNKED_IN_CHUNK_DATA:
        return 1
    return 0


fn phr_decode_chunked(mut decoder: ChunkedDecoder, mut buf: Bytes) -> (Int, Int):
    var dst = 0
    var src = 0
    var bufsz = len(buf)
    var ret: Int = PHR_INCOMPLETE
    var need_exit = False
    var completed = False

    decoder._total_read += bufsz

    while not need_exit and not completed:
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_SIZE:
            while True:
                if src == bufsz:
                    need_exit = True
                    break
                var v = hex_value(buf[src])
                if v == -1:
                    if decoder._hex_count == 0:
                        ret = PHR_ERROR
                        need_exit = True
                        break
                    var ch = buf[src]
                    if not (ch == byte(" ") or ch == 0x09 or ch == byte(";") or ch == 0x0A or ch == 0x0D):
                        ret = PHR_ERROR
                        need_exit = True
                        break
                    break
                if decoder._hex_count >= 16:
                    ret = PHR_ERROR
                    need_exit = True
                    break
                decoder.bytes_left_in_chunk = decoder.bytes_left_in_chunk * 16 + v
                decoder._hex_count += 1
                src += 1
            if need_exit:
                break
            decoder._hex_count = 0
            decoder._state = ChunkState.CHUNKED_IN_CHUNK_EXT
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_EXT and not need_exit and not completed:
            while True:
                if src == bufsz:
                    need_exit = True
                    break
                if buf[src] == 0x0D:
                    break
                elif buf[src] == 0x0A:
                    ret = PHR_ERROR
                    need_exit = True
                    break
                src += 1
            if need_exit:
                break
            src += 1
            decoder._state = ChunkState.CHUNKED_IN_CHUNK_HEADER_EXPECT_LF
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_HEADER_EXPECT_LF and not need_exit and not completed:
            if src == bufsz:
                need_exit = True
                break
            if buf[src] != 0x0A:
                ret = PHR_ERROR
                need_exit = True
                break
            src += 1
            if decoder.bytes_left_in_chunk == 0:
                if decoder.consume_trailer:
                    decoder._state = ChunkState.CHUNKED_IN_TRAILERS_LINE_HEAD
                else:
                    completed = True
            else:
                decoder._state = ChunkState.CHUNKED_IN_CHUNK_DATA
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_DATA and not need_exit and not completed:
            var avail = bufsz - src
            if avail < decoder.bytes_left_in_chunk:
                var k = 0
                while k < avail:
                    buf[dst] = buf[src]
                    dst += 1
                    src += 1
                    k += 1
                decoder.bytes_left_in_chunk -= avail
                need_exit = True
                break
            var k2 = 0
            while k2 < decoder.bytes_left_in_chunk:
                buf[dst] = buf[src]
                dst += 1
                src += 1
                k2 += 1
            decoder.bytes_left_in_chunk = 0
            decoder._state = ChunkState.CHUNKED_IN_CHUNK_DATA_EXPECT_CR
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_DATA_EXPECT_CR and not need_exit and not completed:
            if src == bufsz:
                need_exit = True
                break
            if buf[src] != 0x0D:
                ret = PHR_ERROR
                need_exit = True
                break
            src += 1
            decoder._state = ChunkState.CHUNKED_IN_CHUNK_DATA_EXPECT_LF
        if decoder._state == ChunkState.CHUNKED_IN_CHUNK_DATA_EXPECT_LF and not need_exit and not completed:
            if src == bufsz:
                need_exit = True
                break
            if buf[src] != 0x0A:
                ret = PHR_ERROR
                need_exit = True
                break
            src += 1
            decoder._state = ChunkState.CHUNKED_IN_CHUNK_SIZE
        if decoder._state == ChunkState.CHUNKED_IN_TRAILERS_LINE_HEAD and not need_exit and not completed:
            while True:
                if src == bufsz:
                    need_exit = True
                    break
                if buf[src] != 0x0D:
                    break
                src += 1
            if need_exit:
                break
            if buf[src] == 0x0A:
                src += 1
                completed = True
            else:
                decoder._state = ChunkState.CHUNKED_IN_TRAILERS_LINE_MIDDLE
        if decoder._state == ChunkState.CHUNKED_IN_TRAILERS_LINE_MIDDLE and not need_exit and not completed:
            while True:
                if src == bufsz:
                    need_exit = True
                    break
                if buf[src] == 0x0A:
                    break
                src += 1
            if need_exit:
                break
            src += 1
            decoder._state = ChunkState.CHUNKED_IN_TRAILERS_LINE_HEAD

    if completed:
        ret = bufsz - src
    if dst < len(buf):
        buf = Bytes(Span(buf)[0:dst])
    if ret == PHR_INCOMPLETE:
        decoder._total_overhead += bufsz - dst
        if decoder._total_overhead >= 100 * 1024 and (decoder._total_read - decoder._total_overhead) < Int(decoder._total_read / 4):
            ret = PHR_ERROR
    return (ret, dst)


