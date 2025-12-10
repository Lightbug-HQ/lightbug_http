import math
import sys
from sys import size_of

from lightbug_http.io.bytes import byte
from lightbug_http.strings import BytesConstant
from memory import memcpy


# Constants
alias IS_PRINTABLE_ASCII_MASK = 0o137


# Token character map - represents which characters are valid in tokens
# According to RFC 7230: token = 1*tchar
# tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
#         "0"-"9" / "A"-"Z" / "^" / "_" / "`" / "a"-"z" / "|" / "~"
@always_inline
fn is_token_char(c: UInt8) -> Bool:
    """Check if character is a valid token character.

    Optimized to be inlined and extremely fast - compiles to simple range checks.
    """
    # Alphanumeric ranges
    if c >= BytesConstant.ZERO and c <= BytesConstant.NINE:  # 0-9
        return True
    if c >= BytesConstant.A_UPPER and c <= BytesConstant.Z_UPPER:  # A-Z
        return True
    if c >= BytesConstant.A_LOWER and c <= BytesConstant.Z_LOWER:  # a-z
        return True

    # Special characters allowed in tokens (ordered by ASCII value for branch prediction)
    # !  #  $  %  &  '  *  +  -  .  ^  _  `  |  ~
    return (
        c == BytesConstant.EXCLAMATION
        or c == BytesConstant.POUND
        or c == BytesConstant.DOLLAR
        or c == BytesConstant.PERCENT
        or c == BytesConstant.AMPERSAND
        or c == BytesConstant.APOSTROPHE
        or c == BytesConstant.ASTERISK
        or c == BytesConstant.PLUS
        or c == BytesConstant.HYPHEN
        or c == BytesConstant.DOT
        or c == BytesConstant.CARET
        or c == BytesConstant.UNDERSCORE
        or c == BytesConstant.BACKTICK
        or c == BytesConstant.PIPE
        or c == BytesConstant.TILDE
    )


# Chunked decoder states
alias CHUNKED_IN_CHUNK_SIZE = 0
alias CHUNKED_IN_CHUNK_EXT = 1
alias CHUNKED_IN_CHUNK_HEADER_EXPECT_LF = 2
alias CHUNKED_IN_CHUNK_DATA = 3
alias CHUNKED_IN_CHUNK_DATA_EXPECT_CR = 4
alias CHUNKED_IN_CHUNK_DATA_EXPECT_LF = 5
alias CHUNKED_IN_TRAILERS_LINE_HEAD = 6
alias CHUNKED_IN_TRAILERS_LINE_MIDDLE = 7


struct PhrHeader(Copyable):
    var name: String
    var name_len: Int
    var value: String
    var value_len: Int

    fn __init__(out self):
        self.name = String()
        self.name_len = 0
        self.value = String()
        self.value_len = 0


struct PhrChunkedDecoder:
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


fn is_printable_ascii(c: UInt8) -> Bool:
    return (c - 0x20) < IS_PRINTABLE_ASCII_MASK


fn get_token_to_eol[
    origin: ImmutOrigin
](
    buf: UnsafePointer[UInt8, origin],
    buf_end: UnsafePointer[UInt8, origin],
    mut token: String,
    mut token_len: Int,
    mut ret: Int,
) -> UnsafePointer[UInt8, origin]:
    """Get token up to end of line."""
    var token_start = buf
    var current = buf

    # Find non-printable character
    while current < buf_end:
        if not is_printable_ascii(current[]):
            var c = current[]
            if (c < 0x20 and c != 0x09) or c == 0x7F:
                break
        current += 1

    if current >= buf_end:
        ret = -2
        return UnsafePointer[UInt8, origin]()

    if current[] == BytesConstant.CR:  # '\r'
        current += 1
        if current >= buf_end or current[] != BytesConstant.LF:  # '\n'
            ret = -1
            return UnsafePointer[UInt8, origin]()
        token_len = Int(current) - 1 - Int(token_start)
        current += 1
    elif current[] == BytesConstant.LF:  # '\n'
        token_len = Int(current) - Int(token_start)
        current += 1
    else:
        ret = -1
        return UnsafePointer[UInt8, origin]()

    token = create_string_from_ptr(token_start, token_len)
    return current


fn is_complete[
    origin: ImmutOrigin
](
    buf: UnsafePointer[UInt8, origin], buf_end: UnsafePointer[UInt8, origin], last_len: Int, mut ret: Int
) -> UnsafePointer[UInt8, origin]:
    """Check if request/response is complete."""
    var ret_cnt = 0
    var current = buf if last_len < 3 else buf + last_len - 3

    while current < buf_end:
        if current[] == BytesConstant.CR:  # '\r'
            current += 1
            if current >= buf_end:
                ret = -2
                return UnsafePointer[UInt8, origin]()
            if current[] != BytesConstant.LF:  # '\n'
                ret = -1
                return UnsafePointer[UInt8, origin]()
            current += 1
            ret_cnt += 1
        elif current[] == BytesConstant.LF:  # '\n'
            current += 1
            ret_cnt += 1
        else:
            ret_cnt = 0
            current += 1

        if ret_cnt == 2:
            return current

    ret = -2
    return UnsafePointer[UInt8, origin]()


fn parse_token[
    origin: ImmutOrigin
](
    buf: UnsafePointer[UInt8, origin],
    buf_end: UnsafePointer[UInt8, origin],
    mut token: String,
    mut token_len: Int,
    next_char: UInt8,
    mut ret: Int,
) -> UnsafePointer[UInt8, origin]:
    """Parse a token until next_char is found."""
    var buf_start = buf
    var current = buf

    while current < buf_end:
        if current[] == next_char:
            token_len = Int(current) - Int(buf_start)
            token = create_string_from_ptr(buf_start, token_len)
            return current
        elif not is_token_char(current[]):
            ret = -1
            return UnsafePointer[UInt8, origin]()
        current += 1

    ret = -2
    return UnsafePointer[UInt8, origin]()


fn parse_http_version[
    origin: ImmutOrigin
](
    buf: UnsafePointer[UInt8, origin], buf_end: UnsafePointer[UInt8, origin], mut minor_version: Int, mut ret: Int
) -> UnsafePointer[UInt8, origin]:
    """Parse HTTP version."""
    if Int(buf_end) - Int(buf) < 9:
        ret = -2
        return UnsafePointer[UInt8, origin]()

    var current = buf
    # Check "HTTP/1."
    if (
        current[] != BytesConstant.H
        or current[1] != BytesConstant.T
        or current[2] != BytesConstant.T
        or current[3] != BytesConstant.P
        or current[4] != BytesConstant.SLASH
        or current[5] != BytesConstant.ONE
        or current[6] != BytesConstant.DOT
    ):
        ret = -1
        return UnsafePointer[UInt8, origin]()

    current += 7

    # Parse minor version
    if current[] < BytesConstant.ZERO or current[] > BytesConstant.NINE:
        ret = -1
        return UnsafePointer[UInt8, origin]()

    minor_version = Int(current[] - BytesConstant.ZERO)
    return current + 1


fn parse_headers[
    buf_origin: ImmutOrigin,
    header_origin: MutOrigin,
](
    buf: UnsafePointer[UInt8, buf_origin],
    buf_end: UnsafePointer[UInt8, buf_origin],
    headers: Span[PhrHeader, header_origin],
    mut num_headers: Int,
    max_headers: Int,
    mut ret: Int,
) -> UnsafePointer[UInt8, buf_origin]:
    """Parse HTTP headers."""
    var current = buf

    while current < buf_end:
        # Check for end of headers (empty line)
        if current[] == BytesConstant.CR:  # '\r'
            current += 1
            if current >= buf_end:
                ret = -2
                return UnsafePointer[UInt8, buf_origin]()
            if current[] != BytesConstant.LF:  # '\n'
                ret = -1
                return UnsafePointer[UInt8, buf_origin]()
            current += 1
            break  # End of headers found
        elif current[] == BytesConstant.LF:  # '\n'
            current += 1
            break  # End of headers found

        # Not end of headers, so we must be parsing a header
        if num_headers >= max_headers:
            ret = -1
            return UnsafePointer[UInt8, buf_origin]()

        # Parse header name
        if num_headers == 0 or (current[] != BytesConstant.whitespace and current[] != BytesConstant.TAB):
            var name = String()
            var name_len = Int()
            current = parse_token(current, buf_end, name, name_len, BytesConstant.COLON, ret)
            if current == UnsafePointer[UInt8, buf_origin]() or name_len == 0:
                ret = -1
                return UnsafePointer[UInt8, buf_origin]()

            headers[num_headers].name = name
            headers[num_headers].name_len = name_len
            current += 1  # Skip ':'

            # Skip whitespace
            while current < buf_end and (current[] == BytesConstant.whitespace or current[] == BytesConstant.TAB):
                current += 1
        else:
            headers[num_headers].name = String()
            headers[num_headers].name_len = 0

        # Parse header value
        var value = String()
        var value_len = Int()
        current = get_token_to_eol(current, buf_end, value, value_len, ret)
        if current == UnsafePointer[UInt8, buf_origin]():
            return UnsafePointer[UInt8, buf_origin]()

        # Trim trailing whitespace from value
        while value_len > 0:
            var c = value[value_len - 1]
            ref c_byte = c.as_bytes()[0]
            if c_byte != BytesConstant.whitespace and c_byte != BytesConstant.TAB:
                break
            value_len -= 1

        # Truncate the string to the trimmed length
        headers[num_headers].value = String(value[:value_len]) if value_len < len(value) else value
        headers[num_headers].value_len = value_len
        num_headers += 1

    return current


fn phr_parse_request[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    mut method: String,
    mut path: String,
    mut minor_version: Int,
    headers: Span[PhrHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    """Parse HTTP request."""
    var buf_end = buf_start + len
    var max_headers = num_headers
    var ret: Int = 0
    var current = buf_start

    # Initialize outputs
    method = String()
    method_len = 0
    path = String()
    minor_version = -1
    num_headers = 0

    # Check if request is complete (only if we have previous data)
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if complete == UnsafePointer[UInt8, buf_origin]():
            return ret

    # Skip initial empty lines (for tolerance)
    while current < buf_end:
        if current[] == BytesConstant.CR:  # '\r'
            current += 1
            if current >= buf_end:
                return -2
            if current[] != BytesConstant.LF:  # '\n'
                break  # Not an empty line, start parsing
            current += 1
        elif current[] == BytesConstant.LF:  # '\n'
            current += 1
        else:
            break  # Start of actual request

    # Parse method
    current = parse_token(current, buf_end, method, method_len, BytesConstant.whitespace, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    # Skip the space
    current += 1

    # Skip any extra spaces
    while current < buf_end and current[] == BytesConstant.whitespace:
        current += 1

    # Parse path
    var path_start = current
    while current < buf_end and current[] != BytesConstant.whitespace:
        # Accept printable ASCII (32-126) and high-bit characters (>= 128)
        # Reject control characters (< 32) and DEL (127)
        if not is_printable_ascii(current[]):
            var c = current[]
            if c < 0x20 or c == 0x7F:
                return -1
            # Otherwise, accept high-bit characters (>= 128)
        current += 1

    if current >= buf_end:
        return -2

    path_len = Int(current) - Int(path_start)
    path = create_string_from_ptr(path_start, path_len)

    # Skip spaces before HTTP version
    while current < buf_end and current[] == BytesConstant.whitespace:
        current += 1

    if current >= buf_end:
        return -2

    # Check if method or path is empty
    if method_len == 0 or path_len == 0:
        return -1

    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    # Expect CRLF or LF after version
    if current >= buf_end:
        return -2

    if current[] == BytesConstant.CR:  # '\r'
        current += 1
        if current >= buf_end:
            return -2
        if current[] != BytesConstant.LF:  # '\n'
            return -1
        current += 1
    elif current[] == BytesConstant.LF:  # '\n'
        current += 1
    else:
        return -1

    # Parse headers
    current = parse_headers(current, buf_end, headers, num_headers, max_headers, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    return Int(current) - Int(buf_start)


fn phr_parse_response[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    mut minor_version: Int,
    mut status: Int,
    mut msg: String,
    headers: Span[PhrHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    """Parse HTTP response."""
    var buf_end = buf_start + len
    var max_headers = num_headers
    var ret: Int = 0
    var current = buf_start

    # Initialize outputs
    minor_version = -1
    status = 0
    msg = String()
    msg_len = 0
    num_headers = 0

    # Check if response is complete
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if complete == UnsafePointer[UInt8, buf_origin]():
            return ret

    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    # Skip space(s)
    if current[] != BytesConstant.whitespace:
        return -1

    while current < buf_end and current[] == BytesConstant.whitespace:
        current += 1

    # Parse status code (3 digits)
    if Int(buf_end) - Int(current) < 4:
        return -2

    # Parse 3-digit status code
    status = 0
    for _ in range(3):
        if current[] < BytesConstant.ZERO or current[] > BytesConstant.NINE:
            return -1
        status = status * 10 + Int(current[] - BytesConstant.ZERO)
        current += 1

    # Get message including preceding space
    # var msg_start = current
    current = get_token_to_eol(current, buf_end, msg, msg_len, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    # Remove preceding spaces from message
    if msg_len > 0 and msg[0] == " ":
        var i = 0
        while i < msg_len and msg[i] == " ":
            i += 1
        msg = String(msg[i:])
        msg_len -= i
    elif msg_len > 0 and msg[0] != String(" "):
        # Garbage found after status code
        return -1

    # Parse headers
    current = parse_headers(current, buf_end, headers, num_headers, max_headers, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    return Int(current) - Int(buf_start)


fn phr_parse_headers[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    headers: Span[PhrHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    """Parse only headers (for standalone header parsing)."""
    var buf_end = buf_start + len
    var max_headers = num_headers
    var ret: Int = 0

    num_headers = 0

    # Check if headers are complete
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if complete == UnsafePointer[UInt8, buf_origin]():
            return ret

    # Parse headers
    var current = parse_headers(buf_start, buf_end, headers, num_headers, max_headers, ret)
    if current == UnsafePointer[UInt8, buf_origin]():
        return ret

    return Int(current) - Int(buf_start)


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


fn phr_decode_chunked[
    buf_origin: ImmutOrigin
](mut decoder: PhrChunkedDecoder, buf: Span[UInt8, buf_origin]) -> Tuple[Int, Int]:
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


fn phr_decode_chunked_is_in_data(decoder: PhrChunkedDecoder) -> Bool:
    """Check if decoder is currently in chunk data state."""
    return decoder._state == CHUNKED_IN_CHUNK_DATA


fn memmove[
    T: Copyable, dest_origin: MutOrigin, src_origin: MutOrigin
](dest: UnsafePointer[T, dest_origin], src: UnsafePointer[T, src_origin], count: Int):
    """
    Copies count elements from src to dest, handling overlapping memory regions safely.
    """
    if count <= 0:
        return

    if dest == src:
        return

    # Check if memory regions overlap
    var dest_addr = Int(dest)
    var src_addr = Int(src)
    var element_size = size_of[T]()
    var total_bytes = count * element_size

    var dest_end = dest_addr + total_bytes
    var src_end = src_addr + total_bytes

    # Check for overlap: regions overlap if one starts before the other ends
    var overlaps = (dest_addr < src_end) and (src_addr < dest_end)

    if not overlaps:
        # No overlap - use fast memcpy
        memcpy(dest=dest, src=src, count=count)
    elif dest_addr < src_addr:
        # Destination is before source - copy forwards (left to right)
        for i in range(count):
            (dest + i).init_pointee_copy((src + i)[])
    else:
        # Destination is after source - copy backwards (right to left)
        var i = count - 1
        while i >= 0:
            (dest + i).init_pointee_copy((src + i)[])
            i -= 1


fn create_string_from_ptr[origin: ImmutOrigin](ptr: UnsafePointer[UInt8, origin], length: Int) -> String:
    """Create a String from a pointer and length.

    Copies raw bytes directly into the String. This may result in invalid UTF-8 for bytes >= 0x80,
    but matches the behavior expected by the picohttpparser tests which were written for C.
    """
    if length <= 0:
        return String()

    # Copy raw bytes directly - this preserves the exact bytes from HTTP messages
    var result = String()
    # var buf = List[UInt8](capacity=length)
    # for i in range(length):
    #     buf.append(ptr[i])

    result.write_bytes(Span(ptr=ptr, length=length))

    return result^


fn bufis(s: String, t: String) -> Bool:
    """Check if string s equals t."""
    return s == t
