from testing import assert_equal, assert_true, assert_false
from memory import memset, memcmp, UnsafePointer
import sys
from memory import memcpy
from sys import simdwidthof
from sys.info import sizeof
from algorithm import vectorize
import math
from utils import StaticTuple

# Constants
alias IS_PRINTABLE_ASCII_MASK = 0o137

# Token character map - represents which characters are valid in tokens
alias TOKEN_CHAR_MAP = StaticTuple[Bool, 256](
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, True, False, True, True, True, True, True, False, False, True, True, False, True, True, False,
    True, True, True, True, True, True, True, True, True, True, False, False, False, False, False, False,
    False, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True,
    True, True, True, True, True, True, True, True, True, True, True, False, False, False, True, True,
    True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True,
    True, True, True, True, True, True, True, True, True, True, True, False, True, False, True, False,
    # Rest are False (128-255)
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False,
    False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False
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

struct PhrHeader:
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

fn findchar_fast(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    ranges: UnsafePointer[UInt8],
    ranges_size: Int,
    mut found: Bool
) -> UnsafePointer[UInt8]:
    """Find character in ranges using SIMD operations when possible."""
    found = False
    var current = buf
    
    # For now, simplified version without SIMD
    # In production, you'd want to implement SIMD search here
    return current

fn get_token_to_eol(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    mut token: String,
    mut token_len: Int,
    mut ret: Int
) -> UnsafePointer[UInt8]:
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
        return UnsafePointer[UInt8]()
    
    if current[] == 0x0D:  # '\r'
        current += 1
        if current >= buf_end or current[] != 0x0A:  # '\n'
            ret = -1
            return UnsafePointer[UInt8]()
        token_len = Int(current) - 1 - Int(token_start)
        current += 1
    elif current[] == 0x0A:  # '\n'
        token_len = Int(current) - Int(token_start)
        current += 1
    else:
        ret = -1
        return UnsafePointer[UInt8]()
    
    token = String(token_start, token_len)
    return current

fn is_complete(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    last_len: Int,
    mut ret: Int
) -> UnsafePointer[UInt8]:
    """Check if request/response is complete."""
    var ret_cnt = 0
    var current = buf + max(0, last_len - 3)
    
    while current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end or current[] != 0x0A:  # '\n'
                ret = -1
                return UnsafePointer[UInt8]()
            current += 1
            ret_cnt += 1
        elif current[] == 0x0A:  # '\n'
            current += 1
            ret_cnt += 1
        else:
            current += 1
            ret_cnt = 0
        
        if ret_cnt == 2:
            return current
    
    ret = -2
    return UnsafePointer[UInt8]()

fn parse_token(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    mut token: String,
    mut token_len: Int,
    next_char: UInt8,
    mut ret: Int
) -> UnsafePointer[UInt8]:
    """Parse a token until next_char is found."""
    var buf_start = buf
    var current = buf
    
    while current < buf_end:
        if current[] == next_char:
            break
        elif not TOKEN_CHAR_MAP[Int(current[])]:
            ret = -1
            return UnsafePointer[UInt8]()
        current += 1
    
    if current >= buf_end:
        ret = -2
        return UnsafePointer[UInt8]()
    
    token = String(buf_start, Int(current) - Int(buf_start))
    token_len = Int(current) - Int(buf_start)
    return current

fn parse_http_version(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    mut minor_version: Int,
    mut ret: Int
) -> UnsafePointer[UInt8]:
    """Parse HTTP version."""
    if Int(buf_end) - Int(buf) < 9:
        ret = -2
        return UnsafePointer[UInt8]()
    
    var current = buf
    # Check "HTTP/1."
    if (current[] != ord('H') or current[1] != ord('T') or 
        current[2] != ord('T') or current[3] != ord('P') or
        current[4] != ord('/') or current[5] != ord('1') or
        current[6] != ord('.')):
        ret = -1
        return UnsafePointer[UInt8]()
    
    current += 7
    
    # Parse minor version
    if current[] < ord('0') or current[] > ord('9'):
        ret = -1
        return UnsafePointer[UInt8]()
    
    minor_version = Int(current[]) - ord('0')
    return current + 1

fn parse_headers(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    headers: UnsafePointer[PhrHeader],
    mut num_headers: Int,
    max_headers: Int,
    mut ret: Int
) -> UnsafePointer[UInt8]:
    """Parse HTTP headers."""
    var current = buf
    
    while current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end or current[] != 0x0A:  # '\n'
                ret = -1
                return UnsafePointer[UInt8]()
            current += 1
            break
        elif current[] == 0x0A:  # '\n'
            current += 1
            break
        
        if num_headers >= max_headers:
            ret = -1
            return UnsafePointer[UInt8]()
        
        # Parse header name
        if num_headers == 0 or (current[] != ord(' ') and current[] != ord('\t')):
            var name = String()
            var name_len = Int()
            current = parse_token(current, buf_end, name, name_len, ord(':'), ret)
            if not current or name_len == 0:
                ret = -1
                return UnsafePointer[UInt8]()
            
            headers[num_headers].name = name
            headers[num_headers].name_len = name_len
            current += 1  # Skip ':'
            
            # Skip whitespace
            while current < buf_end and (current[] == ord(' ') or current[] == ord('\t')):
                current += 1
        else:
            headers[num_headers].name = String()
            headers[num_headers].name_len = 0
        
        # Parse header value
        var value = String()
        var value_len = Int()
        current = get_token_to_eol(current, buf_end, value, value_len, ret)
        if not current:
            return UnsafePointer[UInt8]()
        
        # Trim trailing whitespace from value
        while value_len > 0:
            var c = value[value_len - 1]
            if ord(c) != ord(' ') and ord(c) != ord('\t'):
                break
            value_len -= 1
        
        headers[num_headers].value = value
        headers[num_headers].value_len = value_len
        num_headers += 1
    
    if current >= buf_end:
        ret = -2
        return UnsafePointer[UInt8]()
    
    return current

fn phr_parse_request(
    buf_start: UnsafePointer[UInt8],
    len: Int,
    mut method: String,
    mut method_len: Int,
    mut path: String,
    mut path_len: Int,
    mut minor_version: Int,
    headers: UnsafePointer[PhrHeader],
    mut num_headers: Int,
    last_len: Int
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
    path_len = 0
    minor_version = -1
    num_headers = 0
    
    # Check if request is complete
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if not complete:
            return ret
    
    # Skip empty line if present
    if current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end or current[] != 0x0A:  # '\n'
                return -1
            current += 1
        elif current[] == 0x0A:  # '\n'
            current += 1
    
    # Parse method
    current = parse_token(current, buf_end, method, method_len, ord(' '), ret)
    if not current:
        return ret
    
    # Skip spaces
    current += 1
    while current < buf_end and current[] == ord(' '):
        current += 1
    
    # Parse path
    var path_start = current
    while current < buf_end and current[] != ord(' '):
        if not is_printable_ascii(current[]):
            return -1
        current += 1
    
    if current >= buf_end:
        return -2
    
    path = String(path_start, Int(current) - Int(path_start))
    path_len = Int(current) - Int(path_start)
    
    # Skip spaces
    while current < buf_end and current[] == ord(' '):
        current += 1
    
    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if not current:
        return ret
    
    # Parse end of request line
    if current[] == 0x0D:  # '\r'
        current += 1
        if current >= buf_end or current[] != 0x0A:  # '\n'
            return -1
        current += 1
    elif current[] == 0x0A:  # '\n'
        current += 1
    else:
        return -1
    
    # Parse headers
    current = parse_headers(current, buf_end, headers, num_headers, max_headers, ret)
    if not current:
        return ret
    
    return Int(current) - Int(buf_start)

fn decode_hex(ch: UInt8) -> Int:
    """Decode hexadecimal character."""
    if ch >= ord('0') and ch <= ord('9'):
        return Int(ch - ord('0'))
    elif ch >= ord('A') and ch <= ord('F'):
        return Int(ch - ord('A') + 10)
    elif ch >= ord('a') and ch <= ord('f'):
        return Int(ch - ord('a') + 10)
    else:
        return -1

fn phr_decode_chunked(
    mut decoder: PhrChunkedDecoder,
    buf: UnsafePointer[UInt8],
    mut bufsz: Int
) -> Int:
    """Decode chunked transfer encoding."""
    var dst = 0
    var src = 0
    var ret = -2  # incomplete
    
    decoder._total_read += bufsz
    
    while True:
        if decoder._state == CHUNKED_IN_CHUNK_SIZE:
            while src < bufsz:
                var v = decode_hex(buf[src])
                if v == -1:
                    if decoder._hex_count == 0:
                        return -1
                    # Check for valid characters after chunk size
                    var c = buf[src]
                    if c != ord(' ') and c != ord('\t') and c != ord(';') and 
                       c != ord('\n') and c != ord('\r'):
                        return -1
                    break
                
                if decoder._hex_count == 16:  # sizeof(size_t) * 2
                    return -1
                
                decoder.bytes_left_in_chunk = decoder.bytes_left_in_chunk * 16 + v
                decoder._hex_count += 1
                src += 1
            
            if src >= bufsz:
                break
            
            decoder._hex_count = 0
            decoder._state = CHUNKED_IN_CHUNK_EXT
            
        elif decoder._state == CHUNKED_IN_CHUNK_EXT:
            while src < bufsz:
                if buf[src] == ord('\r'):
                    break
                elif buf[src] == ord('\n'):
                    return -1
                src += 1
            
            if src >= bufsz:
                break
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_HEADER_EXPECT_LF
            
        elif decoder._state == CHUNKED_IN_CHUNK_HEADER_EXPECT_LF:
            if src >= bufsz:
                break
            
            if buf[src] != ord('\n'):
                return -1
            
            src += 1
            
            if decoder.bytes_left_in_chunk == 0:
                if decoder.consume_trailer:
                    decoder._state = CHUNKED_IN_TRAILERS_LINE_HEAD
                    continue
                else:
                    ret = bufsz - src
                    break
            
            decoder._state = CHUNKED_IN_CHUNK_DATA
            
        elif decoder._state == CHUNKED_IN_CHUNK_DATA:
            var avail = bufsz - src
            if avail < decoder.bytes_left_in_chunk:
                if dst != src:
                    memmove(buf + dst, buf + src, avail)
                src += avail
                dst += avail
                decoder.bytes_left_in_chunk -= avail
                break
            
            if dst != src:
                memmove(buf + dst, buf + src, decoder.bytes_left_in_chunk)
            
            src += decoder.bytes_left_in_chunk
            dst += decoder.bytes_left_in_chunk
            decoder.bytes_left_in_chunk = 0
            decoder._state = CHUNKED_IN_CHUNK_DATA_EXPECT_CR
            
        elif decoder._state == CHUNKED_IN_CHUNK_DATA_EXPECT_CR:
            if src >= bufsz:
                break
            
            if buf[src] != ord('\r'):
                return -1
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_DATA_EXPECT_LF
            
        elif decoder._state == CHUNKED_IN_CHUNK_DATA_EXPECT_LF:
            if src >= bufsz:
                break
            
            if buf[src] != ord('\n'):
                return -1
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_SIZE
            
        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_HEAD:
            while src < bufsz:
                if buf[src] != ord('\r'):
                    break
                src += 1
            
            if src >= bufsz:
                break
            
            if buf[src] == ord('\n'):
                src += 1
                ret = bufsz - src
                break
            
            decoder._state = CHUNKED_IN_TRAILERS_LINE_MIDDLE
            
        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_MIDDLE:
            while src < bufsz:
                if buf[src] == ord('\n'):
                    break
                src += 1
            
            if src >= bufsz:
                break
            
            src += 1
            decoder._state = CHUNKED_IN_TRAILERS_LINE_HEAD
    
    # Move remaining data to beginning of buffer
    if dst != src and src < bufsz:
        memmove(buf + dst, buf + src, bufsz - src)
    
    bufsz = dst
    
    # Check for excessive overhead
    if ret == -2:
        decoder._total_overhead += bufsz - dst
        if (decoder._total_overhead >= 100 * 1024 and 
            decoder._total_read - decoder._total_overhead < decoder._total_read // 4):
            ret = -1
    
    return ret

fn phr_decode_chunked_is_in_data(decoder: PhrChunkedDecoder) -> Bool:
    """Check if decoder is currently in chunk data state."""
    return decoder._state == CHUNKED_IN_CHUNK_DATA

fn phr_parse_response(
    buf_start: UnsafePointer[UInt8],
    len: Int,
    mut minor_version: Int,
    mut status: Int,
    mut msg: String,
    mut msg_len: Int,
    headers: UnsafePointer[PhrHeader],
    mut num_headers: Int,
    last_len: Int
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
        if not complete:
            return ret
    
    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if not current:
        return ret
    
    # Skip space(s)
    if current[] != ord(' '):
        return -1
    
    while current < buf_end and current[] == ord(' '):
        current += 1
    
    # Parse status code (3 digits)
    if Int(buf_end) - Int(current) < 4:
        return -2
    
    # Parse 3-digit status code
    status = 0
    for i in range(3):
        if current[] < ord('0') or current[] > ord('9'):
            return -1
        status = status * 10 + Int(current[] - ord('0'))
        current += 1
    
    # Get message including preceding space
    var msg_start = current
    current = get_token_to_eol(current, buf_end, msg, msg_len, ret)
    if not current:
        return ret
    
    # Remove preceding spaces from message
    if msg_len > 0 and msg[0] == ' ':
        var i = 0
        while i < msg_len and msg[i] == ' ':
            i += 1
        msg = msg[i:]
        msg_len -= i
    elif msg_len > 0 and msg[0] != String(' '):
        # Garbage found after status code
        return -1
    
    # Parse headers
    current = parse_headers(current, buf_end, headers, num_headers, max_headers, ret)
    if not current:
        return ret
    
    return Int(current) - Int(buf_start)

fn phr_parse_headers(
    buf_start: UnsafePointer[UInt8],
    len: Int,
    headers: UnsafePointer[PhrHeader],
    mut num_headers: Int,
    last_len: Int
) -> Int:
    """Parse only headers (for standalone header parsing)."""
    var buf_end = buf_start + len
    var max_headers = num_headers
    var ret: Int = 0
    
    num_headers = 0
    
    # Check if headers are complete
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if not complete:
            return ret
    
    # Parse headers
    var current = parse_headers(buf_start, buf_end, headers, num_headers, max_headers, ret)
    if not current:
        return ret
    
    return Int(current) - Int(buf_start)

fn memmove[T: Copyable](
    dest: UnsafePointer[T], 
    src: UnsafePointer[T], 
    count: Int
):
    """
    Copies count elements from src to dest, handling overlapping memory regions safely.
    
    Args:
        dest: Destination pointer.
        src: Source pointer.
        count: Number of elements to copy.
    Returns:
        The destination pointer
    """
    if count <= 0:
        return
        
    if dest == src:
        return
    
    # Check if memory regions overlap
    var dest_addr = Int(dest)
    var src_addr = Int(src)
    var element_size = sizeof[T]()
    var total_bytes = count * element_size
    
    var dest_end = dest_addr + total_bytes
    var src_end = src_addr + total_bytes
    
    # Check for overlap: regions overlap if one starts before the other ends
    var overlaps = (dest_addr < src_end) and (src_addr < dest_end)
    
    if not overlaps:
        # No overlap - use fast memcpy
        memcpy(dest, src, count)
    elif dest_addr < src_addr:
        # Destination is before source - copy forwards (left to right)
        # This is safe because we won't overwrite data we haven't read yet
        memcpy(dest, src, count)
    else:
        # Destination is after source - copy backwards (right to left)
        # This prevents overwriting source data before we've read it
        var i = count - 1
        while i >= 0:
            dest[i] = src[i]
            i -= 1


# Byte-specific version for cases where you're working with raw bytes
fn memmove_bytes(
    dest: UnsafePointer[UInt8], 
    src: UnsafePointer[UInt8], 
    num_bytes: Int
):
    """
    Copies num_bytes from src to dest, handling overlapping memory regions safely.
    
    Args:
        dest: Destination pointer.
        src: Source pointer.
        num_bytes: Number of bytes to copy.
    Returns:
        The destination pointer
    """
    memmove[UInt8](dest, src, num_bytes)


fn bufis(s: String, t: String) -> Bool:
    """Check if string s equals t."""
    return s == t

fn test_request() raises:
    """Test HTTP request parsing."""
    var method = String()
    var method_len = Int()
    var path = String()
    var path_len = Int()
    var minor_version = Int()
    var headers = UnsafePointer[PhrHeader].alloc(4)
    var num_headers = Int()
    
    # Helper to create test buffer
    fn parse_test(
        data: String,
        last_len: Int,
        expected: Int,
        comment: String,
    ) -> Int:
        print("Testing:", comment)
        var buf = data.as_bytes()
        var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
        for i in range(len(buf)):
            buf_ptr[i] = buf[i]
        
        num_headers = 4
        var result = phr_parse_request(
            buf_ptr,
            len(buf),
            method,
            method_len,
            path,
            path_len,
            minor_version,
            headers,
            num_headers,
            last_len
        )
        
        buf_ptr.free()
        return result
    
    # Simple request
    var ret = parse_test("GET / HTTP/1.0\r\n\r\n", 0, 0, "simple")
    assert_equal(ret, 18)
    assert_equal(num_headers, 0)
    assert_true(bufis(method, "GET"))
    assert_true(bufis(path, "/"))
    assert_equal(minor_version, 0)
    
    # Partial request
    ret = parse_test("GET / HTTP/1.0\r\n\r", 0, -2, "partial")
    assert_equal(ret, -2)
    
    # Request with headers
    ret = parse_test(
        "GET /hoge HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
        0, 0, "parse headers"
    )
    assert_equal(num_headers, 2)
    assert_true(bufis(method, "GET"))
    assert_true(bufis(path, "/hoge"))
    assert_equal(minor_version, 1)
    assert_true(bufis(headers[0].name, "Host"))
    assert_true(bufis(headers[0].value, "example.com"))
    assert_true(bufis(headers[1].name, "Cookie"))
    assert_true(bufis(headers[1].value, ""))
    
    # Multiline headers
    ret = parse_test(
        "GET / HTTP/1.0\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n",
        0, 0, "parse multiline"
    )
    assert_equal(num_headers, 3)
    assert_true(bufis(method, "GET"))
    assert_true(bufis(path, "/"))
    assert_equal(minor_version, 0)
    assert_true(bufis(headers[0].name, "foo"))
    assert_true(bufis(headers[0].value, ""))
    assert_true(bufis(headers[1].name, "foo"))
    assert_true(bufis(headers[1].value, "b"))
    assert_equal(headers[2].name_len, 0)  # Continuation line has no name
    assert_true(bufis(headers[2].value, "  \tc"))
    
    # Invalid header name with trailing space
    ret = parse_test(
        "GET / HTTP/1.0\r\nfoo : ab\r\n\r\n",
        0, -1, "parse header name with trailing space"
    )
    assert_equal(ret, -1)
    
    # Various incomplete requests
    ret = parse_test("GET", 0, -2, "incomplete 1")
    assert_equal(ret, -2)
    
    ret = parse_test("GET ", 0, -2, "incomplete 2")
    assert_equal(ret, -2)
    assert_true(bufis(method, "GET"))
    
    ret = parse_test("GET /", 0, -2, "incomplete 3")
    assert_equal(ret, -2)
    
    ret = parse_test("GET / ", 0, -2, "incomplete 4")
    assert_equal(ret, -2)
    assert_true(bufis(path, "/"))
    
    ret = parse_test("GET / H", 0, -2, "incomplete 5")
    assert_equal(ret, -2)
    
    ret = parse_test("GET / HTTP/1.", 0, -2, "incomplete 6")
    assert_equal(ret, -2)
    
    ret = parse_test("GET / HTTP/1.0", 0, -2, "incomplete 7")
    assert_equal(ret, -2)
    
    ret = parse_test("GET / HTTP/1.0\r", 0, -2, "incomplete 8")
    assert_equal(ret, -2)
    assert_equal(minor_version, 0)
    
    # Slowloris tests
    var test_str = "GET /hoge HTTP/1.0\r\n\r"
    ret = parse_test(test_str, len(test_str) - 1, -2, "slowloris (incomplete)")
    assert_equal(ret, -2)
    
    var test_str_incomplete = "GET /hoge HTTP/1.0\r\n\r\n"
    ret = parse_test(test_str_incomplete, len(test_str_incomplete) - 1, 0, "slowloris (complete)")
    assert_true(ret > 0)
    
    # Invalid requests
    ret = parse_test(" / HTTP/1.0\r\n\r\n", 0, -1, "empty method")
    assert_equal(ret, -1)
    
    ret = parse_test("GET  HTTP/1.0\r\n\r\n", 0, -1, "empty request-target")
    assert_equal(ret, -1)
    
    ret = parse_test("GET / HTTP/1.0\r\n:a\r\n\r\n", 0, -1, "empty header name")
    assert_equal(ret, -1)
    
    ret = parse_test("GET / HTTP/1.0\r\n :a\r\n\r\n", 0, -1, "header name (space only)")
    assert_equal(ret, -1)
    
    # Multiple spaces between tokens
    ret = parse_test("GET   /   HTTP/1.0\r\n\r\n", 0, 0, "accept multiple spaces between tokens")
    assert_true(ret > 0)
    
    headers.free()

fn test_response() raises:
    """Test HTTP response parsing."""
    var minor_version = Int()
    var status = Int()
    var msg = String()
    var msg_len = Int()
    var headers = UnsafePointer[PhrHeader].alloc(4)
    var num_headers = Int()
    
    fn parse_test(
        data: String,
        last_len: Int,
        expected: Int,
        comment: String,
    ) -> Int:
        print("Testing:", comment)
        var buf = data.as_bytes()
        var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
        for i in range(len(buf)):
            buf_ptr[i] = buf[i]
        
        num_headers = 4
        var result = phr_parse_response(
            buf_ptr,
            len(buf),
            minor_version,
            status,
            msg,
            msg_len,
            headers,
            num_headers,
            last_len
        )
        
        buf_ptr.free()
        return result
    
    # Simple response
    var ret = parse_test("HTTP/1.0 200 OK\r\n\r\n", 0, 0, "simple")
    assert_equal(num_headers, 0)
    assert_equal(status, 200)
    assert_equal(minor_version, 0)
    assert_true(bufis(msg, "OK"))
    
    # Partial response
    ret = parse_test("HTTP/1.0 200 OK\r\n\r", 0, -2, "partial")
    assert_equal(ret, -2)
    
    # Response with headers
    ret = parse_test(
        "HTTP/1.1 200 OK\r\nHost: example.com\r\nCookie: \r\n\r\n",
        0, 0, "parse headers"
    )
    assert_equal(num_headers, 2)
    assert_equal(minor_version, 1)
    assert_equal(status, 200)
    assert_true(bufis(msg, "OK"))
    assert_true(bufis(headers[0].name, "Host"))
    assert_true(bufis(headers[0].value, "example.com"))
    assert_true(bufis(headers[1].name, "Cookie"))
    assert_true(bufis(headers[1].value, ""))
    
    # Internal server error
    ret = parse_test(
        "HTTP/1.0 500 Internal Server Error\r\n\r\n",
        0, 0, "internal server error"
    )
    assert_equal(num_headers, 0)
    assert_equal(minor_version, 0)
    assert_equal(status, 500)
    assert_true(bufis(msg, "Internal Server Error"))
    
    # Various incomplete responses
    ret = parse_test("H", 0, -2, "incomplete 1")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.", 0, -2, "incomplete 2")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.1", 0, -2, "incomplete 3")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.1 ", 0, -2, "incomplete 4")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.1 2", 0, -2, "incomplete 5")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.1 200", 0, -2, "incomplete 6")
    assert_equal(ret, -2)
    
    ret = parse_test("HTTP/1.1 200 ", 0, -2, "incomplete 7")
    assert_equal(ret, -2)
    
    # Accept missing trailing whitespace in status-line
    ret = parse_test("HTTP/1.1 200\r\n\r\n", 0, 0, "accept missing trailing whitespace in status-line")
    assert_true(ret > 0)
    assert_true(bufis(msg, ""))
    
    # Invalid responses
    ret = parse_test("HTTP/1. 200 OK\r\n\r\n", 0, -1, "invalid http version")
    assert_equal(ret, -1)
    
    ret = parse_test("HTTP/1.2z 200 OK\r\n\r\n", 0, -1, "invalid http version 2")
    assert_equal(ret, -1)
    
    ret = parse_test("HTTP/1.1  OK\r\n\r\n", 0, -1, "no status code")
    assert_equal(ret, -1)
    
    headers.free()

fn test_headers() raises:
    """Test header parsing."""
    var headers = UnsafePointer[PhrHeader].alloc(4)
    var num_headers = Int()
    
    fn parse_test(
        data: String,
        last_len: Int,
        expected: Int,
        comment: String,
    ) -> Int:
        print("Testing:", comment)
        var buf = data.as_bytes()
        var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
        for i in range(len(buf)):
            buf_ptr[i] = buf[i]
        
        num_headers = 4
        var result = phr_parse_headers(
            buf_ptr,
            len(buf),
            headers,
            num_headers,
            last_len
        )
        
        buf_ptr.free()
        return result
    
    # Simple headers
    var ret = parse_test(
        "Host: example.com\r\nCookie: \r\n\r\n",
        0, 0, "simple"
    )
    assert_equal(num_headers, 2)
    assert_true(bufis(headers[0].name, "Host"))
    assert_true(bufis(headers[0].value, "example.com"))
    assert_true(bufis(headers[1].name, "Cookie"))
    assert_true(bufis(headers[1].value, ""))
    
    # Slowloris test
    ret = parse_test(
        "Host: example.com\r\nCookie: \r\n\r\n",
        1, 0, "slowloris"
    )
    assert_equal(num_headers, 2)
    
    # Partial headers
    ret = parse_test(
        "Host: example.com\r\nCookie: \r\n\r",
        0, -2, "partial"
    )
    assert_equal(ret, -2)
    
    headers.free()

fn test_chunked_at_once(line: Int,
    consume_trailer: Bool,
    encoded: String,
    decoded: String,
    expected: Int
    ) raises:
    """Test chunked decoding all at once."""
    print("Testing at-once, source at line", line)
    
    var decoder = PhrChunkedDecoder()
    decoder.consume_trailer = consume_trailer
    
    var buf = encoded.as_bytes()
    var buf_ptr = UnsafePointer[UInt8].alloc(len(buf))
    for i in range(len(buf)):
        buf_ptr[i] = buf[i]
    
    var bufsz = len(buf)
    var ret = phr_decode_chunked(decoder, buf_ptr, bufsz)
    
    assert_equal(ret, expected)
    assert_equal(bufsz, len(decoded))
    
    # Check decoded content
    var decoded_bytes = decoded.as_bytes()
    for i in range(bufsz):
        assert_equal(buf_ptr[i], decoded_bytes[i])
    
    buf_ptr.free()

fn test_chunked_per_byte(line: Int,
    consume_trailer: Bool,
    encoded: String,
    decoded: String,
    expected: Int
    ) raises:
    """Test chunked decoding byte by byte."""
    print("Testing per-byte, source at line", line)
    
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
        var ret = phr_decode_chunked(decoder, buf + bytes_ready, bufsz)
        if ret != -2:
            assert_false(True, "Unexpected return value during byte-by-byte parsing")
            buf.free()
            return
        bytes_ready += bufsz
    
    # Feed the last byte(s)
    for i in range(bytes_to_consume - 1, len(encoded)):
        buf[bytes_ready + i - (bytes_to_consume - 1)] = encoded_bytes[i]
    
    var bufsz = len(encoded) - (bytes_to_consume - 1)
    var ret = phr_decode_chunked(decoder, buf + bytes_ready, bufsz)
    
    assert_equal(ret, expected)
    bytes_ready += bufsz
    assert_equal(bytes_ready, len(decoded))
    
    # Check decoded content
    for i in range(bytes_ready):
        assert_equal(buf[i], decoded_bytes[i])
    
    buf.free()

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
        "hello world", 19  # sizeof("a: b\r\nc: d\r\n\r\n") - 1
    )

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

fn main():
    """Run all tests."""
    print("Running picohttpparser tests...")
    
    try:
        test_request()
        test_response()
        test_headers()
        test_chunked()
        test_chunked_consume_trailer()
        print("All tests passed!")
    except e:
        print("Test failed:", e)
    