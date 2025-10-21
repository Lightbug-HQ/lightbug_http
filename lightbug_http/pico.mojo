from testing import assert_equal, assert_true, assert_false
from memory import memset, memcmp, UnsafePointer
import sys
from memory import memcpy
from sys import simdwidthof, size_of
from algorithm import vectorize
import math

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
    if c >= UInt8(ord('0')) and c <= UInt8(ord('9')):  # 0-9
        return True
    if c >= UInt8(ord('A')) and c <= UInt8(ord('Z')):  # A-Z
        return True
    if c >= UInt8(ord('a')) and c <= UInt8(ord('z')):  # a-z
        return True
    
    # Special characters allowed in tokens (ordered by ASCII value for branch prediction)
    # !  #  $  %  &  '  *  +  -  .  ^  _  `  |  ~
    return c == UInt8(ord('!')) or c == UInt8(ord('#')) or c == UInt8(ord('$')) or \
           c == UInt8(ord('%')) or c == UInt8(ord('&')) or c == UInt8(ord("'")) or \
           c == UInt8(ord('*')) or c == UInt8(ord('+')) or c == UInt8(ord('-')) or \
           c == UInt8(ord('.')) or c == UInt8(ord('^')) or c == UInt8(ord('_')) or \
           c == UInt8(ord('`')) or c == UInt8(ord('|')) or c == UInt8(ord('~'))

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
    
    token = create_string_from_ptr(token_start, token_len)
    return current

fn is_complete(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    last_len: Int,
    mut ret: Int
) -> UnsafePointer[UInt8]:
    """Check if request/response is complete."""
    var ret_cnt = 0
    var current = buf if last_len < 3 else buf + last_len - 3
    
    while current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end:
                ret = -2
                return UnsafePointer[UInt8]()
            if current[] != 0x0A:  # '\n'
                ret = -1
                return UnsafePointer[UInt8]()
            current += 1
            ret_cnt += 1
        elif current[] == 0x0A:  # '\n'
            current += 1
            ret_cnt += 1
        else:
            ret_cnt = 0
            current += 1
        
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
            token_len = Int(current) - Int(buf_start)
            token = create_string_from_ptr(buf_start, token_len)
            return current
        elif not is_token_char(current[]):
            ret = -1
            return UnsafePointer[UInt8]()
        current += 1
    
    ret = -2
    return UnsafePointer[UInt8]()

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
    if (current[] != UInt8(ord('H')) or current[1] != UInt8(ord('T')) or 
        current[2] != UInt8(ord('T')) or current[3] != UInt8(ord('P')) or
        current[4] != UInt8(ord('/')) or current[5] != UInt8(ord('1')) or
        current[6] != UInt8(ord('.'))):
        ret = -1
        return UnsafePointer[UInt8]()
    
    current += 7
    
    # Parse minor version
    if current[] < UInt8(ord('0')) or current[] > UInt8(ord('9')):
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
        # Check for end of headers (empty line)
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end:
                ret = -2
                return UnsafePointer[UInt8]()
            if current[] != 0x0A:  # '\n'
                ret = -1
                return UnsafePointer[UInt8]()
            current += 1
            break  # End of headers found
        elif current[] == 0x0A:  # '\n'
            current += 1
            break  # End of headers found
        
        # Not end of headers, so we must be parsing a header
        if num_headers >= max_headers:
            ret = -1
            return UnsafePointer[UInt8]()
        
        # Parse header name
        if num_headers == 0 or (current[] != UInt8(ord(' ')) and current[] != UInt8(ord('\t'))):
            var name = String()
            var name_len = Int()
            current = parse_token(current, buf_end, name, name_len, UInt8(ord(':')), ret)
            if current == UnsafePointer[UInt8]() or name_len == 0:
                ret = -1
                return UnsafePointer[UInt8]()
            
            headers[num_headers].name = name
            headers[num_headers].name_len = name_len
            current += 1  # Skip ':'
            
            # Skip whitespace
            while current < buf_end and (current[] == UInt8(ord(' ')) or current[] == UInt8(ord('\t'))):
                current += 1
        else:
            headers[num_headers].name = String()
            headers[num_headers].name_len = 0
        
        # Parse header value
        var value = String()
        var value_len = Int()
        current = get_token_to_eol(current, buf_end, value, value_len, ret)
        if current == UnsafePointer[UInt8]():
            return UnsafePointer[UInt8]()
        
        # Trim trailing whitespace from value
        while value_len > 0:
            var c = value[value_len - 1]
            if UInt8(ord(c)) != UInt8(ord(' ')) and UInt8(ord(c)) != UInt8(ord('\t')):
                break
            value_len -= 1
        
        # Truncate the string to the trimmed length
        headers[num_headers].value = value[:value_len] if value_len < len(value) else value
        headers[num_headers].value_len = value_len
        num_headers += 1
    
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
    
    # Check if request is complete (only if we have previous data)
    if last_len != 0:
        var complete = is_complete(buf_start, buf_end, last_len, ret)
        if complete == UnsafePointer[UInt8]():
            return ret
    
    # Skip initial empty lines (for tolerance)
    while current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end:
                return -2
            if current[] != 0x0A:  # '\n'
                break  # Not an empty line, start parsing
            current += 1
        elif current[] == 0x0A:  # '\n'
            current += 1
        else:
            break  # Start of actual request
    
    # Parse method
    current = parse_token(current, buf_end, method, method_len, UInt8(ord(' ')), ret)
    if current == UnsafePointer[UInt8]():
        return ret
    
    # Skip the space
    current += 1
    
    # Skip any extra spaces
    while current < buf_end and current[] == UInt8(ord(' ')):
        current += 1
    
    # Parse path
    var path_start = current
    while current < buf_end and current[] != UInt8(ord(' ')):
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
    while current < buf_end and current[] == UInt8(ord(' ')):
        current += 1
    
    if current >= buf_end:
        return -2
    
    # Check if method or path is empty
    if method_len == 0 or path_len == 0:
        return -1
    
    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if current == UnsafePointer[UInt8]():
        return ret
    
    # Expect CRLF or LF after version
    if current >= buf_end:
        return -2
    
    if current[] == 0x0D:  # '\r'
        current += 1
        if current >= buf_end:
            return -2
        if current[] != 0x0A:  # '\n'
            return -1
        current += 1
    elif current[] == 0x0A:  # '\n'
        current += 1
    else:
        return -1
    
    # Parse headers
    current = parse_headers(current, buf_end, headers, num_headers, max_headers, ret)
    if current == UnsafePointer[UInt8]():
        return ret
    
    return Int(current) - Int(buf_start)

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
        if complete == UnsafePointer[UInt8]():
            return ret
    
    # Parse HTTP version
    current = parse_http_version(current, buf_end, minor_version, ret)
    if current == UnsafePointer[UInt8]():
        return ret
    
    # Skip space(s)
    if current[] != UInt8(ord(' ')):
        return -1
    
    while current < buf_end and current[] == UInt8(ord(' ')):
        current += 1
    
    # Parse status code (3 digits)
    if Int(buf_end) - Int(current) < 4:
        return -2
    
    # Parse 3-digit status code
    status = 0
    for i in range(3):
        if current[] < UInt8(ord('0')) or current[] > UInt8(ord('9')):
            return -1
        status = status * 10 + Int(current[] - UInt8(ord('0')))
        current += 1
    
    # Get message including preceding space
    var msg_start = current
    current = get_token_to_eol(current, buf_end, msg, msg_len, ret)
    if current == UnsafePointer[UInt8]():
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
    if current == UnsafePointer[UInt8]():
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
        if complete == UnsafePointer[UInt8]():
            return ret
    
    # Parse headers
    var current = parse_headers(buf_start, buf_end, headers, num_headers, max_headers, ret)
    if current == UnsafePointer[UInt8]():
        return ret
    
    return Int(current) - Int(buf_start)

fn decode_hex(ch: UInt8) -> Int:
    """Decode hexadecimal character."""
    if ch >= UInt8(ord('0')) and ch <= UInt8(ord('9')):
        return Int(ch - UInt8(ord('0')))
    elif ch >= UInt8(ord('A')) and ch <= UInt8(ord('F')):
        return Int(ch - UInt8(ord('A')) + 10)
    elif ch >= UInt8(ord('a')) and ch <= UInt8(ord('f')):
        return Int(ch - UInt8(ord('a')) + 10)
    else:
        return -1

fn phr_decode_chunked(
    mut decoder: PhrChunkedDecoder,
    buf: UnsafePointer[UInt8],
    bufsz: Int
) -> (Int, Int):
    """Decode chunked transfer encoding.
    
    Returns (ret, new_bufsz) where:
    - ret: number of bytes left after chunked data, -1 for error, -2 for incomplete
    - new_bufsz: the new buffer size (decoded data length)
    """
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
                        return (-1, dst)
                    # Check for valid characters after chunk size
                    var c = buf[src]
                    if c != UInt8(ord(' ')) and c != UInt8(ord('\t')) and c != UInt8(ord(';')) and 
                       c != UInt8(ord('\n')) and c != UInt8(ord('\r')):
                        return (-1, dst)
                    break
                
                if decoder._hex_count == 16:  # sizeof(size_t) * 2
                    return (-1, dst)
                
                decoder.bytes_left_in_chunk = decoder.bytes_left_in_chunk * 16 + v
                decoder._hex_count += 1
                src += 1
            
            if src >= bufsz:
                break
            
            decoder._hex_count = 0
            decoder._state = CHUNKED_IN_CHUNK_EXT
            
        elif decoder._state == CHUNKED_IN_CHUNK_EXT:
            while src < bufsz:
                if buf[src] == UInt8(ord('\r')):
                    break
                elif buf[src] == UInt8(ord('\n')):
                    return (-1, dst)
                src += 1
            
            if src >= bufsz:
                break
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_HEADER_EXPECT_LF
            
        elif decoder._state == CHUNKED_IN_CHUNK_HEADER_EXPECT_LF:
            if src >= bufsz:
                break
            
            if buf[src] != UInt8(ord('\n')):
                return (-1, dst)
            
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
            
            if buf[src] != UInt8(ord('\r')):
                return (-1, dst)
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_DATA_EXPECT_LF
            
        elif decoder._state == CHUNKED_IN_CHUNK_DATA_EXPECT_LF:
            if src >= bufsz:
                break
            
            if buf[src] != UInt8(ord('\n')):
                return (-1, dst)
            
            src += 1
            decoder._state = CHUNKED_IN_CHUNK_SIZE
            
        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_HEAD:
            while src < bufsz:
                if buf[src] != UInt8(ord('\r')):
                    break
                src += 1
            
            if src >= bufsz:
                break
            
            if buf[src] == UInt8(ord('\n')):
                src += 1
                ret = bufsz - src
                break
            
            decoder._state = CHUNKED_IN_TRAILERS_LINE_MIDDLE
            
        elif decoder._state == CHUNKED_IN_TRAILERS_LINE_MIDDLE:
            while src < bufsz:
                if buf[src] == UInt8(ord('\n')):
                    break
                src += 1
            
            if src >= bufsz:
                break
            
            src += 1
            decoder._state = CHUNKED_IN_TRAILERS_LINE_HEAD
    
    # Move remaining data to beginning of buffer
    if dst != src and src < bufsz:
        memmove(buf + dst, buf + src, bufsz - src)
    
    var new_bufsz = dst
    
    # Check for excessive overhead
    if ret == -2:
        decoder._total_overhead += bufsz - dst
        if (decoder._total_overhead >= 100 * 1024 and 
            decoder._total_read - decoder._total_overhead < decoder._total_read // 4):
            ret = -1
    
    return (ret, new_bufsz)

fn phr_decode_chunked_is_in_data(decoder: PhrChunkedDecoder) -> Bool:
    """Check if decoder is currently in chunk data state."""
    return decoder._state == CHUNKED_IN_CHUNK_DATA

fn memmove[T: Copyable](
    dest: UnsafePointer[T], 
    src: UnsafePointer[T], 
    count: Int
):
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
        memcpy(dest, src, count)
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

fn create_string_from_ptr(ptr: UnsafePointer[UInt8], length: Int) -> String:
    """Create a String from a pointer and length.
    
    Copies raw bytes directly into the String. This may result in invalid UTF-8 for bytes >= 0x80,
    but matches the behavior expected by the picohttpparser tests which were written for C.
    """
    if length <= 0:
        return String()
    
    # Copy raw bytes directly - this preserves the exact bytes from HTTP messages
    var result = String()
    var buf = List[UInt8](capacity=length)
    for i in range(length):
        buf.append(ptr[i])
    
    result.write_bytes(buf)
    
    return result

fn bufis(s: String, t: String) -> Bool:
    """Check if string s equals t."""
    return s == t

# Test helper structures
@fieldwise_init
struct ParseRequestResult(Copyable):
    var ret: Int
    var method: String
    var method_len: Int
    var path: String
    var path_len: Int
    var minor_version: Int
    var num_headers: Int

@fieldwise_init
struct ParseResponseResult(Copyable):
    var ret: Int
    var minor_version: Int
    var status: Int
    var msg: String
    var msg_len: Int
    var num_headers: Int

@fieldwise_init
struct ParseHeadersResult(Copyable):
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

fn main():
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