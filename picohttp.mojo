from memory import memcpy
from sys import simdwidthof
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
    """Find character in ranges using SIMD operations when possible"""
    found = False
    var current = buf
    
    # For now, simplified version without SIMD
    # In production, you'd want to implement SIMD search here
    return current

fn get_token_to_eol(
    buf: UnsafePointer[UInt8],
    buf_end: UnsafePointer[UInt8],
    inout token: String,
    inout token_len: Int,
    inout ret: Int
) -> UnsafePointer[UInt8]:
    """Get token up to end of line"""
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
        token_len = (current - 1 - token_start)
        current += 1
    elif current[] == 0x0A:  # '\n'
        token_len = (current - token_start)
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
    """Check if request/response is complete"""
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
    inout token: String,
    inout token_len: Int,
    next_char: UInt8,
    inout ret: Int
) -> UnsafePointer[UInt8]:
    """Parse a token until next_char is found"""
    var buf_start = buf
    var current = buf
    
    while current < buf_end:
        if current[] == next_char:
            break
        elif not TOKEN_CHAR_MAP[int(current[])]:
            ret = -1
            return UnsafePointer[UInt8]()
        current += 1
    
    if current >= buf_end:
        ret = -2
        return DTypePointer[DType.uint8]()
    
    token = String(buf_start, current - buf_start)
    token_len = current - buf_start
    return current

fn parse_http_version(
    buf: DTypePointer[DType.uint8],
    buf_end: DTypePointer[DType.uint8],
    inout minor_version: Int,
    inout ret: Int
) -> DTypePointer[DType.uint8]:
    """Parse HTTP version"""
    if buf_end - buf < 9:
        ret = -2
        return DTypePointer[DType.uint8]()
    
    var current = buf
    # Check "HTTP/1."
    if (current[] != ord('H') or current[1] != ord('T') or 
        current[2] != ord('T') or current[3] != ord('P') or
        current[4] != ord('/') or current[5] != ord('1') or
        current[6] != ord('.')):
        ret = -1
        return DTypePointer[DType.uint8]()
    
    current += 7
    
    # Parse minor version
    if current[] < ord('0') or current[] > ord('9'):
        ret = -1
        return DTypePointer[DType.uint8]()
    
    minor_version = int(current[] - ord('0'))
    return current + 1

fn parse_headers(
    buf: DTypePointer[DType.uint8],
    buf_end: DTypePointer[DType.uint8],
    headers: DTypePointer[PhrHeader],
    inout num_headers: Int,
    max_headers: Int,
    inout ret: Int
) -> DTypePointer[DType.uint8]:
    """Parse HTTP headers"""
    var current = buf
    
    while current < buf_end:
        if current[] == 0x0D:  # '\r'
            current += 1
            if current >= buf_end or current[] != 0x0A:  # '\n'
                ret = -1
                return DTypePointer[DType.uint8]()
            current += 1
            break
        elif current[] == 0x0A:  # '\n'
            current += 1
            break
        
        if num_headers >= max_headers:
            ret = -1
            return DTypePointer[DType.uint8]()
        
        # Parse header name
        if num_headers == 0 or (current[] != ord(' ') and current[] != ord('\t')):
            var name: String
            var name_len: Int
            current = parse_token(current, buf_end, name, name_len, ord(':'), ret)
            if not current or name_len == 0:
                ret = -1
                return DTypePointer[DType.uint8]()
            
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
        var value: String
        var value_len: Int
        current = get_token_to_eol(current, buf_end, value, value_len, ret)
        if not current:
            return DTypePointer[DType.uint8]()
        
        # Trim trailing whitespace from value
        while value_len > 0:
            var c = value.data[value_len - 1]
            if c != ord(' ') and c != ord('\t'):
                break
            value_len -= 1
        
        headers[num_headers].value = value
        headers[num_headers].value_len = value_len
        num_headers += 1
    
    if current >= buf_end:
        ret = -2
        return DTypePointer[DType.uint8]()
    
    return current

fn phr_parse_request(
    buf_start: DTypePointer[DType.uint8],
    len: Int,
    inout method: String,
    inout method_len: Int,
    inout path: String,
    inout path_len: Int,
    inout minor_version: Int,
    headers: DTypePointer[PhrHeader],
    inout num_headers: Int,
    last_len: Int
) -> Int:
    """Parse HTTP request"""
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
    
    path = String(path_start, current - path_start)
    path_len = current - path_start
    
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
    
    return int(current - buf_start)

fn decode_hex(ch: UInt8) -> Int:
    """Decode hexadecimal character"""
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
    """Decode chunked transfer encoding"""
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
    """Check if decoder is currently in chunk data state"""
    return decoder._state == CHUNKED_IN_CHUNK_DATA