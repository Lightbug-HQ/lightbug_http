from lightbug_http.io.bytes import Bytes, create_string_from_ptr
from lightbug_http.strings import BytesConstant, is_printable_ascii, is_token_char


struct HTTPHeader(Copyable):
    var name: String
    var name_len: Int
    var value: String
    var value_len: Int

    fn __init__(out self):
        self.name = String()
        self.name_len = 0
        self.value = String()
        self.value_len = 0


struct ParseResult[T: AnyType]:
    """Wrapper for parsing results.

    Error codes:
    0: Success
    -1: Error
    -2: Incomplete data
    """

    var value: T
    var bytes_consumed: Int
    var error_code: Int

    fn __init__(out self, value: T, bytes_consumed: Int, error_code: Int):
        self.value = value
        self.bytes_consumed = bytes_consumed
        self.error_code = error_code

    fn is_ok(self) -> Bool:
        return self.error_code == 0

    fn is_incomplete(self) -> Bool:
        return self.error_code == -2


struct BufferView[origin: Origin]:
    var data: Span[UInt8, Self.origin]
    var offset: Int

    fn __init__(out self, data: Span[UInt8, Self.origin]):
        self.data = data
        self.offset = 0

    fn __init__(out self, data: Span[UInt8, Self.origin], offset: Int):
        self.data = data
        self.offset = offset

    fn remaining(self) -> Int:
        return len(self.data) - self.offset

    fn is_empty(self) -> Bool:
        return self.offset >= len(self.data)

    fn peek(self) -> Optional[UInt8]:
        if self.offset < len(self.data):
            return self.data[self.offset]
        return None

    fn peek_at(self, pos: Int) -> Optional[UInt8]:
        var abs_pos = self.offset + pos
        if abs_pos < len(self.data):
            return self.data[abs_pos]
        return None

    fn advance(mut self, count: Int = 1):
        self.offset = min(self.offset + count, len(self.data))

    fn get_byte(mut self) -> Optional[UInt8]:
        if self.offset < len(self.data):
            var byte = self.data[self.offset]
            self.offset += 1
            return byte
        return None

    fn slice_from_offset(self, start_offset: Int) -> Span[UInt8, Self.origin]:
        var end = self.offset
        if start_offset >= 0 and start_offset < end and end <= len(self.data):
            return self.data[start_offset:end]
        return Span[UInt8, Self.origin]()

    fn create_string_from_offset(self, start_offset: Int, length: Int) -> String:
        if start_offset >= 0 and start_offset + length <= len(self.data):
            var ptr = self.data.unsafe_ptr() + start_offset
            return create_string_from_ptr(ptr, length)
        return String()


fn get_token_to_eol[origin: Origin](mut buf: BufferView[origin], mut token: String, mut token_len: Int) -> Int:
    var token_start = buf.offset

    while not buf.is_empty():
        var byte = buf.peek()
        if not byte:
            return -2

        var c = byte.value()
        if not is_printable_ascii(c):
            if (c < 0x20 and c != 0x09) or c == 0x7F:
                break
        buf.advance()

    if buf.is_empty():
        return -2

    var current_byte = buf.peek()
    if not current_byte:
        return -2

    if current_byte.value() == BytesConstant.CR:
        buf.advance()
        var next_byte = buf.peek()
        if not next_byte or next_byte.value() != BytesConstant.LF:
            return -1
        token_len = buf.offset - 1 - token_start
        buf.advance()
    elif current_byte.value() == BytesConstant.LF:
        token_len = buf.offset - token_start
        buf.advance()
    else:
        return -1

    token = buf.create_string_from_offset(token_start, token_len)
    return 0


fn is_complete[origin: Origin](mut buf: BufferView[origin], last_len: Int) -> Int:
    var ret_cnt = 0
    var start_offset = 0 if last_len < 3 else last_len - 3
    var scan_buf = BufferView(buf.data, start_offset)

    while not scan_buf.is_empty():
        var byte = scan_buf.get_byte()
        if not byte:
            return -2

        if byte.value() == BytesConstant.CR:
            var next = scan_buf.peek()
            if not next:
                return -2
            if next.value() != BytesConstant.LF:
                return -1
            scan_buf.advance()
            ret_cnt += 1
        elif byte.value() == BytesConstant.LF:
            ret_cnt += 1
        else:
            ret_cnt = 0

        if ret_cnt == 2:
            return 0

    return -2


fn parse_token[
    origin: Origin
](mut buf: BufferView[origin], mut token: String, mut token_len: Int, next_char: UInt8,) -> Int:
    var buf_start = buf.offset

    while not buf.is_empty():
        var byte = buf.peek()
        if not byte:
            return -2

        if byte.value() == next_char:
            token_len = buf.offset - buf_start
            token = buf.create_string_from_offset(buf_start, token_len)
            return 0
        elif not is_token_char(byte.value()):
            return -1
        buf.advance()

    return -2


fn parse_http_version[origin: Origin](mut buf: BufferView[origin], mut minor_version: Int) -> Int:
    if buf.remaining() < 9:
        return -2

    var checks = List[UInt8](capacity=7)
    checks.append(BytesConstant.H)
    checks.append(BytesConstant.T)
    checks.append(BytesConstant.T)
    checks.append(BytesConstant.P)
    checks.append(BytesConstant.SLASH)
    checks.append(BytesConstant.ONE)
    checks.append(BytesConstant.DOT)

    for i in range(len(checks)):
        var byte = buf.get_byte()
        if not byte or byte.value() != checks[i]:
            return -1

    var version_byte = buf.peek()
    if not version_byte:
        return -2

    if version_byte.value() < BytesConstant.ZERO or version_byte.value() > BytesConstant.NINE:
        return -1

    minor_version = Int(version_byte.value() - BytesConstant.ZERO)
    buf.advance()
    return 0


fn parse_headers[
    buf_origin: Origin, header_origin: MutOrigin
](
    mut buf: BufferView[buf_origin],
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    max_headers: Int,
) -> Int:
    while not buf.is_empty():
        var byte = buf.peek()
        if not byte:
            return -2

        if byte.value() == BytesConstant.CR:
            buf.advance()
            var next = buf.peek()
            if not next:
                return -2
            if next.value() != BytesConstant.LF:
                return -1
            buf.advance()
            return 0
        elif byte.value() == BytesConstant.LF:
            buf.advance()
            return 0

        if num_headers >= max_headers:
            return -1

        if num_headers == 0 or (byte.value() != BytesConstant.whitespace and byte.value() != BytesConstant.TAB):
            var name = String()
            var name_len = 0
            var ret = parse_token(buf, name, name_len, BytesConstant.COLON)
            if ret != 0 or name_len == 0:
                return -1 if ret == 0 else ret

            headers[num_headers].name = name
            headers[num_headers].name_len = name_len
            buf.advance()

            while not buf.is_empty():
                var ws = buf.peek()
                if not ws:
                    break
                if ws.value() != BytesConstant.whitespace and ws.value() != BytesConstant.TAB:
                    break
                buf.advance()
        else:
            headers[num_headers].name = String()
            headers[num_headers].name_len = 0

        var value = String()
        var value_len = 0
        var ret = get_token_to_eol(buf, value, value_len)
        if ret != 0:
            return ret

        while value_len > 0:
            var c = value[value_len - 1]
            ref c_byte = c.as_bytes()[0]
            if c_byte != BytesConstant.whitespace and c_byte != BytesConstant.TAB:
                break
            value_len -= 1

        headers[num_headers].value = String(value[:value_len]) if value_len < len(value) else value
        headers[num_headers].value_len = value_len
        num_headers += 1

    return -2


fn http_parse_request[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    mut method: String,
    mut path: String,
    mut minor_version: Int,
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    var max_headers = num_headers

    method = String()
    var method_len = 0
    path = String()
    minor_version = -1
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = BufferView(buf_span)

    if last_len != 0:
        var ret = is_complete(buf, last_len)
        if ret != 0:
            return ret

    while not buf.is_empty():
        var byte = buf.peek()
        if not byte:
            return -2

        if byte.value() == BytesConstant.CR:
            buf.advance()
            var next = buf.peek()
            if not next:
                return -2
            if next.value() != BytesConstant.LF:
                break
            buf.advance()
        elif byte.value() == BytesConstant.LF:
            buf.advance()
        else:
            break

    var ret = parse_token(buf, method, method_len, BytesConstant.whitespace)
    if ret != 0:
        return ret

    buf.advance()

    while not buf.is_empty():
        var byte = buf.peek()
        if not byte or byte.value() != BytesConstant.whitespace:
            break
        buf.advance()

    var path_start = buf.offset
    while not buf.is_empty():
        var byte = buf.peek()
        if not byte:
            return -2

        if byte.value() == BytesConstant.whitespace:
            break

        if not is_printable_ascii(byte.value()):
            if byte.value() < 0x20 or byte.value() == 0x7F:
                return -1
        buf.advance()

    if buf.is_empty():
        return -2

    path_len = buf.offset - path_start
    path = buf.create_string_from_offset(path_start, path_len)

    while not buf.is_empty():
        var byte = buf.peek()
        if not byte or byte.value() != BytesConstant.whitespace:
            break
        buf.advance()

    if buf.is_empty():
        return -2

    if method_len == 0 or path_len == 0:
        return -1

    ret = parse_http_version(buf, minor_version)
    if ret != 0:
        return ret

    if buf.is_empty():
        return -2

    var byte = buf.peek()
    if not byte:
        return -2

    if byte.value() == BytesConstant.CR:
        buf.advance()
        var next = buf.peek()
        if not next:
            return -2
        if next.value() != BytesConstant.LF:
            return -1
        buf.advance()
    elif byte.value() == BytesConstant.LF:
        buf.advance()
    else:
        return -1

    ret = parse_headers(buf, headers, num_headers, max_headers)
    if ret != 0:
        return ret

    return buf.offset


fn http_parse_response[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    mut minor_version: Int,
    mut status: Int,
    mut msg: String,
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    var max_headers = num_headers

    minor_version = -1
    status = 0
    msg = String()
    var msg_len = 0
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = BufferView(buf_span)

    if last_len != 0:
        var ret = is_complete(buf, last_len)
        if ret != 0:
            return ret

    var ret = parse_http_version(buf, minor_version)
    if ret != 0:
        return ret

    var byte = buf.peek()
    if not byte or byte.value() != BytesConstant.whitespace:
        return -1

    while not buf.is_empty():
        byte = buf.peek()
        if not byte or byte.value() != BytesConstant.whitespace:
            break
        buf.advance()

    if buf.remaining() < 4:
        return -2

    status = 0
    for _ in range(3):
        byte = buf.get_byte()
        if not byte:
            return -2
        if byte.value() < BytesConstant.ZERO or byte.value() > BytesConstant.NINE:
            return -1
        status = status * 10 + Int(byte.value() - BytesConstant.ZERO)

    ret = get_token_to_eol(buf, msg, msg_len)
    if ret != 0:
        return ret

    if msg_len > 0 and msg[0] == " ":
        var i = 0
        while i < msg_len and msg[i] == " ":
            i += 1
        msg = String(msg[i:])
        msg_len -= i
    elif msg_len > 0 and msg[0] != String(" "):
        return -1

    ret = parse_headers(buf, headers, num_headers, max_headers)
    if ret != 0:
        return ret

    return buf.offset


fn http_parse_headers[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    var max_headers = num_headers
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = BufferView(buf_span)

    if last_len != 0:
        var ret = is_complete(buf, last_len)
        if ret != 0:
            return ret

    var ret = parse_headers(buf, headers, num_headers, max_headers)
    if ret != 0:
        return ret

    return buf.offset
