from lightbug_http.io.bytes import ByteReader, Bytes, create_string_from_ptr
from lightbug_http.strings import BytesConstant, is_printable_ascii, is_token_char
from utils import Variant


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


@fieldwise_init
@register_passable("trivial")
struct ParseError(Movable, Stringable, Writable):
    """Invalid HTTP syntax error."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("ParseError: Invalid HTTP syntax")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct IncompleteError(Movable, Stringable, Writable):
    """Need more data to complete parsing."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("IncompleteError: Need more data")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct HTTPParseError(Movable, Stringable, Writable):
    """Error variant for HTTP parsing operations."""

    comptime type = Variant[ParseError, IncompleteError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: ParseError):
        self.value = value

    @implicit
    fn __init__(out self, value: IncompleteError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[ParseError]():
            writer.write(self.value[ParseError])
        elif self.value.isa[IncompleteError]():
            writer.write(self.value[IncompleteError])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


fn try_peek[origin: ImmutOrigin](reader: ByteReader[origin]) -> Optional[UInt8]:
    """Try to peek at current byte, returns None if unavailable."""
    if reader.available():
        try:
            return reader.peek()
        except:
            return None
    return None


fn try_peek_at[origin: ImmutOrigin](reader: ByteReader[origin], offset: Int) -> Optional[UInt8]:
    """Try to peek at byte at relative offset, returns None if out of bounds."""
    var abs_pos = reader.read_pos + offset
    if abs_pos < len(reader._inner):
        return reader._inner[abs_pos]
    return None


fn try_get_byte[origin: ImmutOrigin](mut reader: ByteReader[origin]) -> Optional[UInt8]:
    """Try to get current byte and advance, returns None if unavailable."""
    if reader.available():
        var byte = reader._inner[reader.read_pos]
        reader.increment()
        return byte
    return None


fn create_string_from_reader[origin: ImmutOrigin](reader: ByteReader[origin], start_offset: Int, length: Int) -> String:
    """Create a string from a range in the reader."""
    if start_offset >= 0 and start_offset + length <= len(reader._inner):
        var ptr = reader._inner.unsafe_ptr() + start_offset
        return create_string_from_ptr(ptr, length)
    return String()


fn get_token_to_eol[
    origin: ImmutOrigin
](mut buf: ByteReader[origin], mut token: String, mut token_len: Int) raises HTTPParseError:
    var token_start = buf.read_pos

    while buf.available():
        var byte = try_peek(buf)
        if not byte:
            raise IncompleteError()

        var c = byte.value()
        if not is_printable_ascii(c):
            if (c < 0x20 and c != 0x09) or c == 0x7F:
                break
        buf.increment()

    if not buf.available():
        raise IncompleteError()

    var current_byte = try_peek(buf)
    if not current_byte:
        raise IncompleteError()

    if current_byte.value() == BytesConstant.CR:
        buf.increment()
        var next_byte = try_peek(buf)
        if not next_byte or next_byte.value() != BytesConstant.LF:
            raise ParseError()
        token_len = buf.read_pos - 1 - token_start
        buf.increment()
    elif current_byte.value() == BytesConstant.LF:
        token_len = buf.read_pos - token_start
        buf.increment()
    else:
        raise ParseError()

    token = create_string_from_reader(buf, token_start, token_len)


fn is_complete[origin: ImmutOrigin](mut buf: ByteReader[origin], last_len: Int) raises HTTPParseError:
    var ret_cnt = 0
    var start_offset = 0 if last_len < 3 else last_len - 3

    var scan_buf = ByteReader(buf._inner)
    scan_buf.read_pos = start_offset

    while scan_buf.available():
        var byte = try_get_byte(scan_buf)
        if not byte:
            raise IncompleteError()

        if byte.value() == BytesConstant.CR:
            var next = try_peek(scan_buf)
            if not next:
                raise IncompleteError()
            if next.value() != BytesConstant.LF:
                raise ParseError()
            scan_buf.increment()
            ret_cnt += 1
        elif byte.value() == BytesConstant.LF:
            ret_cnt += 1
        else:
            ret_cnt = 0

        if ret_cnt == 2:
            return

    raise IncompleteError()


fn parse_token[
    origin: ImmutOrigin
](mut buf: ByteReader[origin], mut token: String, mut token_len: Int, next_char: UInt8,) raises HTTPParseError:
    var buf_start = buf.read_pos

    while buf.available():
        var byte = try_peek(buf)
        if not byte:
            raise IncompleteError()

        if byte.value() == next_char:
            token_len = buf.read_pos - buf_start
            token = create_string_from_reader(buf, buf_start, token_len)
            return
        elif not is_token_char(byte.value()):
            raise ParseError()
        buf.increment()

    raise IncompleteError()


fn parse_http_version[origin: ImmutOrigin](mut buf: ByteReader[origin], mut minor_version: Int) raises HTTPParseError:
    if buf.remaining() < 9:
        raise IncompleteError()

    var checks = List[UInt8](capacity=7)
    checks.append(BytesConstant.H)
    checks.append(BytesConstant.T)
    checks.append(BytesConstant.T)
    checks.append(BytesConstant.P)
    checks.append(BytesConstant.SLASH)
    checks.append(BytesConstant.ONE)
    checks.append(BytesConstant.DOT)

    for i in range(len(checks)):
        var byte = try_get_byte(buf)
        if not byte or byte.value() != checks[i]:
            raise ParseError()

    var version_byte = try_peek(buf)
    if not version_byte:
        raise IncompleteError()

    if version_byte.value() < BytesConstant.ZERO or version_byte.value() > BytesConstant.NINE:
        raise ParseError()

    minor_version = Int(version_byte.value() - BytesConstant.ZERO)
    buf.increment()


fn parse_headers[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    mut buf: ByteReader[buf_origin],
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    max_headers: Int,
) raises HTTPParseError:
    while buf.available():
        var byte = try_peek(buf)
        if not byte:
            raise IncompleteError()

        if byte.value() == BytesConstant.CR:
            buf.increment()
            var next = try_peek(buf)
            if not next:
                raise IncompleteError()
            if next.value() != BytesConstant.LF:
                raise ParseError()
            buf.increment()
            return
        elif byte.value() == BytesConstant.LF:
            buf.increment()
            return

        if num_headers >= max_headers:
            raise ParseError()

        if num_headers == 0 or (byte.value() != BytesConstant.whitespace and byte.value() != BytesConstant.TAB):
            var name = String()
            var name_len = 0
            parse_token(buf, name, name_len, BytesConstant.COLON)
            if name_len == 0:
                raise ParseError()

            headers[num_headers].name = name
            headers[num_headers].name_len = name_len
            buf.increment()

            while buf.available():
                var ws = try_peek(buf)
                if not ws:
                    break
                if ws.value() != BytesConstant.whitespace and ws.value() != BytesConstant.TAB:
                    break
                buf.increment()
        else:
            headers[num_headers].name = String()
            headers[num_headers].name_len = 0

        var value = String()
        var value_len = 0
        get_token_to_eol(buf, value, value_len)

        while value_len > 0:
            var c = value[value_len - 1]
            ref c_byte = c.as_bytes()[0]
            if c_byte != BytesConstant.whitespace and c_byte != BytesConstant.TAB:
                break
            value_len -= 1

        headers[num_headers].value = String(value[:value_len]) if value_len < len(value) else value
        headers[num_headers].value_len = value_len
        num_headers += 1

    raise IncompleteError()


fn http_parse_request_headers[
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
    """Parse HTTP request headers. Returns bytes consumed or negative error code."""
    var max_headers = num_headers

    method = String()
    var method_len = 0
    path = String()
    minor_version = -1
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = ByteReader(buf_span)

    try:
        if last_len != 0:
            is_complete(buf, last_len)

        while buf.available():
            var byte = try_peek(buf)
            if not byte:
                return -2

            if byte.value() == BytesConstant.CR:
                buf.increment()
                var next = try_peek(buf)
                if not next:
                    return -2
                if next.value() != BytesConstant.LF:
                    break
                buf.increment()
            elif byte.value() == BytesConstant.LF:
                buf.increment()
            else:
                break

        parse_token(buf, method, method_len, BytesConstant.whitespace)
        buf.increment()

        while buf.available():
            var byte = try_peek(buf)
            if not byte or byte.value() != BytesConstant.whitespace:
                break
            buf.increment()

        var path_start = buf.read_pos
        while buf.available():
            var byte = try_peek(buf)
            if not byte:
                return -2

            if byte.value() == BytesConstant.whitespace:
                break

            if not is_printable_ascii(byte.value()):
                if byte.value() < 0x20 or byte.value() == 0x7F:
                    return -1
            buf.increment()

        if not buf.available():
            return -2

        var path_len = buf.read_pos - path_start
        path = create_string_from_reader(buf, path_start, path_len)

        while buf.available():
            var byte = try_peek(buf)
            if not byte or byte.value() != BytesConstant.whitespace:
                break
            buf.increment()

        if not buf.available():
            return -2

        if method_len == 0 or path_len == 0:
            return -1

        parse_http_version(buf, minor_version)

        if not buf.available():
            return -2

        var byte = try_peek(buf)
        if not byte:
            return -2

        if byte.value() == BytesConstant.CR:
            buf.increment()
            var next = try_peek(buf)
            if not next:
                return -2
            if next.value() != BytesConstant.LF:
                return -1
            buf.increment()
        elif byte.value() == BytesConstant.LF:
            buf.increment()
        else:
            return -1

        parse_headers(buf, headers, num_headers, max_headers)

        return buf.read_pos
    except e:
        if e.isa[IncompleteError]():
            return -2
        else:
            return -1


fn http_parse_response_headers[
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
    """Parse HTTP response headers. Returns bytes consumed or negative error code."""
    var max_headers = num_headers

    minor_version = -1
    status = 0
    msg = String()
    var msg_len = 0
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = ByteReader(buf_span)

    try:
        if last_len != 0:
            is_complete(buf, last_len)

        parse_http_version(buf, minor_version)

        var byte = try_peek(buf)
        if not byte or byte.value() != BytesConstant.whitespace:
            return -1

        while buf.available():
            byte = try_peek(buf)
            if not byte or byte.value() != BytesConstant.whitespace:
                break
            buf.increment()

        if buf.remaining() < 4:
            return -2

        status = 0
        for _ in range(3):
            byte = try_get_byte(buf)
            if not byte:
                return -2
            if byte.value() < BytesConstant.ZERO or byte.value() > BytesConstant.NINE:
                return -1
            status = status * 10 + Int(byte.value() - BytesConstant.ZERO)

        get_token_to_eol(buf, msg, msg_len)

        if msg_len > 0 and msg[0] == " ":
            var i = 0
            while i < msg_len and msg[i] == " ":
                i += 1
            msg = String(msg[i:])
            msg_len -= i
        elif msg_len > 0 and msg[0] != String(" "):
            return -1

        parse_headers(buf, headers, num_headers, max_headers)

        return buf.read_pos
    except e:
        if e.isa[IncompleteError]():
            return -2
        else:
            return -1


fn http_parse_headers[
    buf_origin: ImmutOrigin, header_origin: MutOrigin
](
    buf_start: UnsafePointer[UInt8, buf_origin],
    len: Int,
    headers: Span[HTTPHeader, header_origin],
    mut num_headers: Int,
    last_len: Int,
) -> Int:
    """Parse only headers (for standalone header parsing). Returns bytes consumed or negative error code."""
    var max_headers = num_headers
    num_headers = 0

    var buf_span = Span[UInt8, buf_origin](ptr=buf_start, length=len)
    var buf = ByteReader(buf_span)

    try:
        if last_len != 0:
            is_complete(buf, last_len)

        parse_headers(buf, headers, num_headers, max_headers)

        return buf.read_pos
    except e:
        if e.isa[IncompleteError]():
            return -2
        else:
            return -1
