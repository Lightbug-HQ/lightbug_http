from lightbug_http.http.parsing import (
    HTTPHeader,
    http_parse_headers,
    http_parse_request_headers,
    http_parse_response_headers,
)
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter, byte, is_newline, is_space
from lightbug_http.strings import CR, LF, BytesConstant, lineBreak
from memory import Span
from utils import Variant


struct HeaderKey:
    """Standard HTTP header key constants (lowercase for normalization)."""

    # General Headers
    comptime CONNECTION = "connection"
    comptime DATE = "date"
    comptime TRAILER = "trailer"
    comptime TRANSFER_ENCODING = "transfer-encoding"
    comptime UPGRADE = "upgrade"
    comptime VIA = "via"
    comptime WARNING = "warning"

    # Request Headers
    comptime ACCEPT = "accept"
    comptime ACCEPT_CHARSET = "accept-charset"
    comptime ACCEPT_ENCODING = "accept-encoding"
    comptime ACCEPT_LANGUAGE = "accept-language"
    comptime AUTHORIZATION = "authorization"
    comptime EXPECT = "expect"
    comptime FROM = "from"
    comptime HOST = "host"
    comptime IF_MATCH = "if-match"
    comptime IF_MODIFIED_SINCE = "if-modified-since"
    comptime IF_NONE_MATCH = "if-none-match"
    comptime IF_RANGE = "if-range"
    comptime IF_UNMODIFIED_SINCE = "if-unmodified-since"
    comptime MAX_FORWARDS = "max-forwards"
    comptime PROXY_AUTHORIZATION = "proxy-authorization"
    comptime RANGE = "range"
    comptime REFERER = "referer"
    comptime TE = "te"
    comptime USER_AGENT = "user-agent"

    # Response Headers
    comptime ACCEPT_RANGES = "accept-ranges"
    comptime AGE = "age"
    comptime ETAG = "etag"
    comptime LOCATION = "location"
    comptime PROXY_AUTHENTICATE = "proxy-authenticate"
    comptime RETRY_AFTER = "retry-after"
    comptime SERVER = "server"
    comptime VARY = "vary"
    comptime WWW_AUTHENTICATE = "www-authenticate"

    # Entity Headers (Content)
    comptime ALLOW = "allow"
    comptime CONTENT_ENCODING = "content-encoding"
    comptime CONTENT_LANGUAGE = "content-language"
    comptime CONTENT_LENGTH = "content-length"
    comptime CONTENT_LOCATION = "content-location"
    comptime CONTENT_MD5 = "content-md5"
    comptime CONTENT_RANGE = "content-range"
    comptime CONTENT_TYPE = "content-type"
    comptime CONTENT_DISPOSITION = "content-disposition"
    comptime EXPIRES = "expires"
    comptime LAST_MODIFIED = "last-modified"

    # Caching Headers
    comptime CACHE_CONTROL = "cache-control"
    comptime PRAGMA = "pragma"

    # Cookie Headers
    comptime COOKIE = "cookie"
    comptime SET_COOKIE = "set-cookie"

    # CORS Headers
    comptime ACCESS_CONTROL_ALLOW_ORIGIN = "access-control-allow-origin"
    comptime ACCESS_CONTROL_ALLOW_CREDENTIALS = "access-control-allow-credentials"
    comptime ACCESS_CONTROL_ALLOW_HEADERS = "access-control-allow-headers"
    comptime ACCESS_CONTROL_ALLOW_METHODS = "access-control-allow-methods"
    comptime ACCESS_CONTROL_EXPOSE_HEADERS = "access-control-expose-headers"
    comptime ACCESS_CONTROL_MAX_AGE = "access-control-max-age"
    comptime ACCESS_CONTROL_REQUEST_HEADERS = "access-control-request-headers"
    comptime ACCESS_CONTROL_REQUEST_METHOD = "access-control-request-method"
    comptime ORIGIN = "origin"

    # Security Headers
    comptime STRICT_TRANSPORT_SECURITY = "strict-transport-security"
    comptime CONTENT_SECURITY_POLICY = "content-security-policy"
    comptime CONTENT_SECURITY_POLICY_REPORT_ONLY = "content-security-policy-report-only"
    comptime X_CONTENT_TYPE_OPTIONS = "x-content-type-options"
    comptime X_FRAME_OPTIONS = "x-frame-options"
    comptime X_XSS_PROTECTION = "x-xss-protection"
    comptime REFERRER_POLICY = "referrer-policy"
    comptime PERMISSIONS_POLICY = "permissions-policy"
    comptime CROSS_ORIGIN_EMBEDDER_POLICY = "cross-origin-embedder-policy"
    comptime CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY = "cross-origin-embedder-policy-report-only"
    comptime CROSS_ORIGIN_OPENER_POLICY = "cross-origin-opener-policy"
    comptime CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY = "cross-origin-opener-policy-report-only"
    comptime CROSS_ORIGIN_RESOURCE_POLICY = "cross-origin-resource-policy"

    # Other Common Headers
    comptime LINK = "link"
    comptime KEEP_ALIVE = "keep-alive"
    comptime PROXY_CONNECTION = "proxy-connection"
    comptime ALT_SVC = "alt-svc"


@fieldwise_init
@register_passable("trivial")
struct HeaderKeyNotFoundError(Movable, Stringable, Writable):
    """Error raised when a header key is not found."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("HeaderKeyNotFoundError: Key not found in headers")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct InvalidHTTPRequestError(Movable, Stringable, Writable):
    """Error raised when the HTTP request is malformed."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("InvalidHTTPRequestError: Not a valid HTTP request")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct IncompleteHTTPRequestError(Movable, Stringable, Writable):
    """Error raised when the HTTP request is incomplete (need more data)."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("IncompleteHTTPRequestError: Incomplete HTTP request")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct InvalidHTTPResponseError(Movable, Stringable, Writable):
    """Error raised when the HTTP response is malformed."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("InvalidHTTPResponseError: Not a valid HTTP response")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct IncompleteHTTPResponseError(Movable, Stringable, Writable):
    """Error raised when the HTTP response is incomplete."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("IncompleteHTTPResponseError: Incomplete HTTP response")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct EmptyBufferError(Movable, Stringable, Writable):
    """Error raised when buffer has no data available."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("EmptyBufferError: No data available in buffer")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct RequestParseError(Movable, Stringable, Writable):
    """Error variant for HTTP request parsing.

    Can be InvalidHTTPRequestError, IncompleteHTTPRequestError, or EmptyBufferError.
    """

    comptime type = Variant[InvalidHTTPRequestError, IncompleteHTTPRequestError, EmptyBufferError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: InvalidHTTPRequestError):
        self.value = value

    @implicit
    fn __init__(out self, value: IncompleteHTTPRequestError):
        self.value = value

    @implicit
    fn __init__(out self, value: EmptyBufferError):
        self.value = value

    fn is_incomplete(self) -> Bool:
        """Returns True if this error indicates we need more data."""
        return self.value.isa[IncompleteHTTPRequestError]()

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[InvalidHTTPRequestError]():
            writer.write(self.value[InvalidHTTPRequestError])
        elif self.value.isa[IncompleteHTTPRequestError]():
            writer.write(self.value[IncompleteHTTPRequestError])
        elif self.value.isa[EmptyBufferError]():
            writer.write(self.value[EmptyBufferError])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct ResponseParseError(Movable, Stringable, Writable):
    """Error variant for HTTP response parsing."""

    comptime type = Variant[InvalidHTTPResponseError, IncompleteHTTPResponseError, EmptyBufferError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: InvalidHTTPResponseError):
        self.value = value

    @implicit
    fn __init__(out self, value: IncompleteHTTPResponseError):
        self.value = value

    @implicit
    fn __init__(out self, value: EmptyBufferError):
        self.value = value

    fn is_incomplete(self) -> Bool:
        """Returns True if this error indicates we need more data."""
        return self.value.isa[IncompleteHTTPResponseError]()

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[InvalidHTTPResponseError]():
            writer.write(self.value[InvalidHTTPResponseError])
        elif self.value.isa[IncompleteHTTPResponseError]():
            writer.write(self.value[IncompleteHTTPResponseError])
        elif self.value.isa[EmptyBufferError]():
            writer.write(self.value[EmptyBufferError])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct ParsedRequestHeaders(Movable):
    """Result of parsing HTTP request headers.

    This contains all information extracted from the request line and headers,
    along with the number of bytes consumed from the input buffer.
    """

    var method: String
    var path: String
    var protocol: String
    var headers: Headers
    var cookies: List[String]
    var bytes_consumed: Int
    """Number of bytes consumed from the input buffer (includes the final \\r\\n\\r\\n)."""

    fn content_length(self) -> Int:
        """Get the Content-Length header value, or 0 if not present."""
        return self.headers.content_length()

    fn expects_body(self) -> Bool:
        """Check if this request expects a body based on method and Content-Length."""
        var cl = self.content_length()
        if cl > 0:
            return True
        if self.method == "POST" or self.method == "PUT" or self.method == "PATCH":
            var te = self.headers.get(HeaderKey.TRANSFER_ENCODING)
            if te and "chunked" in te.value():
                return True
        return False


@fieldwise_init
struct ParsedResponseHeaders(Movable):
    """Result of parsing HTTP response headers."""

    var protocol: String
    var status: Int
    var status_message: String
    var headers: Headers
    var cookies: List[String]
    var bytes_consumed: Int


@fieldwise_init
struct Header(Copyable, Stringable, Writable):
    """A single HTTP header key-value pair."""

    var key: String
    var value: String

    fn __str__(self) -> String:
        return String.write(self)

    fn write_to[T: Writer, //](self, mut writer: T):
        writer.write(self.key, ": ", self.value, lineBreak)


@always_inline
fn write_header[T: Writer](mut writer: T, key: String, value: String):
    """Write a header in HTTP format to a writer."""
    writer.write(key, ": ", value, lineBreak)


fn encode_latin1_header_value(value: String) -> List[UInt8]:
    """Transcode a header value from UTF-8 to ISO-8859-1 bytes.

    HTTP/1.1 header field values must be representable in ISO-8859-1 (RFC 7230 §3.2).
    - Codepoints U+0000–U+007F: single byte, passed through unchanged.
    - Codepoints U+0080–U+00FF: encoded as their single ISO-8859-1 byte.
    - Codepoints above U+00FF: cannot be represented in ISO-8859-1; the raw UTF-8
      bytes are written as-is (best-effort fallback — use RFC 5987 encoding instead).
    - Invalid UTF-8 byte sequences (obs-text from parsing): passed through as-is.
    """
    var utf8 = value.as_bytes()
    var out = List[UInt8](capacity=len(utf8))
    var i = 0
    while i < len(utf8):
        var b = utf8[i]
        if b < 0x80:
            out.append(b)
            i += 1
        else:
            var seq_len = 0
            var codepoint = 0
            if b >= 0xC2 and b <= 0xDF and i + 1 < len(utf8):
                var b2 = utf8[i + 1]
                if b2 >= 0x80 and b2 <= 0xBF:
                    seq_len = 2
                    codepoint = ((Int(b) & 0x1F) << 6) | (Int(b2) & 0x3F)
            elif b >= 0xE0 and b <= 0xEF and i + 2 < len(utf8):
                var b2 = utf8[i + 1]
                var b3 = utf8[i + 2]
                if b2 >= 0x80 and b2 <= 0xBF and b3 >= 0x80 and b3 <= 0xBF:
                    seq_len = 3
                    codepoint = ((Int(b) & 0x0F) << 12) | ((Int(b2) & 0x3F) << 6) | (Int(b3) & 0x3F)
            elif b >= 0xF0 and b <= 0xF7 and i + 3 < len(utf8):
                var b2 = utf8[i + 1]
                var b3 = utf8[i + 2]
                var b4 = utf8[i + 3]
                if b2 >= 0x80 and b2 <= 0xBF and b3 >= 0x80 and b3 <= 0xBF and b4 >= 0x80 and b4 <= 0xBF:
                    seq_len = 4
                    codepoint = ((Int(b) & 0x07) << 18) | ((Int(b2) & 0x3F) << 12) | ((Int(b3) & 0x3F) << 6) | (Int(b4) & 0x3F)

            if seq_len > 0 and codepoint <= 0xFF:
                # Valid UTF-8, codepoint fits in ISO-8859-1: encode as single byte.
                out.append(UInt8(codepoint))
                i += seq_len
            elif seq_len > 0:
                # Valid UTF-8 but codepoint > U+00FF: pass raw UTF-8 bytes through.
                for j in range(seq_len):
                    out.append(utf8[i + j])
                i += seq_len
            else:
                # Not valid UTF-8 (obs-text or stray continuation byte): pass through.
                out.append(b)
                i += 1
    return out^


fn write_header_latin1(mut writer: ByteWriter, key: String, value: String):
    """Write a header with the value transcoded to ISO-8859-1.

    Equivalent to write_header but converts multi-byte UTF-8 sequences for
    codepoints U+0080–U+00FF to their single ISO-8859-1 byte before writing.
    See encode_latin1_header_value for full encoding rules.
    """
    writer.write(key, ": ")
    writer.consuming_write(encode_latin1_header_value(value))
    writer.write(lineBreak)


@fieldwise_init
struct Headers(Copyable, Stringable, Writable):
    """Collection of HTTP headers.

    Header keys are normalized to lowercase for case-insensitive lookup.
    """

    var _inner: Dict[String, String]

    fn __init__(out self):
        self._inner = Dict[String, String]()

    fn __init__(out self, var *headers: Header):
        self._inner = Dict[String, String]()
        for header in headers:
            self[header.key.lower()] = header.value

    @always_inline
    fn empty(self) -> Bool:
        return len(self._inner) == 0

    @always_inline
    fn __contains__(self, key: String) -> Bool:
        return key.lower() in self._inner

    @always_inline
    fn __getitem__(self, key: String) raises HeaderKeyNotFoundError -> String:
        try:
            return self._inner[key.lower()]
        except:
            raise HeaderKeyNotFoundError()

    @always_inline
    fn get(self, key: String) -> Optional[String]:
        return self._inner.get(key.lower())

    @always_inline
    fn __setitem__(mut self, key: String, value: String):
        self._inner[key.lower()] = value

    fn content_length(self) -> Int:
        """Get Content-Length header value, or 0 if not present/invalid."""
        var value = self._inner.get(HeaderKey.CONTENT_LENGTH)
        if not value:
            return 0
        try:
            return Int(value.value())
        except:
            return 0

    fn write_to[T: Writer, //](self, mut writer: T):
        for header in self._inner.items():
            write_header(writer, header.key, header.value)

    fn write_latin1_to(self, mut writer: ByteWriter):
        """Write headers with values transcoded to ISO-8859-1 for HTTP wire format."""
        for header in self._inner.items():
            write_header_latin1(writer, header.key, header.value)

    fn __str__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: Headers) -> Bool:
        if len(self._inner) != len(other._inner):
            return False
        for item in self._inner.items():
            var other_val = other._inner.get(item.key)
            if not other_val or other_val.value() != item.value:
                return False
        return True


fn parse_request_headers(
    buffer: Span[Byte],
    last_len: Int = 0,
) raises RequestParseError -> ParsedRequestHeaders:
    """Parse HTTP request headers from a buffer.

    This function parses the request line (method, path, protocol) and all headers
    from the given buffer. It uses incremental parsing - if the request is incomplete,
    it raises IncompleteHTTPRequestError.

    Args:
        buffer: The buffer containing the HTTP request data.
        last_len: Number of bytes that were already parsed in a previous call.
                  Use 0 for first parse attempt, or the previous buffer length
                  for incremental parsing.

    Returns:
        ParsedRequestHeaders containing all parsed information and bytes consumed.

    Raises:
        RequestParseError: If parsing fails (invalid or incomplete request).
    """
    if len(buffer) == 0:
        raise RequestParseError(EmptyBufferError())

    var method = String()
    var path = String()
    var minor_version = -1
    var max_headers = 100
    var headers_array = InlineArray[HTTPHeader, 100](fill=HTTPHeader())
    var num_headers = max_headers

    var ret = http_parse_request_headers(
        buffer.unsafe_ptr(),
        len(buffer),
        method,
        path,
        minor_version,
        headers_array,
        num_headers,
        last_len,
    )

    if ret < 0:
        if ret == -1:
            raise RequestParseError(InvalidHTTPRequestError())
        else:  # ret == -2
            raise RequestParseError(IncompleteHTTPRequestError())

    var headers = Headers()
    var cookies = List[String]()

    for i in range(num_headers):
        var key = headers_array[i].name.lower()
        var value = headers_array[i].value

        if key == HeaderKey.SET_COOKIE or key == HeaderKey.COOKIE:
            cookies.append(value)
        else:
            headers._inner[key] = value

    var protocol = String("HTTP/1.", minor_version)

    return ParsedRequestHeaders(
        method=method^,
        path=path^,
        protocol=protocol^,
        headers=headers^,
        cookies=cookies^,
        bytes_consumed=ret,
    )


fn parse_response_headers(
    buffer: Span[Byte],
    last_len: Int = 0,
) raises ResponseParseError -> ParsedResponseHeaders:
    """Parse HTTP response headers from a buffer.

    Args:
        buffer: The buffer containing the HTTP response data.
        last_len: Number of bytes already parsed in previous call (0 for first attempt).

    Returns:
        ParsedResponseHeaders containing all parsed information and bytes consumed.

    Raises:
        ResponseParseError: If parsing fails (invalid or incomplete response).
    """
    if len(buffer) == 0:
        raise ResponseParseError(EmptyBufferError())

    if len(buffer) < 5:
        raise ResponseParseError(IncompleteHTTPResponseError())

    if not (
        buffer[0] == BytesConstant.H
        and buffer[1] == BytesConstant.T
        and buffer[2] == BytesConstant.T
        and buffer[3] == BytesConstant.P
        and buffer[4] == BytesConstant.SLASH
    ):
        raise ResponseParseError(InvalidHTTPResponseError())

    var minor_version = -1
    var status = 0
    var msg = String()
    var max_headers = 100
    var headers_array = InlineArray[HTTPHeader, 100](fill=HTTPHeader())
    var num_headers = max_headers

    var ret = http_parse_response_headers(
        buffer.unsafe_ptr(),
        len(buffer),
        minor_version,
        status,
        msg,
        headers_array,
        num_headers,
        last_len,
    )

    if ret < 0:
        if ret == -1:
            raise ResponseParseError(InvalidHTTPResponseError())
        else:  # ret == -2
            raise ResponseParseError(IncompleteHTTPResponseError())

    # Build headers dict and extract cookies
    var headers = Headers()
    var cookies = List[String]()

    for i in range(num_headers):
        var key = headers_array[i].name.lower()
        var value = headers_array[i].value

        if key == HeaderKey.SET_COOKIE:
            cookies.append(value)
        else:
            headers._inner[key] = value

    var protocol = String("HTTP/1.", minor_version)

    return ParsedResponseHeaders(
        protocol=protocol^,
        status=status,
        status_message=msg^,
        headers=headers^,
        cookies=cookies^,
        bytes_consumed=ret,
    )


fn find_header_end(buffer: Span[Byte], search_start: Int = 0) -> Optional[Int]:
    """Find the end of HTTP headers in a buffer.

    Searches for the \\r\\n\\r\\n sequence that marks the end of headers.

    Args:
        buffer: The buffer to search.
        search_start: Offset to start searching from (optimization for incremental reads).

    Returns:
        The index of the first byte AFTER the header end sequence (\\r\\n\\r\\n),
        or None if not found.
    """
    if len(buffer) < 4:
        return None

    # Adjust search start to account for partial matches at boundary
    var actual_start = search_start
    if actual_start > 3:
        actual_start -= 3

    var i = actual_start
    while i <= len(buffer) - 4:
        if (
            buffer[i] == BytesConstant.CR
            and buffer[i + 1] == BytesConstant.LF
            and buffer[i + 2] == BytesConstant.CR
            and buffer[i + 3] == BytesConstant.LF
        ):
            return i + 4
        i += 1

    return None
