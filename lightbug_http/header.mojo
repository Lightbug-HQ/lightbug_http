from lightbug_http.http.parsing import HTTPHeader, http_parse_headers, http_parse_request, http_parse_response
from lightbug_http.io.bytes import ByteReader, Bytes, byte, is_newline, is_space
from lightbug_http.strings import CR, LF, BytesConstant, lineBreak


struct HeaderKey:
    # TODO: Fill in more of these
    comptime CONNECTION = "connection"
    comptime CONTENT_TYPE = "content-type"
    comptime CONTENT_LENGTH = "content-length"
    comptime CONTENT_ENCODING = "content-encoding"
    comptime TRANSFER_ENCODING = "transfer-encoding"
    comptime DATE = "date"
    comptime LOCATION = "location"
    comptime HOST = "host"
    comptime SERVER = "server"
    comptime SET_COOKIE = "set-cookie"
    comptime COOKIE = "cookie"


@fieldwise_init
struct Header(Copyable, Stringable, Writable):
    var key: String
    var value: String

    fn __str__(self) -> String:
        return String.write(self)

    fn write_to[T: Writer, //](self, mut writer: T):
        writer.write(self.key + ": ", self.value, lineBreak)


@always_inline
fn write_header[T: Writer](mut writer: T, key: String, value: String):
    writer.write(key + ": ", value, lineBreak)


@fieldwise_init
struct ParsedRequestResult(Movable):
    var method: String
    var path: String
    var protocol: String
    var cookies: List[String]


@fieldwise_init
struct ParsedResponseResult(Movable):
    var protocol: String
    var status: Int
    var msg: String
    var cookies: List[String]


@fieldwise_init
struct Headers(Copyable, Stringable, Writable):
    """Represents the header key/values in an http request/response.

    Header keys are normalized to lowercase
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
    fn __getitem__(self, key: String) raises -> String:
        try:
            return self._inner[key.lower()]
        except:
            raise Error("KeyError: Key not found in headers: " + key)

    @always_inline
    fn get(self, key: String) -> Optional[String]:
        return self._inner.get(key.lower())

    @always_inline
    fn __setitem__(mut self, key: String, value: String):
        self._inner[key.lower()] = value

    fn content_length(self) -> Int:
        try:
            return Int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw_request(mut self, mut reader: ByteReader, out result: ParsedRequestResult) raises:
        """Parse HTTP request using picohttpparser."""
        if self.check_if_response(reader):
            raise Error("Headers.parse_raw: Not a valid HTTP request.")

        var method = String()
        var path = String()
        var minor_version = -1

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = InlineArray[HTTPHeader, 100](fill=HTTPHeader())

        var num_headers = max_headers
        var ret = http_parse_request(
            reader.as_bytes().unsafe_ptr(),
            len(reader),
            method,
            path,
            minor_version,
            headers,
            num_headers,
            0,  # last_len (0 for first parse)
        )

        if ret < 0:
            if ret == -1:
                raise Error("Headers.parse_raw: Invalid HTTP request")
            else:  # ret == -2
                raise Error("Headers.parse_raw: Incomplete HTTP request")

        # Extract headers and cookies
        var cookies = List[String]()
        for i in range(num_headers):
            var key = headers[i].name.lower()
            var value = headers[i].value

            if key == HeaderKey.SET_COOKIE or key == HeaderKey.COOKIE:
                cookies.append(value)
            else:
                self._inner[key] = value

        # Build protocol string
        reader.read_pos += ret
        result = ParsedRequestResult(method^, path^, String("HTTP/1.", minor_version), cookies^)

    fn parse_raw_response(mut self, mut reader: ByteReader, out result: ParsedResponseResult) raises:
        """Parse HTTP response using picohttpparser."""
        if not self.check_if_response(reader):
            raise Error("Headers.parse_raw: Not a valid HTTP response.")

        var minor_version = -1
        var status = 0
        var msg = String()

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = InlineArray[HTTPHeader, 100](fill=HTTPHeader())
        var num_headers = max_headers
        var ret = http_parse_response(
            reader.as_bytes().unsafe_ptr(),
            len(reader),
            minor_version,
            status,
            msg,
            headers,
            num_headers,
            0,  # last_len (0 for first parse)
        )

        if ret < 0:
            if ret == -1:
                raise Error("Headers.parse_raw: Invalid HTTP response")
            else:  # ret == -2
                raise Error("Headers.parse_raw: Incomplete HTTP response")

        # Extract headers and cookies
        var cookies = List[String]()
        for i in range(num_headers):
            var key = headers[i].name.lower()
            var value = headers[i].value

            if key == HeaderKey.SET_COOKIE:
                cookies.append(value)
            else:
                self._inner[key] = value

        # Build protocol string
        var protocol = String("HTTP/1.", minor_version)
        reader.read_pos += ret
        result = ParsedResponseResult(protocol^, status, msg^, cookies^)

    fn check_if_response(mut self, r: ByteReader) raises -> Bool:
        if not r.available():
            raise Error("Headers.parse_raw: Failed to read first byte from response header.")

        # Check if starts with "HTTP/" (response) or method name (request)
        var buf_span = r.as_bytes()
        return (
            len(buf_span) >= 5
            and buf_span[0] == BytesConstant.H
            and buf_span[1] == BytesConstant.T
            and buf_span[2] == BytesConstant.T
            and buf_span[3] == BytesConstant.P
            and buf_span[4] == BytesConstant.SLASH
        )

    fn write_to[T: Writer, //](self, mut writer: T):
        for header in self._inner.items():
            write_header(writer, header.key, header.value)

    fn __str__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: Headers) -> Bool:
        if len(self._inner) != len(other._inner):
            return False

        for value in self._inner.items():
            for other_value in other._inner.items():
                if value.key != other_value.key or value.value != other_value.value:
                    return False
        return True
