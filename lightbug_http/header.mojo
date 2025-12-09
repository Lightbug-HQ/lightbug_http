from lightbug_http._logger import logger
from lightbug_http.io.bytes import ByteReader, Bytes, byte, is_newline, is_space
from lightbug_http.pico import PhrHeader, phr_parse_headers, phr_parse_request, phr_parse_response
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

    fn _parse_raw_request[
        origin: ImmutOrigin
    ](mut self, buf: Span[UInt8, origin],) raises -> Tuple[Int, Tuple[String, String, String, List[String]]]:
        """Parse HTTP request using picohttpparser."""
        var method = String()
        var path = String()
        var minor_version = -1

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = InlineArray[PhrHeader, 100](fill=PhrHeader())
        # var headers = alloc[PhrHeader](count=max_headers)
        # for i in range(max_headers):
        #     headers[i] = PhrHeader()

        var num_headers = max_headers
        var ret = phr_parse_request(
            buf.unsafe_ptr(),
            len(buf),
            method,
            path,
            minor_version,
            headers,
            num_headers,
            0,  # last_len (0 for first parse)
        )

        if ret < 0:
            # headers.free()
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
        var protocol = String("HTTP/1.", minor_version)

        # headers.free()
        return (ret, (method, path, protocol, cookies^))

    fn _parse_raw_response[
        origin: ImmutOrigin
    ](mut self, buf: Span[UInt8, origin],) raises -> Tuple[Int, Tuple[String, String, String, List[String]]]:
        """Parse HTTP response using picohttpparser."""
        var minor_version = -1
        var status = 0
        var msg = String()

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = InlineArray[PhrHeader, 100](fill=PhrHeader())
        # var headers = alloc[PhrHeader](count=max_headers)
        # for i in range(max_headers):
        #     headers[i] = PhrHeader()

        var num_headers = max_headers
        var ret = phr_parse_response(
            buf.unsafe_ptr(),
            len(buf),
            minor_version,
            status,
            msg,
            headers,
            num_headers,
            0,  # last_len (0 for first parse)
        )

        if ret < 0:
            # headers.free()
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
        var protocol = "HTTP/1." + String(minor_version)

        # headers.free()
        return ret, (protocol, String(status), msg, cookies^)

    fn parse_raw(mut self, mut r: ByteReader) raises -> Tuple[String, String, String, List[String]]:
        if not r.available():
            raise Error("Headers.parse_raw: Failed to read first byte from response header.")

        # Create buffer from ByteReader's remaining data
        var buf_span = r.as_bytes()

        # Check if starts with "HTTP/" (response) or method name (request)
        comptime _H = byte["H"]()
        comptime _T = byte["T"]()
        comptime _P = byte["P"]()
        comptime _SLASH = byte["/"]()
        var is_response = (
            len(buf_span) >= 5
            and buf_span[0] == _H
            and buf_span[1] == _T
            and buf_span[2] == _T
            and buf_span[3] == _P
            and buf_span[4] == _SLASH
        )

        var bytes_consumed: Int
        var result: Tuple[String, String, String, List[String]]
        if is_response:
            var parse_result = self._parse_raw_response(buf_span)
            bytes_consumed = parse_result[0]
            result = parse_result[1]
        else:
            var parse_result = self._parse_raw_request(buf_span)
            bytes_consumed = parse_result[0]
            result = parse_result[1]

        # buf_ptr.free()

        # Advance ByteReader position to start of body (after headers end)
        r.read_pos += bytes_consumed

        return result^

    # fn parse_raw(mut self, mut r: ByteReader) raises -> Tuple[String, String, String, List[String]]:
    #     if not r.available():
    #         raise Error("Headers.parse_raw: Failed to read first byte from response header.")

    #     var first = r.read_word()
    #     r.increment()
    #     var second = r.read_word()
    #     r.increment()
    #     var third = r.read_line()
    #     var cookies = List[String]()

    #     try:
    #         while not is_newline(r.peek()):
    #             var key = r.read_until(BytesConstant.colon)
    #             r.increment()
    #             if is_space(r.peek()):
    #                 r.increment()

    #             # TODO (bgreni): Handle possible trailing whitespace
    #             var value = r.read_line()
    #             var k = String(key).lower()
    #             if k == HeaderKey.SET_COOKIE:
    #                 cookies.append(String(value))
    #                 continue
    #             self._inner[k] = String(value)
    #     except EndOfReaderError:
    #         logger.error(EndOfReaderError)
    #         raise Error("Headers.parse_raw: Failed to read full response headers.")

    #     return (String(first), String(second), String(third), cookies^)

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
