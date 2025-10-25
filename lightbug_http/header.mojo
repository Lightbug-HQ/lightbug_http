from collections import Dict, Optional
from memory import UnsafePointer, Span
from lightbug_http.io.bytes import Bytes, ByteReader, ByteWriter, is_newline, is_space
from lightbug_http.strings import BytesConstant
from lightbug_http._logger import logger
from lightbug_http.strings import rChar, nChar, lineBreak, to_string
from lightbug_http.pico import (
    PhrHeader,
    phr_parse_request,
    phr_parse_response,
    phr_parse_headers,
)


struct HeaderKey:
    # TODO: Fill in more of these
    alias CONNECTION = "connection"
    alias CONTENT_TYPE = "content-type"
    alias CONTENT_LENGTH = "content-length"
    alias CONTENT_ENCODING = "content-encoding"
    alias TRANSFER_ENCODING = "transfer-encoding"
    alias DATE = "date"
    alias LOCATION = "location"
    alias HOST = "host"
    alias SERVER = "server"
    alias SET_COOKIE = "set-cookie"
    alias COOKIE = "cookie"


@fieldwise_init
struct Header(Writable, Stringable, Copyable, Movable):
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
struct Headers(Writable, Stringable, Copyable, Movable):
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

    fn parse_raw(mut self, mut r: ByteReader) raises -> (String, String, String, List[String]):
        """Parse HTTP headers using picohttpparser for request/response.

        This method delegates to parse_raw_request or parse_raw_response based on
        whether the first token looks like an HTTP method or HTTP version.

        Returns:
            For requests: (method, path, protocol, cookies)
            For responses: (protocol, status_code, status_text, cookies)
        """
        # Peek at first few bytes to determine if this is a request or response
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Headers.parse_raw: Failed to read first byte from header")

        # Create buffer from ByteReader's remaining data
        var buf_span = r._inner[r.read_pos:]
        var buf_ptr = UnsafePointer[UInt8].alloc(len(buf_span))
        for i in range(len(buf_span)):
            buf_ptr[i] = buf_span[i]

        # Check if starts with "HTTP/" (response) or method name (request)
        var is_response = (
            len(buf_span) >= 5
            and buf_span[0] == ord('H')
            and buf_span[1] == ord('T')
            and buf_span[2] == ord('T')
            and buf_span[3] == ord('P')
            and buf_span[4] == ord('/')
        )

        var result: (String, String, String, List[String])
        if is_response:
            result = self._parse_raw_response(buf_ptr, len(buf_span))
        else:
            result = self._parse_raw_request(buf_ptr, len(buf_span))

        buf_ptr.free()

        # Advance ByteReader position (we consumed the entire buffer)
        r.read_pos = len(r._inner)

        return result

    fn _parse_raw_request(
        mut self,
        buf_ptr: UnsafePointer[UInt8],
        buf_len: Int
    ) raises -> (String, String, String, List[String]):
        """Parse HTTP request using picohttpparser."""
        var method = String()
        var method_len = 0
        var path = String()
        var path_len = 0
        var minor_version = -1

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = UnsafePointer[PhrHeader].alloc(max_headers)
        for i in range(max_headers):
            headers[i] = PhrHeader()

        var num_headers = max_headers
        var ret = phr_parse_request(
            buf_ptr, buf_len,
            method, method_len,
            path, path_len,
            minor_version,
            headers,
            num_headers,
            0  # last_len (0 for first parse)
        )

        if ret < 0:
            headers.free()
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
        var protocol = "HTTP/1." + String(minor_version)

        headers.free()
        return (method, path, protocol, cookies^)

    fn _parse_raw_response(
        mut self,
        buf_ptr: UnsafePointer[UInt8],
        buf_len: Int
    ) raises -> (String, String, String, List[String]):
        """Parse HTTP response using picohttpparser."""
        var minor_version = -1
        var status = 0
        var msg = String()
        var msg_len = 0

        # Allocate headers array (max 100 headers)
        var max_headers = 100
        var headers = UnsafePointer[PhrHeader].alloc(max_headers)
        for i in range(max_headers):
            headers[i] = PhrHeader()

        var num_headers = max_headers
        var ret = phr_parse_response(
            buf_ptr, buf_len,
            minor_version,
            status,
            msg, msg_len,
            headers,
            num_headers,
            0  # last_len (0 for first parse)
        )

        if ret < 0:
            headers.free()
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

        headers.free()
        return (protocol, String(status), msg, cookies^)

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
