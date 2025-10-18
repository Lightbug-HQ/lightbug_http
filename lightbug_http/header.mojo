from collections import Dict, Optional
from lightbug_http.io.bytes import Bytes, ByteReader, ByteWriter, is_newline, is_space
from lightbug_http.strings import BytesConstant
from lightbug_http._logger import logger
from lightbug_http.strings import rChar, nChar, lineBreak, to_string
from lightbug_http.pico import (
    phr_parse_request,
    phr_parse_response,
    PhrHeader,
)
from memory import UnsafePointer


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


@value
struct Header(Writable, Stringable):
    var key: String
    var value: String

    fn __str__(self) -> String:
        return String.write(self)

    fn write_to[T: Writer, //](self, mut writer: T):
        writer.write(self.key + ": ", self.value, lineBreak)


@always_inline
fn write_header[T: Writer](mut writer: T, key: String, value: String):
    writer.write(key + ": ", value, lineBreak)


@value
struct Headers(Writable, Stringable):
    """Represents the header key/values in an http request/response.

    Header keys are normalized to lowercase
    """

    var _inner: Dict[String, String]

    fn __init__(out self):
        self._inner = Dict[String, String]()

    fn __init__(out self, owned *headers: Header):
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
        """Parse HTTP request or response headers using the pico parser.
        
        Returns:
            For requests: (method, uri, protocol, cookies)
            For responses: (protocol, status_code, status_text, cookies)
        """
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Headers.parse_raw: Failed to read first byte from header")

        # Get the remaining bytes to parse
        var buf_bytes = r._inner[r.read_pos:]
        var buf_ptr = UnsafePointer[UInt8].alloc(len(buf_bytes))
        for i in range(len(buf_bytes)):
            buf_ptr[i] = buf_bytes[i]
        
        # Allocate space for headers (reasonable max)
        alias MAX_HEADERS = 100
        var phr_headers = UnsafePointer[PhrHeader].alloc(MAX_HEADERS)
        for i in range(MAX_HEADERS):
            phr_headers[i] = PhrHeader()
        
        var num_headers = MAX_HEADERS
        var cookies = List[String]()
        
        # Check if it's a request or response by looking at the first word
        var first_word_bytes = r.read_word()
        var first_word = String(first_word_bytes)
        r.read_pos -= len(first_word_bytes) + 1  # Reset position
        
        var result: Int
        var first: String
        var second: String
        var third: String
        
        if first_word == "HTTP/1.0" or first_word == "HTTP/1.1" or first_word.startswith("HTTP/"):
            # It's a response: HTTP/1.x STATUS MESSAGE
            var minor_version: Int = -1
            var status: Int = 0
            var msg: String = ""
            var msg_len: Int = 0
            
            result = phr_parse_response(
                buf_ptr,
                len(buf_bytes),
                minor_version,
                status,
                msg,
                msg_len,
                phr_headers,
                num_headers,
                0  # last_len
            )
            
            if result < 0:
                buf_ptr.free()
                phr_headers.free()
                if result == -1:
                    raise Error("Headers.parse_raw: Invalid HTTP response format")
                else:
                    raise Error("Headers.parse_raw: Incomplete HTTP response")
            
            # Extract protocol, status code, and status text
            first = "HTTP/1." + String(minor_version)
            second = String(status)
            third = msg
            
        else:
            # It's a request: METHOD URI HTTP/1.x
            var method: String = ""
            var method_len: Int = 0
            var path: String = ""
            var path_len: Int = 0
            var minor_version: Int = -1
            
            result = phr_parse_request(
                buf_ptr,
                len(buf_bytes),
                method,
                method_len,
                path,
                path_len,
                minor_version,
                phr_headers,
                num_headers,
                0  # last_len
            )
            
            if result < 0:
                buf_ptr.free()
                phr_headers.free()
                if result == -1:
                    raise Error("Headers.parse_raw: Invalid HTTP request format")
                else:
                    raise Error("Headers.parse_raw: Incomplete HTTP request")
            
            # Extract method, path, and protocol
            first = method
            second = path
            third = "HTTP/1." + String(minor_version)
        
        # Extract headers from phr_headers
        for i in range(num_headers):
            var k = phr_headers[i].name.lower()
            var v = phr_headers[i].value
            
            if k == HeaderKey.SET_COOKIE:
                cookies.append(v)
                continue
            
            self._inner[k] = v
        
        # Update reader position to after the parsed headers
        r.read_pos += result
        
        # Clean up
        buf_ptr.free()
        phr_headers.free()
        
        return (first, second, third, cookies)

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
