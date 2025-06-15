from collections import Dict, Optional
from lightbug_http.io.bytes import Bytes, ByteReader, ByteWriter, is_newline, is_space, ByteView
from lightbug_http.strings import BytesConstant
from lightbug_http._logger import logger
from lightbug_http.strings import rChar, nChar, lineBreak, to_string


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


fn bytes_equal_ignore_case(a: ByteView, b: String) -> Bool:
    """Compare ByteView with String case-insensitively without creating intermediate strings."""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        var byte_a = a[i]
        var byte_b = ord(b[i])
        
        # Convert to lowercase for comparison
        if byte_a >= ord('A') and byte_a <= ord('Z'):
            byte_a = byte_a + 32  # Convert to lowercase
        if byte_b >= ord('A') and byte_b <= ord('Z'):
            byte_b = byte_b + 32  # Convert to lowercase
            
        if byte_a != byte_b:
            return False
    return True


fn bytes_to_lower_string(b: ByteView) -> String:
    """Convert ByteView to lowercase String."""
    var result = Bytes()
    for i in range(len(b)):
        var byte_val = b[i]
        if byte_val >= ord('A') and byte_val <= ord('Z'):
            byte_val = byte_val + 32  # Convert to lowercase
        result.append(byte_val)
    return to_string(result^)


@value
struct Headers[origin: Origin](Writable, Stringable):
    """Represents the header key/values in an http request/response.

    Header keys are normalized to lowercase and stored as strings for efficient lookup,
    while values are stored as bytes to comply with RFC requirements.
    """

    var _inner: Dict[String, Bytes]

    fn __init__(out self):
        self._inner = Dict[String, Bytes]()

    fn __init__(out self, owned *headers: Header):
        self._inner = Dict[String, Bytes]()
        for header in headers:
            var key_lower = header[].key.lower()
            var value_bytes = Bytes(header[].value.as_bytes())
            self._inner[key_lower] = value_bytes

    @always_inline
    fn empty(self) -> Bool:
        return len(self._inner) == 0

    @always_inline
    fn __contains__(self, key: String) -> Bool:
        return key.lower() in self._inner

    @always_inline
    fn __getitem__(self, key: String) raises -> String:
        try:
            var value_bytes = self._inner[key.lower()]
            return to_string(value_bytes)
        except:
            raise Error("KeyError: Key not found in headers: " + key)

    @always_inline
    fn get(self, key: String) -> Optional[String]:
        var value_opt = self._inner.get(key.lower())
        if value_opt:
            return to_string(value_opt.value())
        return None

    @always_inline
    fn __setitem__(mut self, key: String, value: String):
        var value_bytes = Bytes(value.as_bytes())
        self._inner[key.lower()] = value_bytes

    fn content_length(self) -> Int:
        try:
            return Int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw[origin: Origin](mut self, mut r: ByteReader[origin]) raises -> (ByteView[origin], ByteView[origin], ByteView[origin], List[String]):
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Headers.parse_raw: Failed to read first byte from response header")

        var first = r.read_word()
        r.increment()
        var second = r.read_word()
        r.increment()
        var third = r.read_line()
        var cookies = List[String]()

        while not is_newline(r.peek()):
            var key = r.read_until(BytesConstant.colon)
            r.increment()
            if is_space(r.peek()):
                r.increment()
            # TODO (bgreni): Handle possible trailing whitespace
            var value = r.read_line()
            
            if bytes_equal_ignore_case(key, HeaderKey.SET_COOKIE):
                cookies.append(String(value))
                continue

            var key_str = bytes_to_lower_string(key)
            var value_bytes = value.to_bytes()
            self._inner[key_str] = value_bytes
            
        return (first, second, third, cookies)

    fn write_to[T: Writer, //](self, mut writer: T):
        for header in self._inner.items():
            var value_str = to_string(header[].value)
            write_header(writer, header[].key, value_str)

    fn __str__(self) -> String:
        return String.write(self)
