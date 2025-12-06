from lightbug_http._logger import logger
from lightbug_http.io.bytes import ByteReader, Bytes, is_newline, is_space
from lightbug_http.strings import BytesConstant, lineBreak, nChar, rChar


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
struct Header(Copyable, Movable, Stringable, Writable):
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
struct Headers(Copyable, Movable, Stringable, Writable):
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

    fn parse_raw(mut self, mut r: ByteReader) raises -> Tuple[String, String, String, List[String]]:
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
            var k = String(key).lower()
            if k == HeaderKey.SET_COOKIE:
                cookies.append(String(value))
                continue

            self._inner[k] = String(value)
        return (String(first), String(second), String(third), cookies^)

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
