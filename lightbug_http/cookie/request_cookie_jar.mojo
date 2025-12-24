from lightbug_http.header import HeaderKey, write_header
from lightbug_http.io.bytes import ByteWriter
from lightbug_http.strings import lineBreak
from small_time import SmallTime, TimeZone
from small_time.small_time import parse_time_with_format


@fieldwise_init
struct RequestCookieJar(Copyable, Stringable, Writable):
    var _inner: Dict[String, String]

    fn __init__(out self):
        self._inner = Dict[String, String]()

    fn __init__(out self, *cookies: Cookie):
        self._inner = Dict[String, String]()
        for cookie in cookies:
            self._inner[cookie.name] = cookie.value

    fn parse_cookies(mut self, headers: Headers) raises:
        var cookie_header = headers.get(HeaderKey.COOKIE)
        if not cookie_header:
            return None

        var cookie_strings = cookie_header.value().split("; ")

        for chunk in cookie_strings:
            var key = String("")
            var value = chunk
            if "=" in chunk:
                var key_value = chunk.split("=")
                key = String(key_value[0])
                value = key_value[1]

            # TODO value must be "unquoted"
            self._inner[key] = String(value)

    @always_inline
    fn empty(self) -> Bool:
        return len(self._inner) == 0

    @always_inline
    fn __contains__(self, key: String) -> Bool:
        return key in self._inner

    fn __contains__(self, key: Cookie) -> Bool:
        return key.name in self

    @always_inline
    fn __getitem__(self, key: String) raises -> String:
        return self._inner[key.lower()]

    fn get(self, key: String) -> Optional[String]:
        try:
            return self[key]
        except:
            return Optional[String](None)

    fn to_header(self) -> Optional[Header]:
        comptime equal = "="
        if len(self._inner) == 0:
            return None

        var header_value = List[String]()
        for cookie in self._inner.items():
            header_value.append(cookie.key + equal + cookie.value)
        return Header(HeaderKey.COOKIE, StaticString("; ").join(header_value))

    fn encode_to(mut self, mut writer: ByteWriter):
        var header = self.to_header()
        if header:
            write_header(writer, header.value().key, header.value().value)

    fn write_to[T: Writer](self, mut writer: T):
        var header = self.to_header()
        if header:
            write_header(writer, header.value().key, header.value().value)

    fn __str__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: RequestCookieJar) -> Bool:
        if len(self._inner) != len(other._inner):
            return False

        for value in self._inner.items():
            for other_value in other._inner.items():
                if value.key != other_value.key or value.value != other_value.value:
                    return False
        return True
