from collections import Optional, List, Dict
from lightbug_http.external.small_time import SmallTime, TimeZone
from lightbug_http.external.small_time.small_time import strptime
from lightbug_http.strings import to_string, lineBreak
from lightbug_http.header import HeaderKey, write_header
from lightbug_http.io.bytes import ByteReader, ByteWriter, is_newline, is_space


@value
struct RequestCookieJar(Writable, Stringable):
    var _inner: Dict[String, String]

    fn __init__(out self):
        self._inner = Dict[String, String]()

    fn __init__(out self, *cookies: Cookie):
        self._inner = Dict[String, String]()
        for cookie in cookies:
            self._inner[cookie[].name] = cookie[].value

    fn parse_cookies(mut self, headers: Headers) raises:
        var cookie_header = headers.get(HeaderKey.COOKIE)
        if not cookie_header:
            return None

        var cookie_strings = cookie_header.value().split("; ")

        for chunk in cookie_strings:
            var key = String("")
            var value = chunk[]
            if "=" in chunk[]:
                var key_value = chunk[].split("=")
                key = key_value[0]
                value = key_value[1]

            # TODO value must be "unquoted"
            self._inner[key] = value

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
        alias equal = "="
        if len(self._inner) == 0:
            return None

        var header_value = List[String]()
        for cookie in self._inner.items():
            header_value.append(cookie[].key + equal + cookie[].value)
        return Header(HeaderKey.COOKIE, String("; ").join(header_value))

    fn encode_to(mut self, mut writer: ByteWriter):
        var header = self.to_header()
        if header:
            write_header(writer, header.value().key, header.value().value)

    fn write_to[T: Writer](self, mut writer: T):
        var header = self.to_header()
        if header:
            write_header(writer, header.value().key, header.value().value)

    fn __str__(self) -> String:
        return to_string(self)
