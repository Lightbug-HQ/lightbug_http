from collections import KeyElement
from hashlib.hash import Hasher

from lightbug_http.header import HeaderKey, write_header
from lightbug_http.io.bytes import ByteWriter
from lightbug_http.cookie.cookie import InvalidCookieError
from utils import Variant


@fieldwise_init
@register_passable("trivial")
struct CookieParseError(Movable, Stringable, Writable):
    """Error raised when a cookie header string fails to parse."""

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("CookieParseError: Failed to parse cookie header string")

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct ResponseCookieKey(ImplicitlyCopyable, KeyElement):
    var name: String
    var domain: String
    var path: String

    fn __init__(
        out self,
        name: String,
        domain: Optional[String] = Optional[String](None),
        path: Optional[String] = Optional[String](None),
    ):
        self.name = name
        self.domain = domain.or_else("")
        self.path = path.or_else("/")

    fn __ne__(self: Self, other: Self) -> Bool:
        return not (self == other)

    fn __eq__(self: Self, other: Self) -> Bool:
        return self.name == other.name and self.domain == other.domain and self.path == other.path

    fn __moveinit__(out self: Self, deinit existing: Self):
        self.name = existing.name
        self.domain = existing.domain
        self.path = existing.path

    fn __copyinit__(out self: Self, existing: Self):
        self.name = existing.name
        self.domain = existing.domain
        self.path = existing.path

    fn __hash__[H: Hasher](self: Self, mut hasher: H):
        hasher.update(self.name + "~" + self.domain + "~" + self.path)


@fieldwise_init
struct ResponseCookieJar(Copyable, Sized, Stringable, Writable):
    var _inner: Dict[ResponseCookieKey, Cookie]

    fn __init__(out self):
        self._inner = Dict[ResponseCookieKey, Cookie]()

    fn __init__(out self, *cookies: Cookie):
        self._inner = Dict[ResponseCookieKey, Cookie]()
        for cookie in cookies:
            self.set_cookie(cookie)

    fn __init__(out self, cookies: List[Cookie]):
        self._inner = Dict[ResponseCookieKey, Cookie]()
        for cookie in cookies:
            self.set_cookie(cookie)

    @always_inline
    fn __setitem__(mut self, key: ResponseCookieKey, value: Cookie):
        self._inner[key] = value.copy()

    fn __getitem__(self, key: ResponseCookieKey) raises -> Cookie:
        return self._inner[key].copy()

    fn get(self, key: ResponseCookieKey) -> Optional[Cookie]:
        try:
            return self[key]
        except:
            return None

    @always_inline
    fn __contains__(self, key: ResponseCookieKey) -> Bool:
        return key in self._inner

    @always_inline
    fn __contains__(self, key: Cookie) -> Bool:
        return ResponseCookieKey(key.name, key.domain, key.path) in self

    fn __str__(self) -> String:
        return String.write(self)

    fn __len__(self) -> Int:
        return len(self._inner)

    @always_inline
    fn set_cookie(mut self, cookie: Cookie):
        self[ResponseCookieKey(cookie.name, cookie.domain, cookie.path)] = cookie

    @always_inline
    fn empty(self) -> Bool:
        return len(self) == 0

    fn from_headers(mut self, headers: List[String]) raises CookieParseError:
        for header in headers:
            try:
                self.set_cookie(Cookie.from_set_header(header))
            except:
                raise CookieParseError()

    # fn encode_to(mut self, mut writer: ByteWriter):
    #     for cookie in self._inner.values():
    #         var v = cookie[].build_header_value()
    #         write_header(writer, HeaderKey.SET_COOKIE, v)

    fn write_to[T: Writer](self, mut writer: T):
        for cookie in self._inner.values():
            var v = cookie.build_header_value()
            write_header(writer, HeaderKey.SET_COOKIE, v)
