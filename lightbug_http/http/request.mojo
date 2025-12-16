from lightbug_http.header import Header, HeaderKey, Headers, ParsedRequestResult, write_header
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter
from lightbug_http.io.sync import Duration
from lightbug_http.strings import CR, LF, http, lineBreak, strHttp11, whitespace
from lightbug_http.uri import URI
from memory import Span

from lightbug_http.cookie import RequestCookieJar


@fieldwise_init
struct RequestMethod:
    var value: String

    comptime get = RequestMethod("GET")
    comptime post = RequestMethod("POST")
    comptime put = RequestMethod("PUT")
    comptime delete = RequestMethod("DELETE")
    comptime head = RequestMethod("HEAD")
    comptime patch = RequestMethod("PATCH")
    comptime options = RequestMethod("OPTIONS")


comptime strSlash = "/"


@fieldwise_init
struct HTTPRequest(Copyable, Encodable, Stringable, Writable):
    var headers: Headers
    var cookies: RequestCookieJar
    var uri: URI
    var body_raw: Bytes

    var method: String
    var protocol: String

    var server_is_tls: Bool
    var timeout: Duration

    @staticmethod
    fn from_bytes(addr: String, max_body_size: Int, max_uri_length: Int, b: Span[Byte]) raises -> HTTPRequest:
        var reader = ByteReader(b)
        var headers = Headers()
        var rest: ParsedRequestResult
        try:
            rest = headers.parse_raw_request(reader)
        except e:
            raise Error("HTTPRequest.from_bytes: Failed to parse request headers: ", e)

        if len(rest.path.as_bytes()) > max_uri_length:
            raise Error("HTTPRequest.from_bytes: Request URI too long")

        var cookies = RequestCookieJar()
        try:
            cookies.parse_cookies(headers)
        except e:
            raise Error("HTTPRequest.from_bytes: Failed to parse cookies: ", e)

        var content_length = headers.content_length()
        if content_length > 0 and max_body_size > 0 and content_length > max_body_size:
            raise Error("HTTPRequest.from_bytes: Request body too large.")

        var parsed_uri: URI
        try:
            parsed_uri = URI.parse(String(addr, rest.path))
        except URIParseError:
            raise Error("HTTPRequest.from_bytes: Failed to parse request URI.")

        var request = HTTPRequest(
            uri=parsed_uri^, headers=headers^, method=rest.method, protocol=rest.protocol, cookies=cookies^
        )

        if content_length > 0:
            try:
                reader.skip_carriage_return()
                request.read_body(reader, content_length, max_body_size)
            except e:
                raise Error("HTTPRequest.from_bytes: Failed to read request body: ", e)

        return request^

    fn __init__(
        out self,
        var uri: URI,
        var headers: Headers = Headers(),
        var cookies: RequestCookieJar = RequestCookieJar(),
        var method: String = "GET",
        var protocol: String = strHttp11,
        var body: Bytes = Bytes(),
        server_is_tls: Bool = False,
        timeout: Duration = Duration(),
    ):
        self.headers = headers^
        self.cookies = cookies.copy()
        self.method = method^
        self.protocol = protocol^
        self.uri = uri^
        self.body_raw = body^
        self.server_is_tls = server_is_tls
        self.timeout = timeout
        self.set_content_length(len(self.body_raw))
        if HeaderKey.CONNECTION not in self.headers:
            self.headers[HeaderKey.CONNECTION] = "keep-alive"
        if HeaderKey.HOST not in self.headers:
            if self.uri.port:
                self.headers[HeaderKey.HOST] = String(self.uri.host, ":", self.uri.port.value())
            else:
                self.headers[HeaderKey.HOST] = self.uri.host

    fn get_body(self) -> StringSlice[origin_of(self.body_raw)]:
        return StringSlice(unsafe_from_utf8=Span(self.body_raw))

    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = String(l)

    fn connection_close(self) -> Bool:
        var result = self.headers.get(HeaderKey.CONNECTION)
        if not result:
            return False
        return result.value() == "close"

    @always_inline
    fn read_body(mut self, mut r: ByteReader, content_length: Int, max_body_size: Int) raises -> None:
        if content_length > max_body_size:
            raise Error("Request body too large")

        if r.remaining() > content_length:
            try:
                self.body_raw = Bytes(r.read_bytes(content_length).as_bytes())
            except OutOfBoundsError:
                raise Error(
                    "Failed to read request body: reached the end of the reader before reaching content length."
                )

            if len(self.body_raw) != content_length:
                raise Error("Content length mismatch, expected ", content_length, " but got ", len(self.body_raw))

            self.set_content_length(len(self.body_raw))
            return

        # TODO: Handle content length mismatches?
        elif r.remaining() == 0:
            self.body_raw = Bytes()
            self.set_content_length(0)
            return

        self.body_raw = Bytes(r.read_bytes().as_bytes())
        self.set_content_length(len(self.body_raw))

    fn write_to[T: Writer, //](self, mut writer: T):
        path = self.uri.path if len(self.uri.path) > 1 else strSlash
        if len(self.uri.query_string) > 0:
            path.write("?", self.uri.query_string)

        writer.write(
            self.method,
            whitespace,
            path,
            whitespace,
            self.protocol,
            lineBreak,
            self.headers,
            self.cookies,
            lineBreak,
            StringSlice(unsafe_from_utf8=self.body_raw),
        )

    fn encode(deinit self) -> Bytes:
        """Encodes request as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var path = self.uri.path if len(self.uri.path) > 1 else strSlash
        if len(self.uri.query_string) > 0:
            path.write("?", self.uri.query_string)

        var writer = ByteWriter()
        writer.write(
            self.method,
            whitespace,
            path,
            whitespace,
            self.protocol,
            lineBreak,
            self.headers,
            self.cookies,
            lineBreak,
        )
        writer.consuming_write(self.body_raw^)
        return writer^.consume()

    fn __str__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: HTTPRequest) -> Bool:
        return (
            self.method == other.method
            and self.protocol == other.protocol
            and self.uri == other.uri
            and self.headers == other.headers
            and self.cookies == other.cookies
            and self.body_raw.__str__() == other.body_raw.__str__()
        )

    fn __isnot__(self, other: HTTPRequest) -> Bool:
        return not self.__eq__(other)

    fn __isnot__(self, other: None) -> Bool:
        return self.get_body() or self.uri.request_uri
