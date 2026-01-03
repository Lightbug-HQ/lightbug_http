from lightbug_http.header import Header, HeaderKey, Headers, ParsedRequestHeaders, write_header
from lightbug_http.io.bytes import Bytes, ByteWriter
from lightbug_http.io.sync import Duration
from lightbug_http.strings import lineBreak, strHttp11, whitespace
from lightbug_http.uri import URI
from memory import Span
from utils import Variant

from lightbug_http.cookie import RequestCookieJar


@fieldwise_init
struct URITooLongError(ImplicitlyCopyable):
    """Request URI exceeded maximum length."""

    fn message(self) -> String:
        return "Request URI exceeds maximum allowed length"


@fieldwise_init
struct RequestBodyTooLargeError(ImplicitlyCopyable):
    """Request body exceeded maximum size."""

    fn message(self) -> String:
        return "Request body exceeds maximum allowed size"


@fieldwise_init
struct URIParseError(ImplicitlyCopyable):
    """Failed to parse request URI."""

    fn message(self) -> String:
        return "Malformed request URI"


@fieldwise_init
struct CookieParseError(ImplicitlyCopyable):
    """Failed to parse cookies."""

    var detail: String

    fn message(self) -> String:
        return String("Invalid cookies: ", self.detail)


comptime RequestBuildError = Variant[
    URITooLongError,
    RequestBodyTooLargeError,
    URIParseError,
    CookieParseError,
]


@fieldwise_init
struct RequestMethod:
    """HTTP request method constants."""

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
    """Represents a parsed HTTP request.

    This type is constructed from already-parsed components. The server is responsible
    for driving the parsing process (using header.mojo functions) and constructing
    the request once all data is available.
    """

    var headers: Headers
    var cookies: RequestCookieJar
    var uri: URI
    var body_raw: Bytes

    var method: String
    var protocol: String

    var server_is_tls: Bool
    var timeout: Duration

    @staticmethod
    fn from_parsed(
        server_addr: String,
        parsed: ParsedRequestHeaders,
        body: Bytes,
        max_uri_length: Int,
    ) raises RequestBuildError -> HTTPRequest:
        """Construct an HTTPRequest from parsed headers and body.

        This is the primary factory method for creating requests. The server
        should use header.mojo's parse_request_headers() to parse the headers,
        then read the body separately, and finally call this method.

        Args:
            server_addr: The server address (used for URI construction).
            parsed: The parsed request headers from parse_request_headers().
            body: The request body bytes.
            max_uri_length: Maximum allowed URI length.

        Returns:
            A fully constructed HTTPRequest.

        Raises:
            RequestBuildError: If URI is too long, URI parsing fails, or cookie parsing fails.
        """
        if len(parsed.path) > max_uri_length:
            raise RequestBuildError(URITooLongError())

        var cookies = RequestCookieJar()
        for cookie_str in parsed.cookies:
            try:
                cookies.parse_cookie_header(cookie_str[])
            except e:
                raise RequestBuildError(CookieParseError(detail=String(e)))

        var full_uri_string = String(server_addr, parsed.path)
        var parsed_uri: URI
        try:
            parsed_uri = URI.parse(full_uri_string)
        except:
            raise RequestBuildError(URIParseError())

        var request = HTTPRequest(
            uri=parsed_uri^,
            headers=parsed.headers,
            method=parsed.method,
            protocol=parsed.protocol,
            cookies=cookies^,
            body_raw=body,
        )

        request.set_content_length(len(request.body_raw))

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
        """Initialize a new HTTP request.

        This constructor is for building outgoing requests. For parsing incoming
        requests, use from_parsed() instead.
        """
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
        """Get the request body as a string slice."""
        return StringSlice(unsafe_from_utf8=Span(self.body_raw))

    fn set_connection_close(mut self):
        """Set the Connection header to 'close'."""
        self.headers[HeaderKey.CONNECTION] = "close"

    fn set_content_length(mut self, length: Int):
        """Set the Content-Length header."""
        self.headers[HeaderKey.CONTENT_LENGTH] = String(length)

    fn connection_close(self) -> Bool:
        """Check if the Connection header is set to 'close'."""
        var result = self.headers.get(HeaderKey.CONNECTION)
        if not result:
            return False
        return result.value() == "close"

    fn write_to[T: Writer, //](self, mut writer: T):
        """Write the request in HTTP format to a writer."""
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
        """Encode request as bytes, consuming the request."""
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
