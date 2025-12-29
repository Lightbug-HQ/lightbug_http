from hashlib.hash import Hasher

from lightbug_http.io.bytes import ByteReader, Bytes, ByteView
from lightbug_http.strings import find_all, http, https, strHttp10, strHttp11


fn unquote[expand_plus: Bool = False](input_str: String, disallowed_escapes: List[String] = List[String]()) -> String:
    var encoded_str = input_str.replace(QueryDelimiters.PLUS_ESCAPED_SPACE, " ") if expand_plus else input_str

    var percent_idxs: List[Int] = find_all(encoded_str, URIDelimiters.CHAR_ESCAPE)

    if len(percent_idxs) < 1:
        return encoded_str

    var sub_strings = List[String]()
    var current_idx = 0
    var slice_start = 0

    var str_bytes = List[UInt8]()
    while current_idx < len(percent_idxs):
        var slice_end = percent_idxs[current_idx]
        sub_strings.append(String(encoded_str[slice_start:slice_end]))

        var current_offset = slice_end
        while current_idx < len(percent_idxs):
            if (current_offset + 3) > len(encoded_str):
                # If the percent escape is not followed by two hex digits, we stop processing.
                break

            try:
                char_byte = atol(
                    encoded_str[current_offset + 1 : current_offset + 3],
                    base=16,
                )
                str_bytes.append(char_byte)
            except:
                break

            if percent_idxs[current_idx + 1] != (current_offset + 3):
                current_offset += 3
                break

            current_idx += 1
            current_offset = percent_idxs[current_idx]

        if len(str_bytes) > 0:
            var sub_str_from_bytes = String()
            sub_str_from_bytes.write_bytes(str_bytes)
            for disallowed in disallowed_escapes:
                sub_str_from_bytes = sub_str_from_bytes.replace(disallowed, "")
            sub_strings.append(sub_str_from_bytes)
            str_bytes.clear()

        slice_start = current_offset
        current_idx += 1

    sub_strings.append(String(encoded_str[slice_start:]))

    return StaticString("").join(sub_strings)


comptime QueryMap = Dict[String, String]


struct QueryDelimiters:
    comptime STRING_START = "?"
    comptime ITEM = "&"
    comptime ITEM_ASSIGN = "="
    comptime PLUS_ESCAPED_SPACE = "+"


struct URIDelimiters:
    comptime SCHEMA = "://"
    comptime PATH = "/"
    comptime ROOT_PATH = "/"
    comptime CHAR_ESCAPE = "%"
    comptime AUTHORITY = "@"
    comptime QUERY = "?"
    comptime SCHEME = ":"


struct PortBounds:
    comptime NINE: UInt8 = ord("9")
    comptime ZERO: UInt8 = ord("0")


@fieldwise_init
struct Scheme(Equatable, Hashable, ImplicitlyCopyable, Representable, Stringable, Writable):
    var value: UInt8
    comptime HTTP = Self(0)
    comptime HTTPS = Self(1)

    fn __hash__[H: Hasher](self, mut hasher: H):
        hasher.update(self.value)

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self == Self.HTTP:
            writer.write("HTTP")
        else:
            writer.write("HTTPS")

    fn __repr__(self) -> String:
        return String.write("Scheme(", self, ")")

    fn __str__(self) -> String:
        return String.write(self)


struct URIParseError(Stringable, Writable):
    var message: String

    fn __init__(out self, var message: String):
        self.message = message^

    fn write_to[W: Writer, //](self, mut writer: W) -> None:
        writer.write(self.message)

    fn __str__(self) -> String:
        return self.message.copy()


@fieldwise_init
struct URI(Copyable, Representable, Stringable, Writable):
    var _original_path: String
    var scheme: String
    var path: String
    var query_string: String
    var queries: QueryMap
    var _hash: String
    var host: String
    var port: Optional[UInt16]

    var full_uri: String
    var request_uri: String

    var username: String
    var password: String

    @staticmethod
    fn parse(var uri: String) raises URIParseError -> URI:
        """Parses a URI which is defined using the following format.

        `[scheme:][//[user_info@]host][/]path[?query][#fragment]`
        """
        var reader = ByteReader(uri.as_bytes())

        # Parse the scheme, if exists.
        # Assume http if no scheme is provided, fairly safe given the context of lightbug.
        var scheme: String = "http"
        if "://" in uri:
            scheme = String(reader.read_until(ord(URIDelimiters.SCHEME)))
            var scheme_delimiter: ByteView[origin_of(uri)]
            try:
                scheme_delimiter = reader.read_bytes(3)
            except EndOfReaderError:
                raise URIParseError(
                    "URI.parse: Incomplete URI, expected scheme delimiter after scheme but reached the end of the URI."
                )

            if scheme_delimiter != "://".as_bytes():
                raise URIParseError(
                    String(
                        "URI.parse: Invalid URI format, scheme should be followed by `://`. Received: ",
                        uri,
                    )
                )

        # Parse the user info, if exists.
        # TODO (@thatstoasty): Store the user information (username and password) if it exists.
        if ord(URIDelimiters.AUTHORITY) in reader:
            _ = reader.read_until(ord(URIDelimiters.AUTHORITY))
            reader.increment(1)

        # TODOs (@thatstoasty)
        # Handle ipv4 and ipv6 literal
        # Handle string host
        # A query right after the domain is a valid uri, but it's equivalent to example.com/?query
        # so we should add the normalization of paths
        var host_and_port = reader.read_until(ord(URIDelimiters.PATH))
        colon = host_and_port.find(ord(URIDelimiters.SCHEME))
        var host: String
        var port: Optional[UInt16] = None
        if colon != -1:
            host = String(host_and_port[:colon])
            var port_end = colon + 1
            # loop through the post colon chunk until we find a non-digit character
            for b in host_and_port[colon + 1 :]:
                if b < PortBounds.ZERO or b > PortBounds.NINE:
                    break
                port_end += 1

            try:
                port = UInt16(atol(String(host_and_port[colon + 1 : port_end])))
            except conversion_err:
                raise URIParseError(
                    String(
                        "URI.parse: Failed to convert port number from a String to Integer, received: ",
                        uri,
                    )
                )
        else:
            host = String(host_and_port)

        # Reads until either the start of the query string, or the end of the uri.
        var unquote_reader = reader.copy()
        var original_path_bytes = unquote_reader.read_until(ord(URIDelimiters.QUERY))
        var original_path: String
        if not original_path_bytes:
            original_path = "/"
        else:
            original_path = unquote(String(original_path_bytes), disallowed_escapes=["/"])

        var result = URI(
            _original_path=original_path,
            scheme=scheme,
            path=original_path,
            query_string="",
            queries=QueryMap(),
            _hash="",
            host=host,
            port=port,
            full_uri=uri,
            request_uri=original_path,
            username="",
            password="",
        )

        # Parse the path
        var path_delimiter: Byte
        try:
            path_delimiter = reader.peek()
        except EndOfReaderError:
            return result^

        var path: String = "/"
        var request_uri: String = "/"
        if path_delimiter == ord(URIDelimiters.PATH):
            # Copy the remaining bytes to read the request uri.
            var request_uri_reader = reader.copy()
            request_uri = String(request_uri_reader.read_bytes())

            # Read until the query string, or the end if there is none.
            path = unquote(
                String(reader.read_until(ord(URIDelimiters.QUERY))),
                disallowed_escapes=["/"],
            )

        result.request_uri = request_uri
        result.path = path

        # Parse query
        var query_delimiter: Byte
        try:
            query_delimiter = reader.peek()
        except EndOfReaderError:
            return result^

        var query: String = ""
        if query_delimiter == ord(URIDelimiters.QUERY):
            # TODO: Handle fragments for anchors
            query = String(reader.read_bytes()[1:])

        var queries = QueryMap()
        if query:
            var query_items = query.split(QueryDelimiters.ITEM)

            for item in query_items:
                var key_val = item.split(QueryDelimiters.ITEM_ASSIGN, 1)
                var key = unquote[expand_plus=True](String(key_val[0]))

                if key:
                    queries[key] = ""
                    if len(key_val) == 2:
                        queries[key] = unquote[expand_plus=True](String(key_val[1]))

        result.queries = queries^
        result.query_string = query^
        return result^

    fn __str__(self) -> String:
        var result = String.write(self.scheme, URIDelimiters.SCHEMA, self.host, self.path)
        if len(self.query_string) > 0:
            result.write(QueryDelimiters.STRING_START, self.query_string)
        return result^

    fn __repr__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: URI) -> Bool:
        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.path == other.path
            and self.query_string == other.query_string
            and self._original_path == other._original_path
            and self.full_uri == other.full_uri
            and self.request_uri == other.request_uri
        )

    fn write_to[T: Writer](self, mut writer: T):
        writer.write(
            "URI(",
            "scheme=",
            repr(self.scheme),
            ", host=",
            repr(self.host),
            ", path=",
            repr(self.path),
            ", _original_path=",
            repr(self._original_path),
            ", query_string=",
            repr(self.query_string),
            ", full_uri=",
            repr(self.full_uri),
            ", request_uri=",
            repr(self.request_uri),
            ")",
        )

    fn is_https(self) -> Bool:
        return self.scheme == https

    fn is_http(self) -> Bool:
        return self.scheme == http or len(self.scheme) == 0
