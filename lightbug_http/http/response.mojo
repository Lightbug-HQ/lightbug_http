from lightbug_http.connection import TCPConnection, default_buffer_size
from lightbug_http.header import ParsedResponseHeaders, parse_response_headers
from lightbug_http.http.chunked import HTTPChunkedDecoder
from lightbug_http.http.date import http_date_now
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter, byte
from lightbug_http.strings import CR, LF, http, lineBreak, strHttp11, whitespace
from lightbug_http.uri import URI
from utils import Variant


@fieldwise_init
struct ResponseHeaderParseError(ImplicitlyCopyable):
    """Failed to parse response headers."""

    var detail: String

    fn message(self) -> String:
        return String("Failed to parse response headers: ", self.detail)


@fieldwise_init
struct ResponseBodyReadError(ImplicitlyCopyable):
    """Failed to read response body."""

    var detail: String

    fn message(self) -> String:
        return String("Failed to read response body: ", self.detail)


@fieldwise_init
struct ChunkedEncodingError(ImplicitlyCopyable):
    """Invalid chunked transfer encoding."""

    var detail: String

    fn message(self) -> String:
        return String("Invalid chunked encoding: ", self.detail)


comptime ResponseParseError = Variant[
    ResponseHeaderParseError,
    ResponseBodyReadError,
    ChunkedEncodingError,
]


struct StatusCode:
    """HTTP status codes (RFC 9110)."""

    # 1xx Informational
    comptime CONTINUE = 100
    comptime SWITCHING_PROTOCOLS = 101
    comptime PROCESSING = 102
    comptime EARLY_HINTS = 103

    # 2xx Success
    comptime OK = 200
    comptime CREATED = 201
    comptime ACCEPTED = 202
    comptime NON_AUTHORITATIVE_INFORMATION = 203
    comptime NO_CONTENT = 204
    comptime RESET_CONTENT = 205
    comptime PARTIAL_CONTENT = 206
    comptime MULTI_STATUS = 207
    comptime ALREADY_REPORTED = 208
    comptime IM_USED = 226

    # 3xx Redirection
    comptime MULTIPLE_CHOICES = 300
    comptime MOVED_PERMANENTLY = 301
    comptime FOUND = 302
    comptime SEE_OTHER = 303
    comptime NOT_MODIFIED = 304
    comptime USE_PROXY = 305
    comptime TEMPORARY_REDIRECT = 307
    comptime PERMANENT_REDIRECT = 308

    # 4xx Client Errors
    comptime BAD_REQUEST = 400
    comptime UNAUTHORIZED = 401
    comptime PAYMENT_REQUIRED = 402
    comptime FORBIDDEN = 403
    comptime NOT_FOUND = 404
    comptime METHOD_NOT_ALLOWED = 405
    comptime NOT_ACCEPTABLE = 406
    comptime PROXY_AUTHENTICATION_REQUIRED = 407
    comptime REQUEST_TIMEOUT = 408
    comptime CONFLICT = 409
    comptime GONE = 410
    comptime LENGTH_REQUIRED = 411
    comptime PRECONDITION_FAILED = 412
    comptime REQUEST_ENTITY_TOO_LARGE = 413
    comptime REQUEST_URI_TOO_LONG = 414
    comptime UNSUPPORTED_MEDIA_TYPE = 415
    comptime REQUESTED_RANGE_NOT_SATISFIABLE = 416
    comptime EXPECTATION_FAILED = 417
    comptime IM_A_TEAPOT = 418
    comptime MISDIRECTED_REQUEST = 421
    comptime UNPROCESSABLE_ENTITY = 422
    comptime LOCKED = 423
    comptime FAILED_DEPENDENCY = 424
    comptime TOO_EARLY = 425
    comptime UPGRADE_REQUIRED = 426
    comptime PRECONDITION_REQUIRED = 428
    comptime TOO_MANY_REQUESTS = 429
    comptime REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    comptime UNAVAILABLE_FOR_LEGAL_REASONS = 451

    # 5xx Server Errors
    comptime INTERNAL_SERVER_ERROR = 500
    comptime INTERNAL_ERROR = 500  # Alias for backwards compatibility
    comptime NOT_IMPLEMENTED = 501
    comptime BAD_GATEWAY = 502
    comptime SERVICE_UNAVAILABLE = 503
    comptime GATEWAY_TIMEOUT = 504
    comptime HTTP_VERSION_NOT_SUPPORTED = 505
    comptime VARIANT_ALSO_NEGOTIATES = 506
    comptime INSUFFICIENT_STORAGE = 507
    comptime LOOP_DETECTED = 508
    comptime NOT_EXTENDED = 510
    comptime NETWORK_AUTHENTICATION_REQUIRED = 511


@fieldwise_init
struct HTTPResponse(Encodable, Movable, Sized, Stringable, Writable):
    var headers: Headers
    var cookies: ResponseCookieJar
    var body_raw: Bytes

    var status_code: Int
    var status_text: String
    var protocol: String

    @staticmethod
    fn from_bytes(b: Span[Byte]) raises ResponseParseError -> HTTPResponse:
        var cookies = ResponseCookieJar()

        var properties: ParsedResponseHeaders
        try:
            properties = parse_response_headers(b)
        except parse_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(parse_err)))

        try:
            cookies.from_headers(properties.cookies^)
        except cookie_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(cookie_err)))

        # Create reader at the position after headers
        var reader = ByteReader(b)
        try:
            _ = reader.read_bytes(properties.bytes_consumed)
        except bounds_err:
            raise ResponseParseError(ResponseBodyReadError(detail=String(bounds_err)))

        try:
            return HTTPResponse(
                reader=reader,
                headers=properties.headers^,
                cookies=cookies^,
                protocol=properties.protocol^,
                status_code=properties.status,
                status_text=properties.status_message^,
            )
        except body_err:
            raise ResponseParseError(ResponseBodyReadError(detail=String(body_err)))

    @staticmethod
    fn from_bytes(b: Span[Byte], conn: TCPConnection) raises ResponseParseError -> HTTPResponse:
        var cookies = ResponseCookieJar()

        var properties: ParsedResponseHeaders
        try:
            properties = parse_response_headers(b)
        except parse_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(parse_err)))

        try:
            cookies.from_headers(properties.cookies^)
        except cookie_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(cookie_err)))

        # Create reader at the position after headers
        var reader = ByteReader(b)
        try:
            _ = reader.read_bytes(properties.bytes_consumed)
        except bounds_err:
            raise ResponseParseError(ResponseBodyReadError(detail=String(bounds_err)))

        var response = HTTPResponse(
            Bytes(),
            headers=properties.headers^,
            cookies=cookies^,
            protocol=properties.protocol^,
            status_code=properties.status,
            status_text=properties.status_message^,
        )

        var transfer_encoding = response.headers.get(HeaderKey.TRANSFER_ENCODING)
        if transfer_encoding and transfer_encoding.value() == "chunked":
            var decoder = HTTPChunkedDecoder()
            decoder.consume_trailer = True

            var b = Bytes(reader.read_bytes().as_bytes())
            var buff = Bytes(capacity=default_buffer_size)
            try:
                while conn.read(buff) > 0:
                    b.extend(buff.copy())

                    if (
                        len(buff) >= 5
                        and buff[-5] == byte["0"]()
                        and buff[-4] == byte["\r"]()
                        and buff[-3] == byte["\n"]()
                        and buff[-2] == byte["\r"]()
                        and buff[-1] == byte["\n"]()
                    ):
                        break

                    # buff.clear()  # TODO: Should this be cleared? This was commented out before.
            except read_err:
                raise ResponseParseError(ResponseBodyReadError(detail=String(read_err)))

            # response.read_chunks(b)
            # Decode chunks
            response._decode_chunks(decoder, b^)
            return response^

        try:
            response.read_body(reader)
            return response^
        except body_err:
            raise ResponseParseError(ResponseBodyReadError(detail=String(body_err)))

    fn _decode_chunks(mut self, mut decoder: HTTPChunkedDecoder, var chunks: Bytes) raises ResponseParseError:
        """Decode chunked transfer encoding.
        Args:
            decoder: The chunked decoder state machine.
            chunks: The raw chunked data to decode.
        """
        # Convert Bytes to UnsafePointer
        # var buf_ptr = Span(chunks)
        # var buf_ptr = alloc[Byte](count=len(chunks))
        # for i in range(len(chunks)):
        #     buf_ptr[i] = chunks[i]

        # var bufsz = len(chunks)
        var result = decoder.decode(Span(chunks))
        var ret = result[0]
        var decoded_size = result[1]

        if ret == -1:
            # buf_ptr.free()
            raise ResponseParseError(ChunkedEncodingError(detail="Invalid chunked encoding"))
        # ret == -2 means incomplete, but we'll proceed with what we have
        # ret >= 0 means complete, with ret bytes of trailing data

        # Copy decoded data to body
        self.body_raw = Bytes(capacity=decoded_size)
        for i in range(decoded_size):
            self.body_raw.append(Span(chunks)[i])
        # self.body_raw = Bytes(Span(chunks))

        self.set_content_length(len(self.body_raw))
        # buf_ptr.free()

    fn __init__(
        out self,
        body_bytes: Span[Byte],
        headers: Headers = Headers(),
        cookies: ResponseCookieJar = ResponseCookieJar(),
        status_code: Int = 200,
        status_text: String = "OK",
        protocol: String = strHttp11,
    ):
        self.headers = headers.copy()
        self.cookies = cookies.copy()
        if HeaderKey.CONTENT_TYPE not in self.headers:
            self.headers[HeaderKey.CONTENT_TYPE] = "application/octet-stream"
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = Bytes(body_bytes)
        if HeaderKey.CONNECTION not in self.headers:
            self.set_connection_keep_alive()
        if HeaderKey.CONTENT_LENGTH not in self.headers:
            self.set_content_length(len(body_bytes))
        if HeaderKey.DATE not in self.headers:
            self.headers[HeaderKey.DATE] = http_date_now()

    fn __init__(
        out self,
        mut reader: ByteReader,
        headers: Headers = Headers(),
        cookies: ResponseCookieJar = ResponseCookieJar(),
        status_code: Int = 200,
        status_text: String = "OK",
        protocol: String = strHttp11,
    ) raises:
        self.headers = headers.copy()
        self.cookies = cookies.copy()
        if HeaderKey.CONTENT_TYPE not in self.headers:
            self.headers[HeaderKey.CONTENT_TYPE] = "application/octet-stream"
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = Bytes(reader.read_bytes().as_bytes())
        self.set_content_length(len(self.body_raw))
        if HeaderKey.CONNECTION not in self.headers:
            self.set_connection_keep_alive()
        if HeaderKey.CONTENT_LENGTH not in self.headers:
            self.set_content_length(len(self.body_raw))
        if HeaderKey.DATE not in self.headers:
            self.headers[HeaderKey.DATE] = http_date_now()

    fn __len__(self) -> Int:
        return len(self.body_raw)

    fn get_body(self) -> StringSlice[origin_of(self.body_raw)]:
        return StringSlice(unsafe_from_utf8=Span(self.body_raw))

    @always_inline
    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn connection_close(self) -> Bool:
        var result = self.headers.get(HeaderKey.CONNECTION)
        if not result:
            return False
        return result.value() == "close"

    @always_inline
    fn set_connection_keep_alive(mut self):
        self.headers[HeaderKey.CONNECTION] = "keep-alive"

    @always_inline
    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = String(l)

    @always_inline
    fn content_length(self) -> Int:
        var header_val = self.headers.get(HeaderKey.CONTENT_LENGTH)
        if not header_val:
            return 0
        try:
            return Int(header_val.value())
        except:
            return 0

    @always_inline
    fn is_redirect(self) -> Bool:
        return (
            self.status_code == StatusCode.MOVED_PERMANENTLY
            or self.status_code == StatusCode.FOUND
            or self.status_code == StatusCode.TEMPORARY_REDIRECT
            or self.status_code == StatusCode.PERMANENT_REDIRECT
        )

    @always_inline
    fn read_body(mut self, mut r: ByteReader) raises:
        try:
            self.body_raw = Bytes(r.read_bytes(self.content_length()).as_bytes())
            self.set_content_length(len(self.body_raw))
        except e:
            raise Error(String(e))

    fn read_chunks(mut self, chunks: Span[Byte]) raises:
        var reader = ByteReader(chunks)
        while True:
            var size = atol(String(reader.read_line()), 16)
            if size == 0:
                break
            try:
                var data = reader.read_bytes(size).as_bytes()
                reader.skip_carriage_return()
                self.set_content_length(self.content_length() + len(data))
                self.body_raw.extend(data)
            except e:
                raise Error(String(e))

    fn write_to[T: Writer](self, mut writer: T):
        writer.write(
            self.protocol,
            whitespace,
            self.status_code,
            whitespace,
            self.status_text,
            lineBreak,
        )

        if HeaderKey.SERVER not in self.headers:
            writer.write("server: lightbug_http", lineBreak)

        writer.write(
            self.headers,
            self.cookies,
            lineBreak,
            StringSlice(unsafe_from_utf8=Span(self.body_raw)),
        )

    fn encode(deinit self) -> Bytes:
        """Encodes response as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(
            self.protocol,
            whitespace,
            String(self.status_code),
            whitespace,
            self.status_text,
            lineBreak,
            "server: lightbug_http",
            lineBreak,
        )
        if HeaderKey.DATE not in self.headers:
            write_header(writer, HeaderKey.DATE, http_date_now())
        self.headers.write_latin1_to(writer)
        writer.write(self.cookies, lineBreak)
        writer.consuming_write(self.body_raw^)
        return writer^.consume()

    fn __str__(self) -> String:
        return String.write(self)
