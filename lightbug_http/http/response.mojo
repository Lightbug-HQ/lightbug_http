from lightbug_http.connection import TCPConnection, default_buffer_size
from lightbug_http.header import ParsedResponseResult
from lightbug_http.http.chunked import HTTPChunkedDecoder, decode
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter, byte
from lightbug_http.strings import CR, LF, http, lineBreak, strHttp11, whitespace
from lightbug_http.uri import URI
from small_time.small_time import now
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
    comptime OK = 200
    comptime MOVED_PERMANENTLY = 301
    comptime FOUND = 302
    comptime TEMPORARY_REDIRECT = 307
    comptime PERMANENT_REDIRECT = 308
    comptime NOT_FOUND = 404
    comptime INTERNAL_ERROR = 500


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
        var reader = ByteReader(b)
        var headers = Headers()
        var cookies = ResponseCookieJar()

        var properties: ParsedResponseResult
        try:
            properties = headers.parse_raw_response(reader)
            cookies.from_headers(properties.cookies^)
            reader.skip_carriage_return()
        except parse_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(parse_err)))

        try:
            return HTTPResponse(
                reader=reader,
                headers=headers^,
                cookies=cookies^,
                protocol=properties.protocol^,
                status_code=properties.status,
                status_text=properties.msg^,
            )
        except body_err:
            raise ResponseParseError(ResponseBodyReadError(detail=String(body_err)))

    @staticmethod
    fn from_bytes(b: Span[Byte], conn: TCPConnection) raises ResponseParseError -> HTTPResponse:
        var reader = ByteReader(b)
        var headers = Headers()
        var cookies = ResponseCookieJar()

        var properties: ParsedResponseResult
        try:
            properties = headers.parse_raw_response(reader)
            cookies.from_headers(properties.cookies^)
            reader.skip_carriage_return()
        except parse_err:
            raise ResponseParseError(ResponseHeaderParseError(detail=String(parse_err)))

        var response = HTTPResponse(
            Bytes(),
            headers=headers^,
            cookies=cookies^,
            protocol=properties.protocol^,
            status_code=properties.status,
            status_text=properties.msg^,
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
                # response.read_chunks(b)
                # Decode chunks
                response._decode_chunks(decoder, b^)
                return response^
            except chunk_err:
                raise ResponseParseError(ChunkedEncodingError(detail=String(chunk_err)))

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
        var result = decode(decoder, Span(chunks))
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
            try:
                var current_time = String(now(utc=True))
                self.headers[HeaderKey.DATE] = current_time
            except:
                pass

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
            try:
                var current_time = String(now(utc=True))
                self.headers[HeaderKey.DATE] = current_time
            except:
                pass

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
        try:
            return Int(self.headers[HeaderKey.CONTENT_LENGTH])
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
    fn read_body(mut self, mut r: ByteReader) raises -> None:
        self.body_raw = Bytes(r.read_bytes(self.content_length()).as_bytes())
        self.set_content_length(len(self.body_raw))

    fn read_chunks(mut self, chunks: Span[Byte]) raises:
        var reader = ByteReader(chunks)
        while True:
            var size = atol(String(reader.read_line()), 16)
            if size == 0:
                break
            var data = reader.read_bytes(size).as_bytes()
            reader.skip_carriage_return()
            self.set_content_length(self.content_length() + len(data))
            self.body_raw.extend(data)

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
            StringSlice(unsafe_from_utf8=self.body_raw),
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
            try:
                write_header(writer, HeaderKey.DATE, String(now(utc=True)))
            except:
                pass
        writer.write(self.headers, self.cookies, lineBreak)
        writer.consuming_write(self.body_raw^)
        return writer^.consume()

    fn __str__(self) -> String:
        return String.write(self)
