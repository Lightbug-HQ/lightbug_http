from collections import Optional

from lightbug_http.connection import TCPConnection, default_buffer_size
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter, byte, bytes
from lightbug_http.strings import lineBreak, nChar, rChar, strHttp, strHttp11, strSlash, to_string, whitespace
from lightbug_http.uri import URI

from lightbug_http.external.small_time.small_time import now


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
    fn from_bytes(b: Span[Byte]) raises -> HTTPResponse:
        var reader = ByteReader(b)
        var headers = Headers()
        var cookies = ResponseCookieJar()
        var protocol: String
        var status_code: String
        var status_text: String

        try:
            var properties = headers.parse_raw(reader)
            protocol, status_code, status_text = properties[0], properties[1], properties[2]
            cookies.from_headers(properties[3])
            reader.skip_carriage_return()
        except e:
            raise Error("Failed to parse response headers: " + String(e))

        try:
            return HTTPResponse(
                reader=reader,
                headers=headers,
                cookies=cookies,
                protocol=protocol,
                status_code=Int(status_code),
                status_text=status_text,
            )
        except e:
            logger.error(e)
            raise Error("Failed to read request body")

    @staticmethod
    fn from_bytes(b: Span[Byte], conn: TCPConnection) raises -> HTTPResponse:
        var reader = ByteReader(b)
        var headers = Headers()
        var cookies = ResponseCookieJar()
        var protocol: String
        var status_code: String
        var status_text: String

        try:
            var properties = headers.parse_raw(reader)
            protocol, status_code, status_text = properties[0], properties[1], properties[2]
            cookies.from_headers(properties[3])
            reader.skip_carriage_return()
        except e:
            raise Error("Failed to parse response headers: " + String(e))

        var response = HTTPResponse(
            Bytes(),
            headers=headers,
            cookies=cookies,
            protocol=protocol,
            status_code=Int(status_code),
            status_text=status_text,
        )

        var transfer_encoding = response.headers.get(HeaderKey.TRANSFER_ENCODING)
        if transfer_encoding and transfer_encoding.value() == "chunked":
            var b = reader.read_bytes().to_bytes()
            var buff = Bytes(capacity=default_buffer_size)
            try:
                while conn.read(buff) > 0:
                    b += buff.copy()

                    if (
                        buff[-5] == byte("0")
                        and buff[-4] == byte("\r")
                        and buff[-3] == byte("\n")
                        and buff[-2] == byte("\r")
                        and buff[-1] == byte("\n")
                    ):
                        break

                    # buff.clear()
                response.read_chunks(b)
                return response^
            except e:
                logger.error(e)
                raise Error("Failed to read chunked response.")

        try:
            response.read_body(reader)
            return response^
        except e:
            logger.error(e)
            raise Error("Failed to read request body: ")

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
                logger.debug("DATE header not set, unable to get current time and it was instead omitted.")

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
        self.body_raw = reader.read_bytes().to_bytes()
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
        self.body_raw = r.read_bytes(self.content_length()).to_bytes()
        self.set_content_length(len(self.body_raw))

    fn read_chunks(mut self, chunks: Span[Byte]) raises:
        var reader = ByteReader(chunks)
        while True:
            var size = atol(String(reader.read_line()), 16)
            if size == 0:
                break
            var data = reader.read_bytes(size).to_bytes()
            reader.skip_carriage_return()
            self.set_content_length(self.content_length() + len(data))
            self.body_raw += data^

    fn write_to[T: Writer](self, mut writer: T):
        writer.write(self.protocol, whitespace, self.status_code, whitespace, self.status_text, lineBreak)

        if HeaderKey.SERVER not in self.headers:
            writer.write("server: lightbug_http", lineBreak)

        writer.write(self.headers, self.cookies, lineBreak, to_string(self.body_raw.copy()))

    fn encode(var self) -> Bytes:
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
        self.body_raw = Bytes()
        return writer^.consume()

    fn __str__(self) -> String:
        return String.write(self)
