from collections import Optional
from lightbug_http.external.small_time.small_time import now
from lightbug_http.uri import URI
from lightbug_http.io.bytes import Bytes, bytes, byte, ByteReader, ByteWriter
from lightbug_http.connection import TCPConnection, default_buffer_size
from lightbug_http.strings import (
    strHttp11,
    strHttp,
    strSlash,
    whitespace,
    rChar,
    nChar,
    lineBreak,
    to_string,
)
from lightbug_http.pico import PhrChunkedDecoder, phr_decode_chunked
from memory import UnsafePointer


struct StatusCode:
    alias OK = 200
    alias MOVED_PERMANENTLY = 301
    alias FOUND = 302
    alias TEMPORARY_REDIRECT = 307
    alias PERMANENT_REDIRECT = 308
    alias NOT_FOUND = 404
    alias INTERNAL_ERROR = 500


@value
struct HTTPResponse(Writable, Stringable, Encodable, Sized):
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
                    b += buff

                    if (
                        buff[-5] == byte("0")
                        and buff[-4] == byte("\r")
                        and buff[-3] == byte("\n")
                        and buff[-2] == byte("\r")
                        and buff[-1] == byte("\n")
                    ):
                        break

                    buff.clear()
                response.read_chunks(b)
                return response
            except e:
                logger.error(e)
                raise Error("Failed to read chunked response.")

        try:
            response.read_body(reader)
            return response
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
        self.headers = headers
        self.cookies = cookies
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
        self.headers = headers
        self.cookies = cookies
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

    fn get_body(self) -> StringSlice[__origin_of(self.body_raw)]:
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
        """Decode chunked transfer encoding using the pico parser."""
        var decoder = PhrChunkedDecoder()
        decoder.consume_trailer = True  # We want to consume trailing headers
        
        # Copy chunks to a mutable buffer
        var buf_ptr = UnsafePointer[UInt8].alloc(len(chunks))
        for i in range(len(chunks)):
            buf_ptr[i] = chunks[i]
        
        var bufsz = len(chunks)
        var result = phr_decode_chunked(decoder, buf_ptr, bufsz)
        var ret = result[0]
        var decoded_size = result[1]
        
        if ret < 0 and ret != -2:
            buf_ptr.free()
            raise Error("Failed to decode chunked response: Invalid chunk format")
        
        # Copy decoded data to body
        self.body_raw.clear()
        for i in range(decoded_size):
            self.body_raw.append(buf_ptr[i])
        
        self.set_content_length(len(self.body_raw))
        buf_ptr.free()

    fn write_to[T: Writer](self, mut writer: T):
        writer.write(self.protocol, whitespace, self.status_code, whitespace, self.status_text, lineBreak)

        if HeaderKey.SERVER not in self.headers:
            writer.write("server: lightbug_http", lineBreak)

        writer.write(self.headers, self.cookies, lineBreak, to_string(self.body_raw))

    fn encode(owned self) -> Bytes:
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
