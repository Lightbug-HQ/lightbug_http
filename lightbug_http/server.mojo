from io.write import _WriteBufferStack

from lightbug_http.address import NetworkType
from lightbug_http.connection import ListenConfig, NoTLSListener, TCPConnection, default_buffer_size
from lightbug_http.header import Headers
from lightbug_http.http.common_response import BadRequest, InternalError, URITooLong
from lightbug_http.io.bytes import Bytes, BytesConstant, ByteView
from lightbug_http.io.sync import Duration
from lightbug_http.service import HTTPService
from lightbug_http.socket import Socket
from lightbug_http.uri import URI

from lightbug_http.http import HTTPRequest, encode


comptime DefaultConcurrency: Int = 256 * 1024
comptime default_max_request_body_size = 4 * 1024 * 1024
comptime default_max_request_uri_length = 8192
comptime default_max_header_size = 8192
comptime default_header_read_timeout_ms = 30_000


struct ReadResult:
    """Result of a read operation with error context.

    Attributes:
        success: Whether the read operation completed successfully.
        eof: Whether EOF was reached (client closed connection cleanly).
        error_msg: Error message if operation failed.
    """

    var success: Bool
    var eof: Bool
    var error_msg: String

    fn __init__(out self, success: Bool, eof: Bool = False, error_msg: String = ""):
        self.success = success
        self.eof = eof
        self.error_msg = error_msg


struct Server(Movable):
    """HTTP/1.1 server implementation"""

    var tcp_keep_alive: Bool
    var _address: String
    var _max_request_body_size: Int
    var _max_request_uri_length: Int
    var _max_header_size: Int

    fn __init__(
        out self,
        var address: String = "127.0.0.1",
        max_request_body_size: Int = default_max_request_body_size,
        max_request_uri_length: Int = default_max_request_uri_length,
        max_header_size: Int = default_max_header_size,
        tcp_keep_alive: Bool = False,
    ):
        self._address = address^
        self._max_request_body_size = max_request_body_size
        self._max_request_uri_length = max_request_uri_length
        self._max_header_size = max_header_size
        self.tcp_keep_alive = tcp_keep_alive

    fn address(self) -> ref [self._address] String:
        return self._address

    fn set_address(mut self, var own_address: String) -> None:
        self._address = own_address^

    fn max_request_body_size(self) -> Int:
        return self._max_request_body_size

    fn set_max_request_body_size(mut self, size: Int) -> None:
        self._max_request_body_size = size

    fn max_request_uri_length(self) -> Int:
        return self._max_request_uri_length

    fn set_max_request_uri_length(mut self, length: Int) -> None:
        self._max_request_uri_length = length

    fn max_header_size(self) -> Int:
        return self._max_header_size

    fn set_max_header_size(mut self, size: Int) -> None:
        self._max_header_size = size

    fn listen_and_serve[T: HTTPService](mut self, address: StringSlice, mut handler: T) raises:
        """Listen for incoming connections and serve HTTP requests.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            address: The address (host:port) to listen on.
            handler: An object that handles incoming HTTP requests.
        """
        var listener = ListenConfig().listen(address)
        self.set_address(String(address))
        self.serve(listener, handler)

    fn serve[T: HTTPService](self, ln: NoTLSListener, mut handler: T) raises:
        """Serve HTTP requests.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            ln: TCP server that listens for incoming connections.
            handler: An object that handles incoming HTTP requests.

        Raises:
            If there is an error while serving requests.
        """
        while True:
            var conn = ln.accept()
            try:
                self.serve_connection(conn, handler)
            finally:
                conn^.teardown()

    fn serve_connection[T: HTTPService](self, mut conn: TCPConnection, mut handler: T) raises -> None:
        """Serve a single connection with keep-alive support.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            conn: A connection object that represents a client connection.
            handler: An object that handles incoming HTTP requests.
        """
        var max_request_body_size = self.max_request_body_size()
        if max_request_body_size <= 0:
            max_request_body_size = default_max_request_body_size

        var max_request_uri_length = self.max_request_uri_length()
        if max_request_uri_length <= 0:
            max_request_uri_length = default_max_request_uri_length

        var max_header_size = self.max_header_size()
        if max_header_size <= 0:
            max_header_size = default_max_header_size

        var request_buffer = Bytes()

        while True:
            request_buffer.clear()

            # Read headers from connection
            var read_result = self._read_headers(request_buffer, conn, max_header_size)
            if not read_result.success:
                break

            # Parse and handle request
            var response_sent = False
            try:
                var request = HTTPRequest.from_bytes(
                    self.address(), max_request_body_size, max_request_uri_length, request_buffer
                )

                var close_connection = (not self.tcp_keep_alive) or request.connection_close()
                var response: HTTPResponse

                try:
                    response = handler.func(request)

                    if close_connection:
                        response.set_connection_close()

                    _ = conn.write(encode(response^))
                    response_sent = True

                    if close_connection:
                        break

                except handler_error:
                    if not response_sent and not conn.is_closed():
                        try:
                            _ = conn.write(encode(InternalError()))
                        except:
                            pass
                    break

            except parse_error:
                if not response_sent and not conn.is_closed():
                    try:
                        var error_str = String(parse_error)
                        if error_str == "HTTPRequest.from_bytes: Request URI too long":
                            _ = conn.write(encode(URITooLong()))
                        else:
                            _ = conn.write(encode(BadRequest()))
                    except:
                        pass
                break

    fn _read_headers(
        self,
        mut request_buffer: Bytes,
        conn: TCPConnection,
        max_header_size: Int,
    ) raises -> ReadResult:
        """Read HTTP headers.

        Args:
            request_buffer: Buffer to accumulate request data (cleared by caller)
            conn: TCP connection to read from
            max_header_size: Maximum allowed header size (security limit)

        Returns:
            ReadResult indicating success/failure, EOF status, and error message
        """
        var read_buffer = Bytes(capacity=default_buffer_size)
        var total_header_bytes = 0

        while True:
            var bytes_read: UInt

            try:
                bytes_read = conn.read(read_buffer)
            except e:
                var error_str = String(e)

                if error_str == "EOF":
                    # EOF can mean two things:
                    # 1. Clean close: client closed before sending anything (buffer empty)
                    # 2. Incomplete request: client closed mid-request (buffer has partial data)

                    if len(request_buffer) == 0:
                        return ReadResult(success=False, eof=True)
                    else:
                        return ReadResult(success=False, error_msg="Unexpected EOF mid-request")
                else:
                    return ReadResult(success=False, error_msg=error_str)

            if bytes_read == 0:
                return ReadResult(success=False, eof=True)

            request_buffer.extend(read_buffer^)
            total_header_bytes += Int(bytes_read)

            # Security check: prevent excessive header size (slowloris protection)
            if total_header_bytes > max_header_size:
                return ReadResult(success=False, error_msg="Headers too large")

            if BytesConstant.DOUBLE_CRLF in ByteView(request_buffer):
                return ReadResult(success=True)

            read_buffer = Bytes(capacity=default_buffer_size)
