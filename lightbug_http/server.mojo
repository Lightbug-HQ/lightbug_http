from io.write import _WriteBufferStack

from lightbug_http.address import NetworkType
from lightbug_http.connection import ListenConfig, NoTLSListener, TCPConnection, default_buffer_size
from lightbug_http.header import Headers
from lightbug_http.http.common_response import BadRequest, InternalError, URITooLong
from lightbug_http.io.bytes import Bytes, BytesConstant, ByteView
from lightbug_http.io.sync import Duration
from lightbug_http.service import HTTPService
from lightbug_http.socket import EOF, Socket, SocketError
from lightbug_http.uri import URI

from lightbug_http.http import HTTPRequest, encode


comptime DefaultConcurrency: Int = 256 * 1024
comptime default_max_request_body_size = 4 * 1024 * 1024  # 4MB
comptime default_max_request_uri_length = 8192


struct Server(Movable):
    """A Mojo-based server that accept incoming requests and delivers HTTP services."""

    var tcp_keep_alive: Bool
    var _address: String
    var _max_request_body_size: Int
    var _max_request_uri_length: Int

    fn __init__(
        out self,
        var address: String = "127.0.0.1",
        max_request_body_size: Int = default_max_request_body_size,
        max_request_uri_length: Int = default_max_request_uri_length,
        tcp_keep_alive: Bool = False,
    ):
        self._address = address^
        self._max_request_body_size = max_request_body_size
        self._max_request_uri_length = max_request_uri_length
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

    fn listen_and_serve[T: HTTPService](mut self, address: StringSlice, mut handler: T) raises SocketError:
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

    fn serve[T: HTTPService](self, ln: NoTLSListener, mut handler: T) raises SocketError:
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
        """Serve a single connection.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            conn: A connection object that represents a client connection.
            handler: An object that handles incoming HTTP requests.

        Raises:
            If there is an error while serving the connection.
        """
        var max_request_body_size = self.max_request_body_size()
        if max_request_body_size <= 0:
            max_request_body_size = default_max_request_body_size

        var max_request_uri_length = self.max_request_uri_length()
        if max_request_uri_length <= 0:
            max_request_uri_length = default_max_request_uri_length

        var req_number = 0
        while True:
            req_number += 1

            var request_buffer = Bytes()
            while True:
                # If the read_request returns False, it means the connection was closed, an error occurred, or no bytes were read.
                if not read_request(request_buffer, conn, max_request_body_size, max_request_uri_length):
                    return

                if BytesConstant.DOUBLE_CRLF in ByteView(request_buffer):
                    break

            var request: HTTPRequest
            try:
                request = HTTPRequest.from_bytes(
                    self.address(), max_request_body_size, max_request_uri_length, request_buffer
                )
            except e:
                try:
                    # if String(e) == "HTTPRequest.from_bytes: Request URI too long":
                    #     _ = conn.write(encode(URITooLong()))
                    # else:
                    _ = conn.write(encode(BadRequest()))
                except:
                    pass
                finally:
                    break

            try:
                var response: HTTPResponse
                var close_connection = (not self.tcp_keep_alive) or request.connection_close()
                try:
                    response = handler.func(request)
                    if close_connection:
                        response.set_connection_close()
                    try:
                        _ = conn.write(encode(response^))
                    except e:
                        break

                    if close_connection:
                        break
                except e:
                    if not conn.is_closed():
                        try:
                            _ = conn.write(encode(InternalError()))
                        except:
                            raise Error("Failed to send InternalError response")
                        return
            except e:
                try:
                    # if String(e) == "HTTPRequest.from_bytes: Request URI too long":
                    #     _ = conn.write(encode(URITooLong()))
                    # else:
                    _ = conn.write(encode(BadRequest()))
                except:
                    break


fn read_request(
    mut request_buffer: Bytes, conn: TCPConnection, max_request_body_size: Int, max_request_uri_length: Int
) -> Bool:
    var buffer = Bytes(capacity=default_buffer_size)
    var bytes_read: UInt
    try:
        bytes_read = conn.read(buffer)
    except e:
        # If EOF, 0 bytes were read from the peer, which indicates their side of the connection was closed.
        if e.isa[EOF]():
            pass
        return False

    if bytes_read == 0:
        return False

    request_buffer.extend(buffer^)
    return True
