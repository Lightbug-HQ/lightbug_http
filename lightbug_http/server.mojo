from lightbug_http.io.sync import Duration
from lightbug_http.io.bytes import Bytes, BytesConstant, ByteView, ByteReader, bytes
from lightbug_http.address import NetworkType
from lightbug_http._logger import logger
from lightbug_http.connection import NoTLSListener, default_buffer_size, TCPConnection, ListenConfig
from lightbug_http.socket import Socket
from lightbug_http.http import HTTPRequest, encode
from lightbug_http.http.common_response import InternalError, BadRequest, URITooLong
from lightbug_http.uri import URI
from lightbug_http.header import Headers
from lightbug_http.service import HTTPService
from lightbug_http.error import ErrorHandler


alias DefaultConcurrency: Int = 256 * 1024
alias default_max_request_body_size = 4 * 1024 * 1024  # 4MB
alias default_max_request_uri_length = 8192


struct Server(Movable):
    """A Mojo-based server that accept incoming requests and delivers HTTP services."""

    var error_handler: ErrorHandler

    var name: String
    var _address: String
    var max_concurrent_connections: UInt
    var max_requests_per_connection: UInt

    var _max_request_body_size: UInt
    var _max_request_uri_length: UInt
    var tcp_keep_alive: Bool

    fn __init__(
        out self,
        error_handler: ErrorHandler = ErrorHandler(),
        name: String = "lightbug_http",
        address: String = "127.0.0.1",
        max_concurrent_connections: UInt = 1000,
        max_requests_per_connection: UInt = 0,
        max_request_body_size: UInt = default_max_request_body_size,
        max_request_uri_length: UInt = default_max_request_uri_length,
        tcp_keep_alive: Bool = False,
    ) raises:
        self.error_handler = error_handler
        self.name = name
        self._address = address
        self.max_requests_per_connection = max_requests_per_connection
        self._max_request_body_size = max_request_body_size
        self._max_request_uri_length = max_request_uri_length
        self.tcp_keep_alive = tcp_keep_alive
        if max_concurrent_connections == 0:
            self.max_concurrent_connections = DefaultConcurrency
        else:
            self.max_concurrent_connections = max_concurrent_connections

    fn __moveinit__(out self, owned other: Server):
        self.error_handler = other.error_handler^
        self.name = other.name^
        self._address = other._address^
        self.max_concurrent_connections = other.max_concurrent_connections
        self.max_requests_per_connection = other.max_requests_per_connection
        self._max_request_body_size = other._max_request_body_size
        self._max_request_uri_length = other._max_request_uri_length
        self.tcp_keep_alive = other.tcp_keep_alive

    fn address(self) -> ref [self._address] String:
        return self._address

    fn set_address(mut self, own_address: String) -> None:
        self._address = own_address

    fn max_request_body_size(self) -> UInt:
        return self._max_request_body_size

    fn set_max_request_body_size(mut self, size: UInt) -> None:
        self._max_request_body_size = size

    fn max_request_uri_length(self) -> UInt:
        return self._max_request_uri_length

    fn set_max_request_uri_length(mut self, length: UInt) -> None:
        self._max_request_uri_length = length

    fn get_concurrency(self) -> UInt:
        """Retrieve the concurrency level which is either
        the configured `max_concurrent_connections` or the `DefaultConcurrency`.

        Returns:
            Concurrency level for the server.
        """
        return self.max_concurrent_connections

    fn listen_and_serve[T: HTTPService](mut self, address: String, mut handler: T) raises:
        """Listen for incoming connections and serve HTTP requests.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            address: The address (host:port) to listen on.
            handler: An object that handles incoming HTTP requests.
        """
        var config = ListenConfig()
        var listener = config.listen(address)
        self.set_address(address)
        self.serve(listener^, handler)

    fn serve[T: HTTPService](mut self, owned ln: NoTLSListener, mut handler: T) raises:
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
            self.serve_connection(conn, handler)

    fn serve_connection[T: HTTPService](mut self, mut conn: TCPConnection, mut handler: T) raises -> None:
        """Serve a single connection.
        Parameters:
            T: The type of HTTPService that handles incoming requests.
        Args:
            conn: A connection object that represents a client connection.
            handler: An object that handles incoming HTTP requests.
        Raises:
            If there is an error while serving the connection.
        """
        logger.debug(
            "Connection accepted! IP:", conn.socket._remote_address.ip, "Port:", conn.socket._remote_address.port
        )
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
                try:
                    var temp_buffer = Bytes(capacity=default_buffer_size)
                    var bytes_read = conn.read(temp_buffer)
                    logger.debug("Bytes read:", bytes_read)

                    if bytes_read == 0:
                        conn.teardown()
                        return

                    request_buffer.extend(temp_buffer^)
                    logger.debug("Total buffer size:", len(request_buffer))

                    if BytesConstant.DOUBLE_CRLF in ByteView(request_buffer):
                        logger.debug("Found end of headers")
                        break

                except e:
                    conn.teardown()
                    # 0 bytes were read from the peer, which indicates their side of the connection was closed.
                    if String(e) == "EOF":
                        return
                    else:
                        logger.error("Server.serve_connection: Failed to read request. Expected EOF, got:", String(e))
                        return

            var request: HTTPRequest
            try:
                request = HTTPRequest.from_bytes(self.address(), max_request_body_size, max_request_uri_length, request_buffer)
                var response: HTTPResponse
                var close_connection = (not self.tcp_keep_alive) or request.connection_close()
                try:
                    response = handler.func(request)
                    if close_connection:
                        response.set_connection_close()
                    logger.debug(
                        conn.socket._remote_address.ip,
                        String(conn.socket._remote_address.port),
                        request.method,
                        request.uri.path,
                        response.status_code,
                    )
                    try:
                        _ = conn.write(encode(response^))
                    except e:
                        logger.error("Failed to write encoded response to the connection:", String(e))
                        conn.teardown()
                        break

                    if close_connection:
                        conn.teardown()
                        break
                except e:
                    logger.error("Handler error:", String(e))
                    if not conn.is_closed():
                        try:
                            _ = conn.write(encode(InternalError()))
                        except e:
                            raise Error("Failed to send InternalError response")
                        finally:
                            conn.teardown()
                        return
            except e:
                logger.error("Failed to parse HTTPRequest:", String(e))
                try:
                    if String(e) == "HTTPRequest.from_bytes: Request URI too long":
                        _ = conn.write(encode(URITooLong()))
                    else:
                        _ = conn.write(encode(BadRequest()))
                except e:
                    logger.error("Failed to write BadRequest response to the connection:", String(e))
                    conn.teardown()
                    break
