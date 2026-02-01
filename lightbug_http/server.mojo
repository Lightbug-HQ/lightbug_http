from lightbug_http.connection import (
    ConnectionState,
    ListenConfig,
    ListenerError,
    NoTLSListener,
    TCPConnection,
    default_buffer_size,
)
from lightbug_http.header import (
    Headers,
    ParsedRequestHeaders,
    RequestParseError,
    find_header_end,
    parse_request_headers,
)
from lightbug_http.http.common_response import BadRequest, InternalError, URITooLong
from lightbug_http.io.bytes import Bytes, ByteView
from lightbug_http.service import HTTPService
from lightbug_http.socket import EOF, FatalCloseError, SocketAcceptError, SocketClosedError, SocketRecvError
from lightbug_http.utils.error import CustomError
from lightbug_http.utils.owning_list import OwningList
from utils import Variant

from lightbug_http.http import HTTPRequest, HTTPResponse, encode


@fieldwise_init
struct ServerError(Movable, Stringable, Writable):
    """Error variant for server operations."""

    comptime type = Variant[
        ListenerError,
        ProvisionError,
        SocketAcceptError,
        SocketRecvError,
        FatalCloseError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, var value: ListenerError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: ProvisionError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: SocketAcceptError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: SocketRecvError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: FatalCloseError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[ListenerError]():
            writer.write(self.value[ListenerError])
        elif self.value.isa[ProvisionError]():
            writer.write(self.value[ProvisionError])
        elif self.value.isa[SocketAcceptError]():
            writer.write(self.value[SocketAcceptError])
        elif self.value.isa[SocketRecvError]():
            writer.write(self.value[SocketRecvError])
        elif self.value.isa[FatalCloseError]():
            writer.write(self.value[FatalCloseError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct ServerConfig(Copyable, Movable):
    """Configuration for the HTTP server."""

    var max_connections: Int
    """Maximum number of concurrent connections."""

    var max_keepalive_requests: Int
    """Maximum requests per keepalive connection (0 = unlimited)."""

    var socket_buffer_size: Int
    """Size of socket read buffer."""

    var recv_buffer_max: Int
    """Maximum total receive buffer size."""

    var max_request_body_size: Int
    """Maximum request body size."""

    var max_request_uri_length: Int
    """Maximum URI length."""

    fn __init__(out self):
        self.max_connections = 1024
        self.max_keepalive_requests = 0

        self.socket_buffer_size = default_buffer_size
        self.recv_buffer_max = 2 * 1024 * 1024  # 2MB

        self.max_request_body_size = 4 * 1024 * 1024  # 4MB
        self.max_request_uri_length = 8192


@fieldwise_init
struct BodyReadState(Copyable, ImplicitlyCopyable, Movable):
    """State for body reading phase."""

    var content_length: Int
    """Total expected body length from Content-Length header."""

    var bytes_read: Int
    """Bytes of body read so far."""

    var header_end_offset: Int
    """Offset in recv_buffer where headers end and body begins."""


@fieldwise_init
struct ConnectionProvision(Movable):
    """All resources needed to handle a connection.

    Pre-allocated and reused (pooled) across connections.
    """

    var recv_buffer: Bytes
    """Accumulated receive data."""

    var parsed_headers: Optional[ParsedRequestHeaders]
    """Parsed headers (available after header parsing completes)."""

    var request: Optional[HTTPRequest]
    """Constructed request (available after body is complete)."""

    var response: Optional[HTTPResponse]
    """Response to send."""

    var state: ConnectionState
    """Current state in the connection state machine."""

    var body_state: Optional[BodyReadState]
    """Body reading state (only valid during READING_BODY)."""

    var last_parse_len: Int
    """Length of buffer at last parse attempt (for incremental parsing)."""

    var keepalive_count: Int
    """Number of requests handled on this connection."""

    var should_close: Bool
    """Whether to close connection after response."""

    fn __init__(out self, config: ServerConfig):
        self.recv_buffer = Bytes(capacity=config.socket_buffer_size)
        self.parsed_headers = None
        self.request = None
        self.response = None
        self.state = ConnectionState.reading_headers()
        self.body_state = None
        self.last_parse_len = 0
        self.keepalive_count = 0
        self.should_close = False

    fn prepare_for_new_request(mut self):
        """Reset provision for next request in keepalive connection."""
        self.parsed_headers = None
        self.request = None
        self.response = None
        self.recv_buffer.clear()
        self.state = ConnectionState.reading_headers()
        self.body_state = None
        self.last_parse_len = 0
        self.should_close = False


@fieldwise_init
@register_passable("trivial")
struct ProvisionPoolExhaustedError(CustomError):
    comptime message = "ProvisionError: Connection provision pool exhausted"

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(self.message)

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct ProvisionError(Movable, Stringable, Writable):
    """Error variant for provision pool operations."""

    comptime type = Variant[ProvisionPoolExhaustedError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: ProvisionPoolExhaustedError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(self.value[ProvisionPoolExhaustedError])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


struct ProvisionPool(Movable):
    """Pool of ConnectionProvision objects for reuse across connections."""

    var provisions: OwningList[ConnectionProvision]
    var available: OwningList[Int]
    var capacity: Int
    var initialized_count: Int

    fn __init__(out self, capacity: Int, config: ServerConfig):
        self.provisions = OwningList[ConnectionProvision](capacity=capacity)
        self.available = OwningList[Int](capacity=capacity)
        self.capacity = capacity
        self.initialized_count = 0

        for i in range(capacity):
            self.provisions.append(ConnectionProvision(config))
            self.available.append(i)
            self.initialized_count += 1

    fn borrow(mut self) raises ProvisionError -> Int:
        if len(self.available) == 0:
            raise ProvisionPoolExhaustedError()
        return self.available.pop()

    fn release(mut self, index: Int):
        self.available.append(index)

    fn get_ptr(mut self, index: Int) -> Pointer[ConnectionProvision, origin_of(self.provisions)]:
        return Pointer(to=self.provisions[index])

    fn size(self) -> Int:
        return self.initialized_count - len(self.available)


fn handle_connection[
    T: HTTPService
](
    mut conn: TCPConnection,
    mut provision: ConnectionProvision,
    mut handler: T,
    config: ServerConfig,
    server_address: String,
    tcp_keep_alive: Bool,
) raises SocketRecvError:
    """Handle a single HTTP connection through its lifecycle.

    Args:
        conn: The TCP connection to handle.
        provision: Pre-allocated resources for this connection.
        handler: The HTTP service handler.
        config: Server configuration.
        server_address: The server's address string.
        tcp_keep_alive: Whether to enable TCP keep-alive.

    Raises:
        SocketRecvError: If a socket read operation fails (not including clean EOF/close).
    """
    while True:
        if provision.state.kind == ConnectionState.READING_HEADERS:
            var buffer = Bytes(capacity=config.socket_buffer_size)
            var bytes_read: UInt

            try:
                bytes_read = conn.read(buffer)
            except read_err:
                if read_err.isa[EOF]() or read_err.isa[SocketClosedError]():
                    provision.state = ConnectionState.closed()
                    break
                raise read_err^

            if bytes_read == 0:
                provision.state = ConnectionState.closed()
                break

            var prev_len = len(provision.recv_buffer)
            provision.recv_buffer.extend(buffer^)

            if len(provision.recv_buffer) > config.recv_buffer_max:
                _send_error_response(conn, BadRequest())
                provision.state = ConnectionState.closed()
                break

            var search_start = prev_len
            if search_start > 3:
                search_start -= 3  # Account for partial \r\n\r\n match

            var header_end = find_header_end(
                Span(provision.recv_buffer),
                search_start,
            )

            if header_end:
                var header_end_offset = header_end.value()
                var parsed: ParsedRequestHeaders
                try:
                    parsed = parse_request_headers(
                        Span(provision.recv_buffer)[:header_end_offset],
                        provision.last_parse_len,
                    )
                except parse_err:
                    if parse_err.isa[RequestParseError]():
                        # TODO: Differentiate errors
                        _send_error_response(conn, BadRequest())
                    else:
                        _send_error_response(conn, BadRequest())
                    provision.state = ConnectionState.closed()
                    break

                if len(parsed.path) > config.max_request_uri_length:
                    _send_error_response(conn, URITooLong())
                    provision.state = ConnectionState.closed()
                    break

                var content_length = parsed.content_length()

                if content_length > config.max_request_body_size:
                    _send_error_response(conn, BadRequest())
                    provision.state = ConnectionState.closed()
                    break

                var body_bytes_in_buffer = len(provision.recv_buffer) - header_end_offset

                provision.parsed_headers = parsed^

                if content_length > 0:
                    provision.body_state = BodyReadState(
                        content_length=content_length,
                        bytes_read=body_bytes_in_buffer,
                        header_end_offset=header_end_offset,
                    )
                    provision.state = ConnectionState.reading_body(content_length)
                else:
                    provision.state = ConnectionState.processing()

            provision.last_parse_len = len(provision.recv_buffer)

        elif provision.state.kind == ConnectionState.READING_BODY:
            var body_st = provision.body_state.value()

            if body_st.bytes_read >= body_st.content_length:
                provision.state = ConnectionState.processing()
                continue

            var buffer = Bytes(capacity=config.socket_buffer_size)
            var bytes_read: UInt

            try:
                bytes_read = conn.read(buffer)
            except read_err:
                if read_err.isa[EOF]() or read_err.isa[SocketClosedError]():
                    provision.state = ConnectionState.closed()
                    break
                raise read_err^

            if bytes_read == 0:
                provision.state = ConnectionState.closed()
                break

            provision.recv_buffer.extend(buffer^)
            body_st.bytes_read += Int(bytes_read)
            provision.body_state = body_st

            if len(provision.recv_buffer) > config.recv_buffer_max:
                _send_error_response(conn, BadRequest())
                provision.state = ConnectionState.closed()
                break

            if body_st.bytes_read >= body_st.content_length:
                provision.state = ConnectionState.processing()

        elif provision.state.kind == ConnectionState.PROCESSING:
            var parsed = provision.parsed_headers.take()

            var body = Bytes()
            if provision.body_state:
                var body_st = provision.body_state.value()
                var body_start = body_st.header_end_offset
                var body_end = body_start + body_st.content_length

                if body_end <= len(provision.recv_buffer):
                    body = Bytes(capacity=body_st.content_length)
                    for i in range(body_start, body_end):
                        body.append(provision.recv_buffer[i])

            var request: HTTPRequest
            try:
                request = HTTPRequest.from_parsed(
                    server_address,
                    parsed^,
                    body^,
                    config.max_request_uri_length,
                )
            except build_err:
                _send_error_response(conn, BadRequest())
                provision.state = ConnectionState.closed()
                break

            provision.should_close = (not tcp_keep_alive) or request.connection_close()

            var response: HTTPResponse
            try:
                response = handler.func(request^)
            except handler_err:
                response = InternalError()
                provision.should_close = True

            if (not provision.should_close) and (config.max_keepalive_requests > 0):
                if (provision.keepalive_count + 1) >= config.max_keepalive_requests:
                    provision.should_close = True

            if provision.should_close:
                response.set_connection_close()

            provision.response = response^
            provision.state = ConnectionState.responding()

        elif provision.state.kind == ConnectionState.RESPONDING:
            var response = provision.response.take()

            try:
                _ = conn.write(encode(response^))
            except write_err:
                provision.state = ConnectionState.closed()
                break

            if provision.should_close:
                provision.state = ConnectionState.closed()
                break

            if (config.max_keepalive_requests > 0) and (provision.keepalive_count >= config.max_keepalive_requests):
                provision.state = ConnectionState.closed()
                break

            provision.keepalive_count += 1
            provision.prepare_for_new_request()

        else:
            break


struct Server(Movable):
    """HTTP/1.1 Server implementation."""

    var config: ServerConfig
    var _address: String
    var tcp_keep_alive: Bool

    fn __init__(
        out self,
        var address: String = "127.0.0.1",
        tcp_keep_alive: Bool = True,
    ):
        self.config = ServerConfig()
        self._address = address^
        self.tcp_keep_alive = tcp_keep_alive

    fn __init__(
        out self,
        var config: ServerConfig,
        var address: String = "127.0.0.1",
        tcp_keep_alive: Bool = True,
    ):
        self.config = config^
        self._address = address^
        self.tcp_keep_alive = tcp_keep_alive

    fn address(self) -> ref [self._address] String:
        return self._address

    fn set_address(mut self, var own_address: String):
        self._address = own_address^

    fn max_request_body_size(self) -> Int:
        return self.config.max_request_body_size

    fn set_max_request_body_size(mut self, size: Int):
        self.config.max_request_body_size = size

    fn max_request_uri_length(self) -> Int:
        return self.config.max_request_uri_length

    fn set_max_request_uri_length(mut self, length: Int):
        self.config.max_request_uri_length = length

    fn listen_and_serve[T: HTTPService](mut self, address: StringSlice, mut handler: T) raises ServerError:
        """Listen for incoming connections and serve HTTP requests.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            address: The address (host:port) to listen on.
            handler: An object that handles incoming HTTP requests.

        Raises:
            ServerError: If listener setup fails or serving encounters fatal errors.
        """
        var listener: NoTLSListener
        try:
            listener = ListenConfig().listen(address)
        except listener_err:
            raise listener_err^

        self.set_address(String(address))

        try:
            self.serve(listener, handler)
        except server_err:
            raise server_err^

    fn serve[T: HTTPService](self, ln: NoTLSListener, mut handler: T) raises ServerError:
        """Serve HTTP requests from an existing listener.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            ln: TCP server that listens for incoming connections.
            handler: An object that handles incoming HTTP requests.

        Raises:
            ServerError: If accept fails or critical connection handling errors occur.
        """
        var provision_pool = ProvisionPool(self.config.max_connections, self.config)

        while True:
            var conn: TCPConnection
            try:
                conn = ln.accept()
            except listener_err:
                raise listener_err^

            var index: Int
            try:
                index = provision_pool.borrow()
            except provision_err:
                # Pool exhausted - close the connection and continue
                try:
                    conn^.teardown()
                except:
                    pass
                continue

            try:
                handle_connection(
                    conn,
                    provision_pool.provisions[index],
                    handler,
                    self.config,
                    self.address(),
                    self.tcp_keep_alive,
                )
            except socket_err:
                # Connection handling failed - just close the connection
                pass
            finally:
                # Always clean up the connection and return provision to pool
                try:
                    conn^.teardown()
                except:
                    pass
                provision_pool.provisions[index].prepare_for_new_request()
                provision_pool.provisions[index].keepalive_count = 0
                provision_pool.release(index)


fn _send_error_response(mut conn: TCPConnection, var response: HTTPResponse):
    """Helper to send an error response, ignoring write errors."""
    try:
        _ = conn.write(encode(response^))
    except:
        pass  # Ignore write errors for error responses
