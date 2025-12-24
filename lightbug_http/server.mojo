from lightbug_http.connection import ListenConfig, NoTLSListener, TCPConnection, default_buffer_size
from lightbug_http.http.common_response import BadRequest, InternalError, URITooLong
from lightbug_http.io.bytes import ByteReader, Bytes, BytesConstant, ByteView
from lightbug_http.service import HTTPService
from lightbug_http.socket import EOF, SocketError

from lightbug_http.http import HTTPRequest, HTTPResponse, encode


@fieldwise_init
struct ServerConfig(Copyable, Movable):
    """
    Configuration for HTTP server.
    Provides explicit control over resource limits and buffer sizes.
    """

    var max_connections: Int
    var max_keepalive_requests: Int

    var socket_buffer_size: Int
    var recv_buffer_max: Int
    var recv_buffer_retain: Int  # Retained capacity after clear

    var max_request_body_size: Int
    var max_request_uri_length: Int

    fn __init__(out self):
        self.max_connections = 1024
        self.max_keepalive_requests = 0

        self.socket_buffer_size = default_buffer_size
        self.recv_buffer_max = 2 * 1024 * 1024  # 2MB
        self.recv_buffer_retain = 4096

        self.max_request_body_size = 4 * 1024 * 1024  # 4MB
        self.max_request_uri_length = 8192


struct ZeroCopyBuffer(Movable):
    """
    Growable buffer that retains capacity when cleared.
    Reduces allocations in long-lived connections.
    """

    var data: Bytes
    var written: Int
    var retain_size: Int

    fn __init__(out self, initial_capacity: Int, retain: Int):
        self.data = Bytes(capacity=initial_capacity)
        self.written = 0
        self.retain_size = retain

    fn append(mut self, var byte_data: Bytes):
        self.data.extend(byte_data^)
        self.written = len(self.data)

    fn as_bytes(self) -> Span[Byte, origin_of(self.data)]:
        return self.data

    fn clear_retaining_capacity(mut self):
        if len(self.data) > self.retain_size:
            # Shrink to retain size
            self.data = Bytes(capacity=self.retain_size)
        else:
            self.data.clear()
        self.written = 0

    fn len(self) -> Int:
        return len(self.data)


@fieldwise_init
struct RequestBodyState(Copyable, Movable):
    """State for reading request body."""

    var content_length: Int
    var bytes_read: Int


@fieldwise_init
struct ConnectionState(Copyable, Movable):
    """
    State machine for connection processing.

    States:
    - reading_headers: Accumulating request header bytes
    - reading_body: Reading request body based on Content-Length
    - processing: Invoking application handler
    - responding: Sending response to client
    - closed: Connection finished
    """

    comptime READING_HEADERS = 0
    comptime READING_BODY = 1
    comptime PROCESSING = 2
    comptime RESPONDING = 3
    comptime CLOSED = 4

    var kind: Int
    var body_state: RequestBodyState

    @staticmethod
    fn reading_headers() -> Self:
        return ConnectionState(Self.READING_HEADERS, RequestBodyState(0, 0))

    @staticmethod
    fn reading_body(content_length: Int) -> Self:
        return ConnectionState(Self.READING_BODY, RequestBodyState(content_length, 0))

    @staticmethod
    fn processing() -> Self:
        return ConnectionState(Self.PROCESSING, RequestBodyState(0, 0))

    @staticmethod
    fn responding() -> Self:
        return ConnectionState(Self.RESPONDING, RequestBodyState(0, 0))

    @staticmethod
    fn closed() -> Self:
        return ConnectionState(Self.CLOSED, RequestBodyState(0, 0))


struct ConnectionProvision(Movable):
    """
    All resources needed to handle a connection.
    Pre-allocated and reused (pooled) across connections.
    """

    var recv_buffer: ZeroCopyBuffer
    var request: Optional[HTTPRequest]
    var response: Optional[HTTPResponse]
    var state: ConnectionState
    var keepalive_count: Int
    var should_close: Bool

    fn __init__(out self, config: ServerConfig):
        self.recv_buffer = ZeroCopyBuffer(config.socket_buffer_size, config.recv_buffer_retain)
        self.request = None
        self.response = None
        self.state = ConnectionState.reading_headers()
        self.keepalive_count = 0
        self.should_close = False

    fn prepare_for_new_request(mut self):
        """Reset provision for next request in keepalive connection."""
        self.request = None
        self.response = None
        self.recv_buffer.clear_retaining_capacity()
        self.state = ConnectionState.reading_headers()
        self.should_close = False


fn handle_connection[
    T: HTTPService
](
    mut conn: TCPConnection,
    mut provision: ConnectionProvision,
    mut handler: T,
    config: ServerConfig,
    server_address: String,
    tcp_keep_alive: Bool,
) raises SocketError:
    while True:
        if provision.state.kind == ConnectionState.READING_HEADERS:
            var buffer = Bytes(capacity=config.socket_buffer_size)
            var bytes_read: UInt

            try:
                bytes_read = conn.read(buffer)
            except e:
                if e.isa[EOF]():
                    print("Error reading from connection:", e)
                provision.state = ConnectionState.closed()
                break

            if bytes_read == 0:
                provision.state = ConnectionState.closed()
                break

            provision.recv_buffer.append(buffer^)

            if BytesConstant.DOUBLE_CRLF in ByteView(provision.recv_buffer.as_bytes()):
                try:
                    var request = HTTPRequest.from_bytes(
                        server_address,
                        config.max_request_body_size,
                        config.max_request_uri_length,
                        provision.recv_buffer.as_bytes(),
                    )

                    var content_length = request.headers.content_length()

                    provision.request = request^

                    if content_length > 0:
                        provision.state = ConnectionState.reading_body(content_length)
                    else:
                        provision.state = ConnectionState.processing()

                except e:
                    var error_response: HTTPResponse
                    # if "URI too long" in String(e):
                    # error_response = URITooLong()
                    # else:
                    error_response = BadRequest()

                    _ = conn.write(encode(error_response^))
                    provision.state = ConnectionState.closed()
                    break

            if provision.recv_buffer.len() > config.recv_buffer_max:
                _ = conn.write(encode(BadRequest()))
                provision.state = ConnectionState.closed()
                break

        elif provision.state.kind == ConnectionState.READING_BODY:
            var buffer = Bytes(capacity=config.socket_buffer_size)
            var bytes_read: UInt

            try:
                bytes_read = conn.read(buffer)
            except e:
                provision.state = ConnectionState.closed()
                break

            if bytes_read == 0:
                provision.state = ConnectionState.closed()
                break

            provision.recv_buffer.append(buffer^)
            provision.state.body_state.bytes_read += Int(bytes_read)

            if provision.state.body_state.bytes_read >= provision.state.body_state.content_length:
                provision.state = ConnectionState.processing()

            if provision.recv_buffer.len() > config.max_request_body_size:
                _ = conn.write(encode(BadRequest()))
                provision.state = ConnectionState.closed()
                break

        elif provision.state.kind == ConnectionState.PROCESSING:
            var request = provision.request.take()
            provision.should_close = (not tcp_keep_alive) or request.connection_close()
            var response: HTTPResponse

            try:
                response = handler.func(request^)
            except e:
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
            except e:
                provision.state = ConnectionState.closed()
                break

            if provision.should_close:
                provision.state = ConnectionState.closed()
                break

            # Enforce keep-alive request cap only when explicitly configured.
            if (config.max_keepalive_requests > 0) and (provision.keepalive_count >= config.max_keepalive_requests):
                provision.state = ConnectionState.closed()
                break

            provision.keepalive_count += 1
            provision.prepare_for_new_request()

        else:  # CLOSED
            break


struct Server(Movable):
    """
    HTTP/1.1 Server implementation.
    """

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

        try:
            self.serve(listener, handler)
        except e:
            raise Error("Error while serving HTTP requests: ", e)

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
            var provision = ConnectionProvision(self.config)

            try:
                handle_connection(
                    conn,
                    provision,
                    handler,
                    self.config,
                    self.address(),
                    self.tcp_keep_alive,
                )
            finally:
                conn^.teardown()
