from lightbug_http.connection import ConnectionState, ListenConfig, NoTLSListener, TCPConnection, default_buffer_size
from lightbug_http.http.common_response import BadRequest, InternalError, URITooLong
from lightbug_http.io.bytes import ByteReader, Bytes, BytesConstant, ByteView
from lightbug_http.utils.owning_list import OwningList
from lightbug_http.service import HTTPService
from lightbug_http.socket import EOF, SocketError, FatalCloseError
from utils import Variant

from lightbug_http.http import HTTPRequest, HTTPResponse, encode


@fieldwise_init
struct ServerError(Movable, Stringable, Writable):
    """Error variant for server operations that may encounter socket or close errors."""

    comptime type = Variant[
        SocketError,
        FatalCloseError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SocketError):
        self.value = value

    @implicit
    fn __init__(out self, value: FatalCloseError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SocketError]():
            writer.write(self.value[SocketError])
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
    var max_connections: Int
    var max_keepalive_requests: Int

    var socket_buffer_size: Int
    var recv_buffer_max: Int

    var max_request_body_size: Int
    var max_request_uri_length: Int

    fn __init__(out self):
        self.max_connections = 1024
        self.max_keepalive_requests = 0

        self.socket_buffer_size = default_buffer_size
        self.recv_buffer_max = 2 * 1024 * 1024  # 2MB

        self.max_request_body_size = 4 * 1024 * 1024  # 4MB
        self.max_request_uri_length = 8192


struct ConnectionProvision(Movable):
    """
    All resources needed to handle a connection.
    Pre-allocated and reused (pooled) across connections.
    """

    var recv_buffer: Bytes
    var request: Optional[HTTPRequest]
    var response: Optional[HTTPResponse]
    var state: ConnectionState
    var keepalive_count: Int
    var should_close: Bool

    fn __init__(out self, config: ServerConfig):
        self.recv_buffer = Bytes(capacity=config.socket_buffer_size)
        self.request = None
        self.response = None
        self.state = ConnectionState.reading_headers()
        self.keepalive_count = 0
        self.should_close = False

    fn prepare_for_new_request(mut self):
        """Reset provision for next request in keepalive connection."""
        self.request = None
        self.response = None
        self.recv_buffer.clear()
        self.state = ConnectionState.reading_headers()
        self.should_close = False


struct ProvisionPool(Movable):
    """
    Pool of ConnectionProvision objects for reuse across connections.
    """

    var provisions: OwningList[ConnectionProvision]
    var available: OwningList[Int]
    var capacity: Int
    var initialized_count: Int

    fn __init__(out self, capacity: Int, config: ServerConfig):
        """Initialize the provision pool with the given capacity.

        Args:
            capacity: Maximum number of provisions in the pool.
            config: Server configuration for initializing provisions.
        """
        self.provisions = OwningList[ConnectionProvision](capacity=capacity)
        self.available = OwningList[Int](capacity=capacity)
        self.capacity = capacity
        self.initialized_count = 0

        # Pre-allocate all provisions
        for i in range(capacity):
            self.provisions.append(ConnectionProvision(config))
            self.available.append(i)
            self.initialized_count += 1

    fn borrow(mut self) raises -> Int:
        """Borrow a provision from the pool.

        Returns:
            Index of the borrowed provision.

        Raises:
            Error if no provisions are available.
        """
        if len(self.available) == 0:
            raise Error("ProvisionPool: No provisions available")

        return self.available.pop()

    fn release(mut self, index: Int):
        """Return a provision to the pool.

        Args:
            index: Index of the provision to return.
        """
        self.available.append(index)

    fn get_ptr(mut self, index: Int) -> Pointer[ConnectionProvision, origin_of(self.provisions)]:
        """Get a mutable pointer to a provision by index.

        Args:
            index: Index of the provision.

        Returns:
            Mutable pointer to the provision.
        """
        return Pointer(to=self.provisions[index])

    fn size(self) -> Int:
        """Get the number of provisions currently in use.

        Returns:
            Number of provisions in use.
        """
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
) raises SocketError:
    while True:
        if provision.state.kind == ConnectionState.READING_HEADERS:
            var buffer = Bytes(capacity=config.socket_buffer_size)
            var bytes_read: UInt

            try:
                bytes_read = conn.read(buffer)
            except e:
                # if e.isa[EOF]():
                # print("Error reading from connection:", e)
                provision.state = ConnectionState.closed()
                break

            if bytes_read == 0:
                provision.state = ConnectionState.closed()
                break

            provision.recv_buffer.extend(buffer^)

            if BytesConstant.DOUBLE_CRLF in ByteView(provision.recv_buffer):
                try:
                    var request = HTTPRequest.from_bytes(
                        server_address,
                        config.max_request_body_size,
                        config.max_request_uri_length,
                        provision.recv_buffer,
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

            if len(provision.recv_buffer) > config.recv_buffer_max:
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

            provision.recv_buffer.extend(buffer^)
            provision.state.body_state.bytes_read += Int(bytes_read)

            if provision.state.body_state.bytes_read >= provision.state.body_state.content_length:
                provision.state = ConnectionState.processing()

            if len(provision.recv_buffer) > config.max_request_body_size:
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

    fn serve[T: HTTPService](self, ln: NoTLSListener, mut handler: T) raises ServerError:
        """Serve HTTP requests.

        Parameters:
            T: The type of HTTPService that handles incoming requests.

        Args:
            ln: TCP server that listens for incoming connections.
            handler: An object that handles incoming HTTP requests.

        Raises:
            If there is an error while serving requests.
        """
        var provision_pool = ProvisionPool(self.config.max_connections, self.config)

        while True:
            var conn = ln.accept()

            var index: Int
            try:
                index = provision_pool.borrow()
            except e:
                conn^.teardown()
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
            finally:
                conn^.teardown()
                provision_pool.provisions[index].prepare_for_new_request()
                provision_pool.provisions[index].keepalive_count = 0
                provision_pool.release(index)
