from sys.info import CompilationTarget
from time import sleep

from lightbug_http.address import HostPort, NetworkType, ParseError, TCPAddr, UDPAddr, parse_address
from lightbug_http.c.address import AddressFamily
from lightbug_http.c.socket_error import AcceptError, GetpeernameError, RecvError, RecvfromError, SendError, SendtoError, ShutdownEINVALError
from lightbug_http.c.socket_error import SocketError as CSocketError
from lightbug_http.io.bytes import Bytes
from lightbug_http.io.sync import Duration
from lightbug_http.socket import (
    EOF,
    FatalCloseError,
    Socket,
    SocketAcceptError,
    SocketBindError,
    SocketConnectError,
    SocketOption,
    SocketRecvError,
    SocketRecvfromError,
    SocketType,
    TCPSocket,
    UDPSocket,
)
from lightbug_http.utils.error import CustomError
from utils import Variant


comptime default_buffer_size = 4096
"""The default buffer size for reading and writing data."""
comptime default_tcp_keep_alive = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds
"""The default TCP keep-alive duration."""


@fieldwise_init
@register_passable("trivial")
struct AddressParseError(CustomError):
    comptime message = "ListenerError: Failed to parse listen address"

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketCreationError(CustomError):
    comptime message = "ListenerError: Failed to create socket"

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindFailedError(CustomError):
    comptime message = "ListenerError: Failed to bind socket to address"

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ListenFailedError(CustomError):
    comptime message = "ListenerError: Failed to listen on socket"

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ListenerError(Movable, Stringable, Writable):
    """Error variant for listener creation operations.

    Represents failures during address parsing, socket creation, binding, or listening.
    """

    comptime type = Variant[
        AddressParseError, SocketCreationError, BindFailedError, ListenFailedError, CSocketError, SocketBindError, Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: AddressParseError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketCreationError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindFailedError):
        self.value = value

    @implicit
    fn __init__(out self, value: ListenFailedError):
        self.value = value

    @implicit
    fn __init__(out self, var value: CSocketError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: SocketBindError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[AddressParseError]():
            writer.write(self.value[AddressParseError])
        elif self.value.isa[SocketCreationError]():
            writer.write(self.value[SocketCreationError])
        elif self.value.isa[BindFailedError]():
            writer.write(self.value[BindFailedError])
        elif self.value.isa[ListenFailedError]():
            writer.write(self.value[ListenFailedError])
        elif self.value.isa[CSocketError]():
            writer.write(self.value[CSocketError])
        elif self.value.isa[SocketBindError]():
            writer.write(self.value[SocketBindError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


struct NoTLSListener[network: NetworkType = NetworkType.tcp4](Movable):
    """A TCP listener that listens for incoming connections and can accept them."""

    var socket: TCPSocket[TCPAddr[Self.network]]

    fn __init__(out self, var socket: TCPSocket[TCPAddr[Self.network]]):
        self.socket = socket^

    fn __init__(out self) raises CSocketError:
        self.socket = Socket[TCPAddr[Self.network]]()

    fn accept(self) raises SocketAcceptError -> TCPConnection[Self.network]:
        """Accept an incoming TCP connection.

        Returns:
            A new TCPConnection for the accepted client.

        Raises:
            SocketAcceptError: If accept fails.
        """
        return TCPConnection(self.socket.accept())

    fn close(mut self) raises FatalCloseError -> None:
        """Close the listener socket.

        Raises:
            FatalCloseError: If close fails (excludes EBADF).
        """
        return self.socket.close()

    fn shutdown(mut self) raises ShutdownEINVALError:
        """Shutdown the listener socket.

        Raises:
            ShutdownEINVALError: If shutdown fails.
        """
        return self.socket.shutdown()

    fn teardown(deinit self) raises FatalCloseError:
        """Teardown the listener socket on destruction.

        Raises:
            FatalCloseError: If close fails during teardown.
        """
        self.socket^.teardown()

    fn addr(self) -> TCPAddr[Self.network]:
        return self.socket.local_address


struct ListenConfig:
    var _keep_alive: Duration

    fn __init__(out self, keep_alive: Duration = default_tcp_keep_alive):
        self._keep_alive = keep_alive

    fn listen[
        network: NetworkType = NetworkType.tcp4
    ](self, address: StringSlice) raises ListenerError -> NoTLSListener[network]:
        """Create a TCP listener on the specified address.

        Parameters:
            network: The network type (tcp4 or tcp6).

        Args:
            address: The address to listen on (host:port).

        Returns:
            A NoTLSListener ready to accept connections.

        Raises:
            ListenerError: If address parsing, socket creation, bind, or listen fails.
        """
        var local: HostPort
        try:
            local = parse_address[network](address)
        except ParseError:
            raise AddressParseError()

        var socket: Socket[TCPAddr[network]]
        try:
            socket = Socket[TCPAddr[network]]()
        except socket_err:
            raise SocketCreationError()

        @parameter
        # TODO: do we want to add SO_REUSEPORT on linux? Doesn't work on some systems
        if CompilationTarget.is_macos():
            try:
                socket.set_socket_option(SocketOption.SO_REUSEADDR, 1)
            except sockopt_err:
                # Socket option failure is not fatal, just continue
                pass

        var addr = TCPAddr[network](ip=local.host^, port=local.port)
        var bind_success = False
        var bind_fail_logged = False
        while not bind_success:
            try:
                socket.bind(addr.ip, addr.port)
                bind_success = True
            except bind_err:
                if not bind_fail_logged:
                    print("Bind attempt failed (address may be in use)")
                    print("Retrying. Might take 10-15 seconds.")
                    bind_fail_logged = True
                print(".", end="", flush=True)

                try:
                    socket.shutdown()
                except shutdown_err:
                    # Shutdown failure during retry is not critical
                    # The socket will be closed and recreated on next attempt
                    pass
                sleep(UInt(1))

        try:
            socket.listen(128)
        except listen_err:
            raise ListenFailedError()

        var listener = NoTLSListener(socket^)
        var msg = String(
            "\n🔥🐝 Lightbug is listening on ",
            "http://",
            addr.ip,
            ":",
            String(addr.port),
        )
        print(msg)
        print("Ready to accept connections...")

        return listener^


@fieldwise_init
struct RequestBodyState(Copyable):
    """State for reading request body."""

    var content_length: Int
    var bytes_read: Int


@fieldwise_init
struct ConnectionState(Copyable):
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


struct TCPConnection[network: NetworkType = NetworkType.tcp4]:
    var socket: TCPSocket[TCPAddr[Self.network]]

    fn __init__(out self, var socket: TCPSocket[TCPAddr[Self.network]]):
        self.socket = socket^

    fn read(self, mut buf: Bytes) raises SocketRecvError -> UInt:
        """Read data from the TCP connection.

        Args:
            buf: Buffer to read data into.

        Returns:
            Number of bytes read.

        Raises:
            SocketRecvError: If read fails or connection is closed.
        """
        return self.socket.receive(buf)

    fn write(self, buf: Span[Byte]) raises SendError -> UInt:
        """Write data to the TCP connection.

        Args:
            buf: Buffer containing data to write.

        Returns:
            Number of bytes written.

        Raises:
            SendError: If write fails.
        """
        return self.socket.send(buf)

    fn close(mut self) raises FatalCloseError:
        """Close the TCP connection.

        Raises:
            FatalCloseError: If close fails (excludes EBADF).
        """
        self.socket.close()

    fn shutdown(mut self) raises ShutdownEINVALError:
        """Shutdown the TCP connection.

        Raises:
            ShutdownEINVALError: If shutdown fails.
        """
        self.socket.shutdown()

    fn teardown(deinit self) raises FatalCloseError:
        """Teardown the connection on destruction.

        Raises:
            FatalCloseError: If close fails during teardown.
        """
        self.socket^.teardown()

    fn is_closed(self) -> Bool:
        return self.socket._closed

    # TODO: Switch to property or return ref when trait supports attributes.
    fn local_addr(self) -> TCPAddr[Self.network]:
        return self.socket.local_address

    fn remote_addr(self) -> TCPAddr[Self.network]:
        return self.socket.remote_address


struct UDPConnection[
    network: NetworkType = NetworkType.udp4,
    address_family: AddressFamily = AddressFamily.AF_INET,
](Movable):
    comptime _sock_type = Socket[
        sock_type = SocketType.SOCK_DGRAM,
        address = UDPAddr[Self.network],
        address_family = Self.address_family,
    ]
    var socket: Self._sock_type

    fn __init__(out self, var socket: Self._sock_type):
        self.socket = socket^

    fn read_from(mut self, size: Int = default_buffer_size) raises SocketRecvfromError -> Tuple[Bytes, String, UInt16]:
        """Reads data from the underlying file descriptor.

        Args:
            size: The size of the buffer to read data into.

        Returns:
            The number of bytes read, or an error if one occurred.

        Raises:
            SocketRecvfromError: If an error occurred while reading data.
        """

        return self.socket.receive_from(size)

    fn read_from(mut self, mut dest: Bytes) raises SocketRecvfromError -> Tuple[UInt, String, UInt16]:
        """Reads data from the underlying file descriptor.

        Args:
            dest: The buffer to read data into.

        Returns:
            The number of bytes read, or an error if one occurred.

        Raises:
            SocketRecvfromError: If an error occurred while reading data.
        """

        return self.socket.receive_from(dest)

    fn write_to(mut self, src: Span[Byte], mut address: UDPAddr) raises SendtoError -> UInt:
        """Writes data to the underlying file descriptor.

        Args:
            src: The buffer to read data into.
            address: The remote peer address.

        Returns:
            The number of bytes written, or an error if one occurred.

        Raises:
            SendtoError: If an error occurred while writing data.
        """

        return self.socket.send_to(src, address.ip, address.port)

    fn write_to(mut self, src: Span[Byte], mut host: String, port: UInt16) raises SendtoError -> UInt:
        """Writes data to the underlying file descriptor.

        Args:
            src: The buffer to read data into.
            host: The remote peer address in IPv4 format.
            port: The remote peer port.

        Returns:
            The number of bytes written, or an error if one occurred.

        Raises:
            SendtoError: If an error occurred while writing data.
        """

        return self.socket.send_to(src, host, port)

    fn close(mut self) raises FatalCloseError:
        """Close the UDP connection.

        Raises:
            FatalCloseError: If close fails (excludes EBADF).
        """
        self.socket.close()

    fn shutdown(mut self) raises ShutdownEINVALError:
        """Shutdown the UDP connection.

        Raises:
            ShutdownEINVALError: If shutdown fails.
        """
        self.socket.shutdown()

    fn teardown(deinit self) raises FatalCloseError:
        """Teardown the connection on destruction.

        Raises:
            FatalCloseError: If close fails during teardown.
        """
        self.socket^.teardown()

    fn is_closed(self) -> Bool:
        return self.socket._closed

    # fn local_addr(self) -> ref [self.socket.local_address] UDPAddr[network]:
    #     return self.socket.local_address

    # fn remote_addr(self) -> ref [self.socket.remote_address] UDPAddr[network]:
    #     return self.socket.remote_address


@fieldwise_init
struct CreateConnectionError(Movable, Stringable, Writable):
    """Error variant for create_connection operations.
    Can be CSocketError from socket creation or SocketConnectError from connect.
    """

    comptime type = Variant[CSocketError, SocketConnectError]
    var value: Self.type

    @implicit
    fn __init__(out self, var value: CSocketError):
        self.value = value^

    @implicit
    fn __init__(out self, var value: SocketConnectError):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[CSocketError]():
            writer.write(self.value[CSocketError])
        elif self.value.isa[SocketConnectError]():
            writer.write(self.value[SocketConnectError])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


fn create_connection(mut host: String, port: UInt16) raises CreateConnectionError -> TCPConnection[NetworkType.tcp4]:
    """Connect to a server using a TCP socket.

    Args:
        host: The host to connect to.
        port: The port to connect on.

    Returns:
        A connected TCPConnection.

    Raises:
        CreateConnectionError: If socket creation or connection fails.
    """
    var socket: Socket[TCPAddr[NetworkType.tcp4]]
    try:
        socket = Socket[TCPAddr[NetworkType.tcp4]]()
    except socket_err:
        raise socket_err^

    try:
        socket.connect(host, port)
    except connect_err:
        # Connection failed - try to shutdown gracefully before propagating error
        try:
            socket.shutdown()
        except shutdown_err:
            # Shutdown failure is not critical here - connection already failed
            pass
        # Propagate the original connection error with type info
        raise connect_err^

    return TCPConnection(socket^)
