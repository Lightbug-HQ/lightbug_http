from sys.ffi import c_uint
from sys.info import CompilationTarget

from lightbug_http.address import (
    Addr,
    NetworkType,
    TCPAddr,
    UDPAddr,
    binary_ip_to_string,
    binary_port_to_int,
    get_ip_address,
)
from lightbug_http.c.address import AddressFamily, AddressLength
from lightbug_http.c.network import SocketAddress, inet_pton
from lightbug_http.c.socket import (
    SOL_SOCKET,
    EBADFError,
    EINTRError,
    EINVALError,
    EIOError,
    ENOSPCError,
    ShutdownOption,
    SocketOption,
    SocketType,
    accept,
    bind,
    close,
    connect,
    getpeername,
    getsockname,
    getsockopt,
    listen,
    recv,
    recvfrom,
    send,
    sendto,
    setsockopt,
    shutdown,
    socket,
)
from lightbug_http.c.socket_error import CloseError
from lightbug_http.connection import default_buffer_size
from lightbug_http.io.bytes import Bytes
from utils import Variant


@fieldwise_init
@register_passable("trivial")
struct SocketClosedError(Movable):
    pass


@fieldwise_init
@register_passable("trivial")
struct EOF(Movable):
    pass


@fieldwise_init
struct SocketError(Movable, Stringable, Writable):
    comptime type = Variant[
        SocketClosedError,
        EOF,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SocketClosedError):
        self.value = value

    @implicit
    fn __init__(out self, value: EOF):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SocketClosedError]():
            writer.write("SocketClosedError")
        elif self.value.isa[EOF]():
            writer.write("EOF")
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct FatalCloseError(Movable, Stringable, Writable):
    """Error type for Socket.close() that excludes EBADF.

    EBADF is excluded because it indicates the socket is already closed,
    which is the desired state. Other errors indicate actual failures
    that should be propagated.
    """

    comptime type = Variant[EINTRError, EIOError, ENOSPCError, Error]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOSPCError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    @implicit
    fn __init__(out self, var value: CloseError) raises:
        if value.isa[EINTRError]():
            self.value = EINTRError()
        elif value.isa[EIOError]():
            self.value = EIOError()
        elif value.isa[ENOSPCError]():
            self.value = ENOSPCError()
        elif value.isa[Error]():
            self.value = Error(value[Error])
        else:
            raise Error("Cannot convert EBADF to FatalCloseError - socket already closed")

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EIOError]():
            writer.write(self.value[EIOError])
        elif self.value.isa[ENOSPCError]():
            writer.write(self.value[ENOSPCError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)


@fieldwise_init
struct Socket[
    address: Addr,
    sock_type: SocketType = SocketType.SOCK_STREAM,
    address_family: AddressFamily = AddressFamily.AF_INET,
](Movable, Representable, Stringable, Writable):
    """Represents a network file descriptor. Wraps around a file descriptor and provides network functions.

    Parameters:
        address: The type of address the socket uses.
        sock_type: The type of socket (e.g., SOCK_STREAM for TCP, SOCK_DGRAM for UDP).
        address_family: The address family (e.g., AF_INET for IPv4, AF_INET6 for IPv6).

    Args:
        local_address: The local address of the socket (local address if bound).
        remote_address: The remote address of the socket (peer's address if connected).
    """

    var fd: FileDescriptor
    """The file descriptor of the socket."""
    var local_address: Self.address
    """The local address of the socket (local address if bound)."""
    var remote_address: Self.address
    """The remote address of the socket (peer's address if connected)."""
    var _closed: Bool
    """Whether the socket is closed."""
    var _connected: Bool
    """Whether the socket is connected."""

    fn __init__(
        out self,
        local_address: Self.address = Self.address(),
        remote_address: Self.address = Self.address(),
    ) raises:
        """Create a new socket object.

        Args:
            local_address: The local address of the socket (local address if bound).
            remote_address: The remote address of the socket (peer's address if connected).

        Raises:
            Error: If the socket creation fails.
        """
        # TODO: Tried unspec for both address family and protocol, and inet for both but that doesn't seem to work.
        # I guess for now, I'll leave protocol as unspec.
        self.fd = FileDescriptor(Int(socket(Self.address_family.value, Self.sock_type.value, 0)))
        self.local_address = local_address
        self.remote_address = remote_address
        self._closed = False
        self._connected = False

    fn __init__(
        out self,
        fd: FileDescriptor,
        local_address: Self.address,
        remote_address: Self.address = Self.address(),
    ):
        """
        Create a new socket object when you already have a socket file descriptor. Typically through socket.accept().

        Args:
            fd: The file descriptor of the socket.
            local_address: The local address of the socket (local address if bound).
            remote_address: The remote address of the socket (peer's address if connected).
        """
        self.fd = fd
        self.local_address = local_address
        self.remote_address = remote_address
        self._closed = False
        self._connected = True

    fn teardown(deinit self) raises FatalCloseError:
        """Close the socket and free the file descriptor."""
        if self._connected:
            try:
                self.shutdown()
            except e:
                pass

        if not self._closed:
            self.close()

    fn __enter__(var self) -> Self:
        return self^

    fn __del__(deinit self):
        """Close the socket when the object is deleted."""
        try:
            self^.teardown()
        except e:
            pass

    fn __str__(self) -> String:
        return String.write(self)

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(
            "Socket[",
            Self.address._type,
            ", ",
            Self.address_family,
            "]",
            "(",
            "fd=",
            self.fd.value,
            ", local_address=",
            repr(self.local_address),
            ", remote_address=",
            repr(self.remote_address),
            ", _closed=",
            self._closed,
            ", _connected=",
            self._connected,
            ")",
        )

    fn accept(self) raises SocketError -> Self:
        """Accept a connection. The socket must be bound to an address and listening for connections.
        The return value is a connection where conn is a new socket object usable to send and receive data on the connection,
        and address is the address bound to the socket on the other end of the connection.

        Returns:
            A new socket object and the address of the remote socket.

        Raises:
            SocketError: If accept fails or getting peer address fails.
        """
        var new_socket_fd: FileDescriptor
        try:
            new_socket_fd = accept(self.fd)
        except e:
            # Propagate the typed AcceptError
            raise Error("Socket.accept: " + String(e))

        var new_socket = Self(
            fd=new_socket_fd,
            local_address=self.local_address,
        )
        var peer = new_socket.get_peer_name()
        new_socket.remote_address = Self.address(peer[0], peer[1])
        return new_socket^

    fn listen(self, backlog: UInt = 0) raises:
        """Enable a server to accept connections.

        Args:
            backlog: The maximum number of queued connections. Should be at least 0, and the maximum is system-dependent (usually 5).

        Raises:
            Error: If listening for a connection fails.
        """
        try:
            listen(self.fd, backlog)
        except e:
            # Propagate the typed ListenError with context
            raise Error("Socket.listen: " + String(e))

    fn bind(mut self, ip_address: String, port: UInt16) raises SocketError:
        """Bind the socket to address. The socket must not already be bound. (The format of address depends on the address family).

        When a socket is created with Socket(), it exists in a name
        space (address family) but has no address assigned to it.  bind()
        assigns the address specified by addr to the socket referred to
        by the file descriptor fd.  addrlen specifies the size, in
        bytes, of the address structure pointed to by addr.
        Traditionally, this operation is called 'assigning a name to a
        socket'.

        Args:
            ip_address: The IP address to bind the socket to.
            port: The port number to bind the socket to.

        Raises:
            SocketError: If IP conversion fails, bind fails, or getting socket name fails.
        """
        var binary_ip: c_uint
        try:
            binary_ip = inet_pton[Self.address_family](ip_address)
        except e:
            raise Error("Socket.bind: Failed to convert IP '" + ip_address + "' to binary: " + String(e))

        var local_address = SocketAddress(
            address_family=Self.address_family,
            port=port,
            binary_ip=binary_ip,
        )
        try:
            bind(self.fd, local_address)
        except e:
            # Propagate the typed BindError with context
            raise Error("Socket.bind: " + String(e))

        var local = self.get_sock_name()
        self.local_address = Self.address(local[0], local[1])

    fn get_sock_name(self) raises SocketError -> Tuple[String, UInt16]:
        """Return the address of the socket.

        Returns:
            The address of the socket.

        Raises:
            SocketError: If socket is closed or getsockname fails.
        """
        if self._closed:
            raise SocketError(SocketClosedError())

        # TODO: Add check to see if the socket is bound and error if not.
        var local_address = SocketAddress()
        try:
            getsockname(self.fd, local_address)
        except e:
            # Propagate the typed GetsocknameError with context
            raise Error("Socket.get_sock_name: " + String(e))

        ref local_sockaddr_in = local_address.as_sockaddr_in()
        return (
            binary_ip_to_string[Self.address_family](local_sockaddr_in.sin_addr.s_addr),
            UInt16(binary_port_to_int(local_sockaddr_in.sin_port)),
        )

    fn get_peer_name(self) raises SocketError -> Tuple[String, UInt16]:
        """Return the address of the peer connected to the socket.

        Returns:
            The address of the peer connected to the socket.

        Raises:
            SocketError: If socket is closed or getpeername fails.
        """
        if self._closed:
            raise SocketClosedError()

        # TODO: Add check to see if the socket is bound and error if not.
        var peer_address: SocketAddress
        try:
            peer_address = getpeername(self.fd)
        except e:
            # Propagate the typed GetpeernameError with context
            raise Error("Socket.get_peer_name: " + String(e))

        ref peer_sockaddr_in = peer_address.as_sockaddr_in()
        return (
            binary_ip_to_string[Self.address_family](peer_sockaddr_in.sin_addr.s_addr),
            UInt16(binary_port_to_int(peer_sockaddr_in.sin_port)),
        )

    fn get_socket_option(self, option_name: SocketOption) raises SocketError -> Int:
        """Return the value of the given socket option.

        Args:
            option_name: The socket option to get.

        Returns:
            The value of the given socket option.

        Raises:
            Error: If getting the socket option fails.
        """
        return getsockopt(self.fd, SOL_SOCKET, option_name.value)

    fn set_socket_option(self, option_name: SocketOption, var option_value: Int = 1) raises:
        """Return the value of the given socket option.

        Args:
            option_name: The socket option to set.
            option_value: The value to set the socket option to. Defaults to 1 (True).

        Raises:
            Error: If setting the socket option fails.
        """
        setsockopt(self.fd, SOL_SOCKET, option_name.value, option_value)

    fn connect(mut self, mut ip_address: String, port: UInt16) raises SocketError -> None:
        """Connect to a remote socket at address.

        Args:
            ip_address: The IP address to connect to.
            port: The port number to connect to.

        Raises:
            Error: If connecting to the remote socket fails.
        """
        var ip = get_ip_address(ip_address, Self.address_family, Self.sock_type)
        var remote_address = SocketAddress(address_family=Self.address_family, port=port, binary_ip=ip)
        connect(self.fd, remote_address)

        var remote = self.get_peer_name()
        self.remote_address = Self.address(remote[0], remote[1])

    fn send(self, buffer: Span[Byte]) raises SocketError -> UInt:
        return send(self.fd, buffer, UInt(len(buffer)), 0)

    fn send_to(self, src: Span[Byte], mut host: String, port: UInt16) raises SocketError -> UInt:
        """Send data to the a remote address by connecting to the remote socket before sending.
        The socket must be not already be connected to a remote socket.

        Args:
            src: The data to send.
            host: The host to connect to.
            port: The port number to connect to.

        Returns:
            The number of bytes sent.

        Raises:
            Error: If sending the data fails.
        """
        var ip = get_ip_address(host, Self.address_family, Self.sock_type)
        var remote_address = SocketAddress(address_family=Self.address_family, port=port, binary_ip=ip)
        return sendto(self.fd, src, UInt(len(src)), 0, remote_address)

    fn _receive(self, mut buffer: Bytes) raises SocketError -> UInt:
        """Receive data from the socket into the buffer.

        Args:
            buffer: The buffer to read data into.

        Returns:
            The number of bytes received.

        Raises:
            SocketError: If reading data from the socket fails.
            EOF: If 0 bytes are received.
        """
        var bytes_received: UInt
        var size = len(buffer)
        try:
            bytes_received = recv(
                self.fd,
                Span(buffer)[size:],
                UInt(buffer.capacity - len(buffer)),
                0,
            )
            buffer._len += Int(bytes_received)
        except e:
            # Propagate the typed RecvError with context
            raise Error("Socket._receive: " + String(e))

        if bytes_received == 0:
            raise EOF()

        return bytes_received

    fn receive(self, size: Int = default_buffer_size) raises SocketError -> List[Byte]:
        """Receive data from the socket into the buffer with capacity of `size` bytes.

        Args:
            size: The size of the buffer to receive data into.

        Returns:
            The buffer with the received data, and an error if one occurred.
        """
        var buffer = Bytes(capacity=size)
        _ = self._receive(buffer)
        return buffer^

    fn receive(self, mut buffer: Bytes) raises SocketError -> UInt:
        """Receive data from the socket into the buffer.

        Args:
            buffer: The buffer to read data into.

        Returns:
            The buffer with the received data, and an error if one occurred.

        Raises:
            Error: If reading data from the socket fails.
            EOF: If 0 bytes are received, return EOF.
        """
        return self._receive(buffer)

    fn _receive_from(self, mut buffer: Bytes) raises SocketError -> Tuple[UInt, String, UInt16]:
        """Receive data from the socket into the buffer.

        Args:
            buffer: The buffer to read data into.

        Returns:
            Tuple of (bytes received, remote host, remote port).

        Raises:
            SocketError: If reading data from the socket fails.
            EOF: If 0 bytes are received.
        """
        var remote_address = SocketAddress()
        var bytes_received: UInt
        try:
            var size = len(buffer)
            bytes_received = recvfrom(
                self.fd,
                Span(buffer)[size:],
                UInt(buffer.capacity - len(buffer)),
                0,
                remote_address,
            )
            buffer._len += Int(bytes_received)
        except e:
            # Propagate the typed RecvfromError with context
            raise Error("Socket._receive_from: " + String(e))

        if bytes_received == 0:
            raise EOF()

        ref peer_sockaddr_in = remote_address.as_sockaddr_in()
        return (
            bytes_received,
            binary_ip_to_string[Self.address_family](peer_sockaddr_in.sin_addr.s_addr),
            UInt16(binary_port_to_int(peer_sockaddr_in.sin_port)),
        )

    fn receive_from(self, size: Int = default_buffer_size) raises SocketError -> Tuple[List[Byte], String, UInt16]:
        """Receive data from the socket into the buffer dest.

        Args:
            size: The size of the buffer to receive data into.

        Returns:
            The number of bytes read, the remote address, and an error if one occurred.

        Raises:
            Error: If reading data from the socket fails.
        """
        var buffer = Bytes(capacity=size)
        _, host, port = self._receive_from(buffer)
        return buffer^, host, port

    fn receive_from(self, mut dest: List[Byte]) raises SocketError -> Tuple[UInt, String, UInt16]:
        """Receive data from the socket into the buffer dest.

        Args:
            dest: The buffer to read data into.

        Returns:
            The number of bytes read, the remote address, and an error if one occurred.

        Raises:
            Error: If reading data from the socket fails.
        """
        return self._receive_from(dest)

    fn shutdown(mut self) raises EINVALError -> None:
        """Shut down the socket. The remote end will receive no more data (after queued data is flushed)."""
        try:
            shutdown(self.fd, ShutdownOption.SHUT_RDWR)
        except e:
            # For the other errors, either the socket is already closed or the descriptor is invalid.
            # At that point we can feasibly say that the socket is already shut down.
            if e.isa[EINVALError]():
                raise e[EINVALError]

        self._connected = False

    fn close(mut self) raises FatalCloseError -> None:
        """Mark the socket closed.
        Once that happens, all future operations on the socket object will fail.
        The remote end will receive no more data (after queued data is flushed).

        Raises:
            FatalCloseError: If closing the socket fails (excludes EBADF which means already closed).
        """
        try:
            close(self.fd)
        except e:
            # If the file descriptor is invalid, then it was most likely already closed.
            # Other errors indicate a failure while attempting to close the socket.
            if not e.isa[EBADFError]():
                raise

        self._closed = True

    fn get_timeout(self) raises SocketError -> Int:
        """Return the timeout value for the socket."""
        return self.get_socket_option(SocketOption.SO_RCVTIMEO)

    fn set_timeout(self, var duration: Int) raises:
        """Set the timeout value for the socket.

        Args:
            duration: Seconds - The timeout duration in seconds.
        """
        self.set_socket_option(SocketOption.SO_RCVTIMEO, duration)


comptime UDPSocket[address: Addr] = Socket[
    address=address,
    sock_type = SocketType.SOCK_DGRAM,
    address_family = AddressFamily.AF_INET,
]
comptime UDP4Socket = UDPSocket[UDPAddr]
comptime TCPSocket[address: Addr] = Socket[
    address=address,
    sock_type = SocketType.SOCK_STREAM,
    address_family = AddressFamily.AF_INET,
]
comptime TCP4Socket = TCPSocket[TCPAddr]
comptime TCP6Socket = TCPSocket[TCPAddr[NetworkType.tcp6]]
