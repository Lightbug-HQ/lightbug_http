from memory import Span, stack_allocation
from utils import StaticTuple
from .libc import (
    socket,
    connect,
    recv,
    # recvfrom,
    send,
    # sendto,
    shutdown,
    inet_pton,
    # inet_ntoa,
    inet_ntop,
    htons,
    ntohs,
    # getaddrinfo,
    # getaddrinfo_unix,
    gai_strerror,
    bind,
    listen,
    accept,
    setsockopt,
    getsockopt,
    getsockname,
    getpeername,
    close,
    sockaddr,
    sockaddr_in,
    addrinfo,
    # addrinfo_unix,
    socklen_t,
    c_void,
    c_uint,
    c_char,
    c_int,
    in_addr,
    # AddressFamily,
    # AddressInformation,
    # SocketOptions,
    # SocketType,
    SHUT_RDWR,
    SOL_SOCKET,
    AF_INET,
    AF_INET6,
    SOCK_STREAM,
    INET_ADDRSTRLEN,
    SO_REUSEADDR,
    SO_RCVTIMEO
)
# from .ip import (
#     convert_binary_ip_to_string,
#     build_sockaddr,
#     build_sockaddr_in,
#     convert_binary_port_to_int,
#     convert_sockaddr_to_host_port,
# )
from lightbug_http.io.bytes import Bytes
from .net import Addr, TCPAddr, HostPort, get_peer_name, default_buffer_size, convert_binary_port_to_int, convert_binary_ip_to_string, resolve_internet_addr, addrinfo_macos, addrinfo_unix
from sys import sizeof, external_call
from sys.info import os_is_macos
from memory import Pointer, UnsafePointer
from .utils import logger


alias SocketClosedError = "Socket: Socket is already closed"



struct Socket[AddrType: Addr]():
    """Represents a network file descriptor. Wraps around a file descriptor and provides network functions.

    Args:
        local_address: The local address of the socket (local address if bound).
        remote_address: The remote address of the socket (peer's address if connected).
        address_family: The address family of the socket.
        socket_type: The socket type.
        protocol: The protocol.
    """

    var fd: Int32
    """The file descriptor of the socket."""
    var address_family: Int
    """The address family of the socket."""
    var socket_type: Int32
    """The socket type."""
    var protocol: Byte
    """The protocol."""
    var _local_address: AddrType
    """The local address of the socket (local address if bound)."""
    var _remote_address: AddrType
    """The remote address of the socket (peer's address if connected)."""
    var _closed: Bool
    """Whether the socket is closed."""
    var _is_connected: Bool
    """Whether the socket is connected."""

    fn __init__(
        out self,
        local_address: AddrType = AddrType(),
        remote_address: AddrType = AddrType(),
        address_family: Int = AF_INET,
        socket_type: Int32 = SOCK_STREAM,
        protocol: Byte = 0,
    ) raises:
        """Create a new socket object.

        Args:
            local_address: The local address of the socket (local address if bound).
            remote_address: The remote address of the socket (peer's address if connected).
            address_family: The address family of the socket.
            socket_type: The socket type.
            protocol: The protocol.

        Raises:
            Error: If the socket creation fails.
        """
        self.address_family = address_family
        self.socket_type = socket_type
        self.protocol = protocol

        self.fd = socket(address_family, socket_type, 0)
        self._local_address = local_address
        self._remote_address = remote_address
        self._closed = False
        self._is_connected = False

    fn __init__(
        out self,
        fd: Int32,
        address_family: Int,
        socket_type: Int32,
        protocol: Byte,
        local_address: AddrType,
        remote_address: AddrType,
    ):
        """
        Create a new socket object when you already have a socket file descriptor. Typically through socket.accept().

        Args:
            fd: The file descriptor of the socket.
            address_family: The address family of the socket.
            socket_type: The socket type.
            protocol: The protocol.
            local_address: The local address of the socket (local address if bound).
            remote_address: The remote address of the socket (peer's address if connected).
        """
        self.fd = fd
        self.address_family = address_family
        self.socket_type = socket_type
        self.protocol = protocol
        self._local_address = local_address
        self._remote_address = remote_address
        self._closed = False
        self._is_connected = True

    fn __moveinit__(out self, owned existing: Self):
        """Initialize a new socket object by moving the data from an existing socket object.

        Args:
            existing: The existing socket object to move the data from.
        """
        self.fd = existing.fd
        self.address_family = existing.address_family
        self.socket_type = existing.socket_type
        self.protocol = existing.protocol
        self._local_address = existing._local_address^
        self._remote_address = existing._remote_address^
        self._closed = existing._closed
        self._is_connected = existing._is_connected
    
    fn _teardown(mut self) raises:
        """Close the socket and free the file descriptor."""
        if self._is_connected:
            try:
                shutdown(self.fd, SHUT_RDWR)
            except e:
                logger.error("Socket._teardown: Failed to shutdown listener: " + str(e))
                logger.error(e)

        if not self._closed:
            try:
                close(self.fd)
            except e:
                logger.error(e)
                raise Error("Socket._teardown: Failed to close listener.")

    fn __enter__(owned self) -> Self:
        return self^

    fn __exit__(mut self) raises:
        self._teardown()

    fn __del__(owned self):
        """Close the socket when the object is deleted."""
        if not self._closed:
            try:
                self._teardown()
            except e:
                logger.error("Socket.__del__: Failed to close socket during deletion:", str(e))

    fn local_address(ref self) -> ref [self._local_address] AddrType:
        """Return the local address of the socket as a UDP address.

        Returns:
            The local address of the socket as a UDP address.
        """
        return self._local_address

    fn remote_address(ref self) -> ref [self._remote_address] AddrType:
        """Return the remote address of the socket as a UDP address.

        Returns:
            The remote address of the socket as a UDP address.
        """
        return self._remote_address

    fn accept(self) raises -> Socket[AddrType]:
        """Accept a connection. The socket must be bound to an address and listening for connections.
        The return value is a connection where conn is a new socket object usable to send and receive data on the connection,
        and address is the address bound to the socket on the other end of the connection.

        Returns:
            A new socket object and the address of the remote socket.

        Raises:
            Error: If the connection fails.
        """
        var remote_address = sockaddr()        
        var new_sockfd: c_int
        try:
            new_sockfd = accept(
                self.fd, 
                Pointer.address_of(remote_address),
                Pointer.address_of(socklen_t(sizeof[socklen_t]())))
        except e:
            logger.error(e)
            raise Error("Socket.accept: Failed to accept connection, system `accept()` returned an error.")

        var remote = get_peer_name(new_sockfd)
        return Socket(
            fd=new_sockfd,
            address_family=self.address_family,
            socket_type=self.socket_type,
            protocol=self.protocol,
            local_address=self.local_address(),
            remote_address=AddrType(remote.host, int(remote.port)),
        )

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
            logger.error(e)
            raise Error("Socket.listen: Failed to listen for connections.")

    fn bind[network: String = "tcp4"](mut self, address: String, port: Int) raises:
        """Bind the socket to address. The socket must not already be bound. (The format of address depends on the address family).

        When a socket is created with Socket(), it exists in a name
        space (address family) but has no address assigned to it.  bind()
        assigns the address specified by addr to the socket referred to
        by the file descriptor fd.  addrlen specifies the size, in
        bytes, of the address structure pointed to by addr.
        Traditionally, this operation is called 'assigning a name to a
        socket'.

        Args:
            address: The IP address to bind the socket to.
            port: The port number to bind the socket to.

        Raises:
            Error: If binding the socket fails.
        """
        var addr: TCPAddr
        try:
            addr = resolve_internet_addr(network, address)
        except e:
            raise Error("ListenConfig.listen: Failed to resolve host address - " + str(e))

        var ip_buf_size = 4
        if self.address_family == AF_INET6:
            ip_buf_size = 16
        var ip_buf = UnsafePointer[c_void].alloc(ip_buf_size)

        try:
            inet_pton(self.address_family, addr.ip.unsafe_ptr(), ip_buf)
        except e:
            logger.error(e)
            raise Error("ListenConfig.listen: Failed to convert IP address to binary form.")

        var local_address = sockaddr_in(
            sin_family=self.address_family,
            sin_port=htons(port),
            sin_addr=in_addr(ip_buf.bitcast[c_uint]().take_pointee()),
            sin_zero=StaticTuple[c_char, 8]()
        )
        try:
            bind(self.fd, Pointer.address_of(local_address), sizeof[sockaddr_in]())
        except e:
            logger.error(e)
            raise Error("Socket.bind: Binding socket failed.")

        var local = self.get_sock_name()
        self._local_address = AddrType(local.host, int(local.port))

    fn get_sock_name(self) raises -> HostPort:
        """Return the address of the socket.

        Returns:
            The address of the socket.

        Raises:
            Error: If getting the address of the socket fails.
        """
        if self._closed:
            raise SocketClosedError

        # TODO: Add check to see if the socket is bound and error if not.
        var local_address = stack_allocation[1, sockaddr]()
        try:
            getsockname(
                self.fd,
                local_address,
                Pointer.address_of(socklen_t(sizeof[sockaddr]())),
            )
        except e:
            logger.error(e)
            raise Error("get_sock_name: Failed to get address of local socket.")

        var addr_in = local_address.bitcast[sockaddr_in]().take_pointee()
        return HostPort(
            host=convert_binary_ip_to_string(addr_in.sin_addr.s_addr, AF_INET, INET_ADDRSTRLEN),
            port=convert_binary_port_to_int(addr_in.sin_port),
        )

    fn get_peer_name(self) raises -> HostPort:
        """Return the address of the peer connected to the socket.

        Returns:
            The address of the peer connected to the socket.

        Raises:
            Error: If getting the address of the peer connected to the socket fails.
        """
        if self._closed:
            raise SocketClosedError

        # TODO: Add check to see if the socket is bound and error if not.
        var remote_address = stack_allocation[1, sockaddr]()
        try:
            getpeername(
                self.fd,
                remote_address,
                Pointer.address_of(socklen_t(sizeof[sockaddr]())),
            )
        except e:
            logger.error(e)
            raise Error("get_peer_name: Failed to get address of remote socket.")

        # Cast sockaddr struct to sockaddr_in to convert binary IP to string.
        var addr_in = remote_address.bitcast[sockaddr_in]().take_pointee()
        return HostPort(
            host=convert_binary_ip_to_string(addr_in.sin_addr.s_addr, AF_INET, INET_ADDRSTRLEN),
            port=convert_binary_port_to_int(addr_in.sin_port),
        )


    fn get_socket_option(self, option_name: Int) raises -> Int:
        """Return the value of the given socket option.

        Args:
            option_name: The socket option to get.

        Returns:
            The value of the given socket option.

        Raises:
            Error: If getting the socket option fails.
        """
        var option_value_pointer = stack_allocation[1, c_void]()
        try:
            getsockopt(
                self.fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                option_value_pointer,
                sizeof[Int](),
            )
        except e:
            # TODO: Should this be a warning or an error?
            logger.warn("Socket.get_socket_option: Failed to get socket option.")
            raise e

        return option_value_pointer.bitcast[Int]().take_pointee()

    fn set_socket_option(self, option_name: Int, owned option_value: Byte = 1) raises:
        """Return the value of the given socket option.

        Args:
            option_name: The socket option to set.
            option_value: The value to set the socket option to.

        Raises:
            Error: If setting the socket option fails.
        """
        try:
            setsockopt(
                self.fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                Pointer[c_void].address_of(option_value),
                sizeof[Int](),
            )
        except e:
            # TODO: Should this be a warning or an error?
            logger.warn("Socket.set_socket_option: Failed to set socket option.")
            raise e

    fn connect(mut self, address: String, port: Int) raises -> None:
        """Connect to a remote socket at address.

        Args:
            address: String - The IP address to connect to.
            port: The port number to connect to.

        Raises:
            Error: If connecting to the remote socket fails.
        """
        @parameter
        if os_is_macos():
            ip = addrinfo_macos().get_ip_address(address)
        else:
            ip = addrinfo_unix().get_ip_address(address)

        var addr = sockaddr_in(self.address_family, htons(port), in_addr(ip.s_addr), StaticTuple[c_char, 8](0, 0, 0, 0, 0, 0, 0, 0))
        try:
            connect(self.fd, addr, sizeof[sockaddr_in]())
        except e:
            logger.error("Socket.connect: Failed to establish a connection to the server.")
            raise e

        var remote = self.get_peer_name()
        self._remote_address = AddrType(remote.host, remote.port)

    # @always_inline
    # fn write_bytes(mut self, bytes: Span[Byte]) raises -> None:
    #     """Write a `Span[Byte]` to this `Writer`.

    #     Args:
    #         bytes: The string slice to write to this Writer. Must NOT be null-terminated.
    #     """
    #     if len(bytes) == 0:
    #         return

    #     var bytes_sent = send(self.fd, bytes.unsafe_ptr(), len(bytes), 0)
    #     # if bytes_sent == -1:
    #     #     abort("Failed to send message")

    # fn write[*Ts: Writable](mut self, *args: *Ts) -> None:
    #     """Write data to the File Descriptor.

    #     Parameters:
    #         Ts: The types of data to write to the file descriptor.

    #     Args:
    #         args: The data to write to the file descriptor.
    #     """

    #     @parameter
    #     fn write_arg[T: Writable](arg: T):
    #         arg.write_to(self)

    #     args.each[write_arg]()

    fn send(self, buffer: Span[Byte]) raises -> Int:
        if buffer[-1] == 0:
            raise Error("Socket.send: Buffer must not be null-terminated.")
        
        try:
            return send(self.fd, buffer.unsafe_ptr(), len(buffer), 0)
        except e:
            logger.error("Socket.send: Failed to write data to connection.")
            raise e

    fn send_all(self, src: Span[Byte], max_attempts: Int = 3) raises -> None:
        """Send data to the socket. The socket must be connected to a remote socket.

        Args:
            src: The data to send.
            max_attempts: The maximum number of attempts to send the data.

        Raises:
            Error: If sending the data fails, or if the data is not sent after the maximum number of attempts.
        """
        var total_bytes_sent = 0
        var attempts = 0

        # Try to send all the data in the buffer. If it did not send all the data, keep trying but start from the offset of the last successful send.
        while total_bytes_sent < len(src):
            if attempts > max_attempts:
                raise Error("Failed to send message after " + str(max_attempts) + " attempts.")

            var sent: Int
            try:
                sent = self.send(src[total_bytes_sent:])
            except e:
                logger.error(e)
                raise Error("Socket.send_all: Failed to send message, wrote" + str(total_bytes_sent) + "bytes before failing.")

            total_bytes_sent += sent
            attempts += 1

    # fn send_to(mut self, src: Span[Byte], address: String, port: Int) raises -> Int:
    #     """Send data to the a remote address by connecting to the remote socket before sending.
    #     The socket must be not already be connected to a remote socket.

    #     Args:
    #         src: The data to send.
    #         address: The IP address to connect to.
    #         port: The port number to connect to.

    #     Returns:
    #         The number of bytes sent.

    #     Raises:
    #         Error: If sending the data fails.
    #     """
    #     sa = build_sockaddr(address, port, self.address_family)
    #     bytes_sent = sendto(
    #         self.fd,
    #         src.unsafe_ptr(),
    #         len(src),
    #         0,
    #         Pointer.address_of(sa),
    #         sizeof[sockaddr_in](),
    #     )

    #     if bytes_sent == -1:
    #         raise Error("Socket.send_to: Failed to send message to remote socket at: " + address + ":" + str(port))

    #     return bytes_sent
    
    fn _receive(mut self, mut buffer: Bytes) raises -> Bytes:
        """Receive data from the socket into the buffer.

        Args:
            buffer: The buffer to read data into.
        
        Returns:
            The buffer with the received data, and an error if one occurred.
        
        Raises:
            Error: If reading data from the socket fails.
            EOF: If 0 bytes are received, return EOF.
        """
        var bytes_received: Int
        try:
            bytes_received = recv(
                self.fd,
                buffer.unsafe_ptr().offset(buffer.size),
                buffer.capacity - buffer.size,
                0,
            )
            buffer.size += bytes_received
        except e:
            logger.error(e)
            raise Error("Socket.receive: Failed to read data from connection.")

        if bytes_received == 0:
            raise Error("EOF")

        return buffer
    
    fn receive(mut self, size: Int = default_buffer_size) raises -> List[Byte, True]:
        """Receive data from the socket into the buffer with capacity of `size` bytes.

        Args:
            size: The size of the buffer to receive data into.

        Returns:
            The buffer with the received data, and an error if one occurred.
        """
        var buffer = Bytes(capacity=size)
        return self._receive(buffer)
    
    fn receive_into(mut self, mut buffer: Bytes) raises -> List[Byte, True]:
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

    # fn receive_from(mut self, mut buffer: Bytes) raises -> (List[Byte, True], HostPort):
    #     """Receive data from the socket into the buffer dest.

    #     Args:
    #         buffer: The buffer to read data into.

    #     Returns:
    #         The number of bytes read, the remote address, and an error if one occurred.

    #     Raises:
    #         Error: If reading data from the socket fails.
    #     """
    #     remote_address = sockaddr()
    #     # remote_address_ptr = UnsafePointer[sockaddr].alloc(1)
    #     remote_address_ptr_size = socklen_t(sizeof[sockaddr]())
    #     buffer = UnsafePointer[Byte].alloc(size)
    #     bytes_received = recvfrom(
    #         self.fd,
    #         buffer,
    #         size,
    #         0,
    #         Pointer.address_of(remote_address),
    #         Pointer.address_of(remote_address_ptr_size),
    #     )

    #     if bytes_received == 0:
    #         raise "EOF"
    #     elif bytes_received == -1:
    #         raise Error("Failed to read from socket, received a -1 response.")

    #     remote = convert_sockaddr_to_host_port(remote_address)
    #     return List[Byte, True](ptr=buffer, length=bytes_received, capacity=size), remote

    # fn receive_from_into(mut self, mut dest: List[Byte, True]) raises -> (Int, HostPort):
    #     """Receive data from the socket into the buffer dest.

    #     Args:
    #         dest: The buffer to read data into.

    #     Returns:
    #         The number of bytes read, the remote address, and an error if one occurred.

    #     Raises:
    #         Error: If reading data from the socket fails.
    #     """
    #     remote_address = sockaddr()
    #     # remote_address_ptr = UnsafePointer[sockaddr].alloc(1)
    #     remote_address_ptr_size = socklen_t(sizeof[sockaddr]())
    #     bytes_read = recvfrom(
    #         self.fd,
    #         dest.unsafe_ptr() + len(dest),
    #         dest.capacity - dest.size,
    #         0,
    #         Pointer.address_of(remote_address),
    #         Pointer.address_of(remote_address_ptr_size),
    #     )
    #     dest.size += bytes_read

    #     if bytes_read == 0:
    #         raise "EOF"
    #     elif bytes_read == -1:
    #         raise Error("Socket.receive_from_into: Failed to read from socket, received a -1 response.")

    #     return bytes_read, convert_sockaddr_to_host_port(remote_address)

    fn shutdown(self) raises -> None:
        """Shut down the socket. The remote end will receive no more data (after queued data is flushed)."""
        try:
            shutdown(self.fd, SHUT_RDWR)
        except e:
            logger.error("Socket.shutdown: Failed to shutdown socket.")
            raise e

    fn close(mut self) raises -> None:
        """Mark the socket closed.
        Once that happens, all future operations on the socket object will fail.
        The remote end will receive no more data (after queued data is flushed).

        Raises:
            Error: If closing the socket fails.
        """
        try:
            close(self.fd)
        except e:
            logger.error("Socket.close: Failed to close socket.")
            raise e

        self._closed = True

    fn get_timeout(self) raises -> Int:
        """Return the timeout value for the socket."""
        return self.get_socket_option(SO_RCVTIMEO)

    fn set_timeout(self, owned duration: Int) raises:
        """Set the timeout value for the socket.

        Args:
            duration: Seconds - The timeout duration in seconds.
        """
        self.set_socket_option(SO_RCVTIMEO, duration)
