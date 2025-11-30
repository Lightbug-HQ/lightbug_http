from time import sleep
from memory import Span
from sys.info import CompilationTarget
from lightbug_http.address import NetworkType
from lightbug_http.io.bytes import Bytes, ByteView, bytes
from lightbug_http.io.sync import Duration
from lightbug_http.address import parse_address, TCPAddr, UDPAddr
from lightbug_http._libc import (
    sockaddr,
    SOCK_DGRAM,
    SO_REUSEADDR,
    socket,
    connect,
    listen,
    accept,
    send,
    bind,
    shutdown,
    close,
)
from lightbug_http._logger import logger
from lightbug_http.socket import Socket


alias default_buffer_size = 4096
"""The default buffer size for reading and writing data."""
alias default_tcp_keep_alive = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds
"""The default TCP keep-alive duration."""


trait Connection(Movable):
    fn read(self, mut buf: Bytes) raises -> UInt:
        ...

    fn write(self, buf: Span[Byte]) raises -> UInt:
        ...

    fn close(mut self) raises:
        ...

    fn shutdown(mut self) raises -> None:
        ...

    fn teardown(mut self) raises:
        ...

    fn local_addr(self) -> TCPAddr:
        ...

    fn remote_addr(self) -> TCPAddr:
        ...


struct NoTLSListener:
    """A TCP listener that listens for incoming connections and can accept them."""

    var socket: Socket[TCPAddr]

    fn __init__(out self, var socket: Socket[TCPAddr]):
        self.socket = socket^

    fn __init__(out self) raises:
        self.socket = Socket[TCPAddr]()

    fn __moveinit__(out self, deinit existing: Self):
        self.socket = existing.socket^

    fn accept(self) raises -> TCPConnection:
        return TCPConnection(self.socket.accept())

    fn close(mut self) raises -> None:
        return self.socket.close()

    fn shutdown(mut self) raises -> None:
        return self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn addr(self) -> TCPAddr:
        return self.socket.local_address()


struct ListenConfig:
    var _keep_alive: Duration

    fn __init__(out self, keep_alive: Duration = default_tcp_keep_alive):
        self._keep_alive = keep_alive

    fn listen[network: NetworkType = NetworkType.tcp4](mut self, address: String) raises -> NoTLSListener:
        var local = parse_address[origin_of(address)](network, address)
        var addr = TCPAddr(ip=String(local[0]), port=local[1])
        var socket: Socket[TCPAddr]
        try:
            socket = Socket[TCPAddr]()
        except e:
            logger.error(e)
            raise Error("ListenConfig.listen: Failed to create listener due to socket creation failure.")

        @parameter
        # TODO: do we want to add SO_REUSEPORT on linux? Doesn't work on some systems
        if CompilationTarget.is_macos():
            try:
                socket.set_socket_option(SO_REUSEADDR, 1)
            except e:
                logger.warn("ListenConfig.listen: Failed to set socket as reusable", e)

        var bind_success = False
        var bind_fail_logged = False
        while not bind_success:
            try:
                socket.bind(addr.ip, addr.port)
                bind_success = True
            except e:
                if not bind_fail_logged:
                    print("Bind attempt failed: ", e)
                    print("Retrying. Might take 10-15 seconds.")
                    bind_fail_logged = True
                print(".", end="", flush=True)

                try:
                    socket.shutdown()
                except e:
                    logger.error("ListenConfig.listen: Failed to shutdown socket:", e)
                    # TODO: Should shutdown failure be a hard failure? We can still ungracefully close the socket.
                sleep(UInt(1))

        try:
            socket.listen(128)
        except e:
            logger.error(e)
            raise Error("ListenConfig.listen: Listen failed on sockfd: " + String(socket.fd))

        var listener = NoTLSListener(socket^)
        var msg = String.write("\n🔥🐝 Lightbug is listening on ", "http://", addr.ip, ":", String(addr.port))
        print(msg)
        print("Ready to accept connections...")

        return listener^


struct TCPConnection(Connection):
    var socket: Socket[TCPAddr]

    fn __init__(out self, var socket: Socket[TCPAddr]):
        self.socket = socket^

    fn __moveinit__(out self, deinit existing: Self):
        self.socket = existing.socket^

    fn read(self, mut buf: Bytes) raises -> UInt:
        try:
            return self.socket.receive(buf)
        except e:
            if String(e) == "EOF":
                raise e
            else:
                logger.error(e)
                raise Error("TCPConnection.read: Failed to read data from connection.")

    fn write(self, buf: Span[Byte]) raises -> UInt:
        try:
            return self.socket.send(buf)
        except e:
            logger.error("TCPConnection.write: Failed to write data to connection.")
            raise e

    fn close(mut self) raises:
        self.socket.close()

    fn shutdown(mut self) raises:
        self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn is_closed(self) -> Bool:
        return self.socket._closed

    # TODO: Switch to property or return ref when trait supports attributes.
    fn local_addr(self) -> TCPAddr:
        return self.socket.local_address()

    fn remote_addr(self) -> TCPAddr:
        return self.socket.remote_address()


struct UDPConnection[network: NetworkType]:
    var socket: Socket[UDPAddr[network]]

    fn __init__(out self, var socket: Socket[UDPAddr[network]]):
        self.socket = socket^

    fn __moveinit__(out self, deinit existing: Self):
        self.socket = existing.socket^

    fn read_from(mut self, size: Int = default_buffer_size) raises -> Tuple[Bytes, String, UInt16]:
        """Reads data from the underlying file descriptor.

        Args:
            size: The size of the buffer to read data into.

        Returns:
            The number of bytes read, or an error if one occurred.

        Raises:
            Error: If an error occurred while reading data.
        """
        return self.socket.receive_from(size)

    fn read_from(mut self, mut dest: Bytes) raises -> Tuple[UInt, String, UInt16]:
        """Reads data from the underlying file descriptor.

        Args:
            dest: The buffer to read data into.

        Returns:
            The number of bytes read, or an error if one occurred.

        Raises:
            Error: If an error occurred while reading data.
        """
        return self.socket.receive_from(dest)

    fn write_to(mut self, src: Span[Byte], address: UDPAddr) raises -> UInt:
        """Writes data to the underlying file descriptor.

        Args:
            src: The buffer to read data into.
            address: The remote peer address.

        Returns:
            The number of bytes written, or an error if one occurred.

        Raises:
            Error: If an error occurred while writing data.
        """
        return self.socket.send_to(src, address.ip, address.port)

    fn write_to(mut self, src: Span[Byte], host: String, port: UInt16) raises -> UInt:
        """Writes data to the underlying file descriptor.

        Args:
            src: The buffer to read data into.
            host: The remote peer address in IPv4 format.
            port: The remote peer port.

        Returns:
            The number of bytes written, or an error if one occurred.

        Raises:
            Error: If an error occurred while writing data.
        """
        return self.socket.send_to(src, host, port)

    fn close(mut self) raises:
        self.socket.close()

    fn shutdown(mut self) raises:
        self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn is_closed(self) -> Bool:
        return self.socket._closed

    fn local_addr(self) -> ref [self.socket._local_address] UDPAddr[network]:
        return self.socket.local_address()

    fn remote_addr(self) -> ref [self.socket._remote_address] UDPAddr[network]:
        return self.socket.remote_address()


fn create_connection(host: String, port: UInt16) raises -> TCPConnection:
    """Connect to a server using a socket.

    Args:
        host: The host to connect to.
        port: The port to connect on.

    Returns:
        The socket file descriptor.
    """
    var socket = Socket[TCPAddr]()
    try:
        socket.connect(host, port)
    except e:
        logger.error(e)
        try:
            socket.shutdown()
        except e:
            logger.error("Failed to shutdown socket: " + String(e))
        raise Error("Failed to establish a connection to the server.")

    return TCPConnection(socket^)


fn listen_udp[network: NetworkType = NetworkType.udp4](local_address: UDPAddr) raises -> UDPConnection[network]:
    """Creates a new UDP listener.

    Args:
        local_address: The local address to listen on.

    Returns:
        A UDP connection.

    Raises:
        Error: If the address is invalid or failed to bind the socket.
    """
    var socket = Socket[UDPAddr[network]](socket_type=SOCK_DGRAM)
    socket.bind(local_address.ip, local_address.port)
    return UDPConnection[network](socket^)


fn listen_udp[network: NetworkType = NetworkType.udp4](local_address: String) raises -> UDPConnection[network]:
    """Creates a new UDP listener.

    Args:
        local_address: The address to listen on. The format is "host:port".

    Returns:
        A UDP connection.

    Raises:
        Error: If the address is invalid or failed to bind the socket.
    """
    var address = parse_address(NetworkType.udp4, local_address)
    return listen_udp[network](UDPAddr[network](String(address[0]), address[1]))


fn listen_udp[network: NetworkType = NetworkType.udp4](host: String, port: UInt16) raises -> UDPConnection[network]:
    """Creates a new UDP listener.

    Args:
        host: The address to listen on in ipv4 format.
        port: The port number.

    Returns:
        A UDP connection.

    Raises:
        Error: If the address is invalid or failed to bind the socket.
    """
    return listen_udp[network](UDPAddr[network](host, port))


fn dial_udp[network: NetworkType = NetworkType.udp4](local_address: UDPAddr[network]) raises -> UDPConnection[network]:
    """Connects to the address on the named network. The network must be "udp", "udp4", or "udp6".

    Args:
        local_address: The local address.

    Returns:
        The UDP connection.

    Raises:
        Error: If the network type is not supported or failed to connect to the address.
    """
    return UDPConnection(Socket[UDPAddr[network]](local_address=local_address, socket_type=SOCK_DGRAM))


fn dial_udp[network: NetworkType = NetworkType.udp4](local_address: String) raises -> UDPConnection[network]:
    """Connects to the address on the named network. The network must be "udp", "udp4", or "udp6".

    Args:
        local_address: The local address.

    Returns:
        The UDP connection.

    Raises:
        Error: If the network type is not supported or failed to connect to the address.
    """
    var address = parse_address(network, local_address)
    return dial_udp[network](UDPAddr[network](String(address[0]), address[1]))


fn dial_udp[network: NetworkType = NetworkType.udp4](host: String, port: UInt16) raises -> UDPConnection[network]:
    """Connects to the address on the udp network.

    Args:
        host: The host to connect to.
        port: The port to connect on.

    Returns:
        The UDP connection.

    Raises:
        Error: If failed to connect to the address.
    """
    return dial_udp[network](UDPAddr[network](host, port))
