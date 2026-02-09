from sys.ffi import c_int, c_size_t, c_ssize_t, c_uchar, external_call, get_errno
from sys.info import CompilationTarget, size_of

from lightbug_http.c.aliases import c_void
from lightbug_http.c.network import SocketAddress, sockaddr, sockaddr_in, socklen_t
from lightbug_http.c.socket_error import *
from memory import stack_allocation


@fieldwise_init
@register_passable("trivial")
struct ShutdownOption(Copyable, Equatable, Stringable, Writable):
    var value: c_int
    comptime SHUT_RD = Self(0)
    comptime SHUT_WR = Self(1)
    comptime SHUT_RDWR = Self(2)

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self == Self.SHUT_RD:
            writer.write("SHUT_RD")
        elif self == Self.SHUT_WR:
            writer.write("SHUT_WR")
        else:
            writer.write("SHUT_RDWR")

    fn __str__(self) -> String:
        return String.write(self)


comptime SOL_SOCKET = 0xFFFF


# Socket option flags
# TODO: These are probably platform specific, on MacOS I have these values, but we should check on Linux.
# Taken from: https://github.com/openbsd/src/blob/master/sys/sys/socket.h
@fieldwise_init
@register_passable("trivial")
struct SocketOption(Copyable, Equatable, Stringable, Writable):
    var value: c_int
    comptime SO_DEBUG = Self(0x0001)
    comptime SO_ACCEPTCONN = Self(0x0002)
    comptime SO_REUSEADDR = Self(0x0004)
    comptime SO_KEEPALIVE = Self(0x0008)
    comptime SO_DONTROUTE = Self(0x0010)
    comptime SO_BROADCAST = Self(0x0020)
    comptime SO_USELOOPBACK = Self(0x0040)
    comptime SO_LINGER = Self(0x0080)
    comptime SO_OOBINLINE = Self(0x0100)
    comptime SO_REUSEPORT = Self(0x0200)
    comptime SO_TIMESTAMP = Self(0x0800)
    comptime SO_BINDANY = Self(0x1000)
    comptime SO_ZEROIZE = Self(0x2000)
    comptime SO_SNDBUF = Self(0x1001)
    comptime SO_RCVBUF = Self(0x1002)
    comptime SO_SNDLOWAT = Self(0x1003)
    comptime SO_RCVLOWAT = Self(0x1004)
    comptime SO_SNDTIMEO = Self(0x1005)
    comptime SO_RCVTIMEO = Self(0x1006)
    comptime SO_ERROR = Self(0x1007)
    comptime SO_TYPE = Self(0x1008)
    comptime SO_NETPROC = Self(0x1020)
    comptime SO_RTABLE = Self(0x1021)
    comptime SO_PEERCRED = Self(0x1022)
    comptime SO_SPLICE = Self(0x1023)
    comptime SO_DOMAIN = Self(0x1024)
    comptime SO_PROTOCOL = Self(0x1025)

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self == Self.SO_DEBUG:
            writer.write("SO_DEBUG")
        elif self == Self.SO_ACCEPTCONN:
            writer.write("SO_ACCEPTCONN")
        elif self == Self.SO_REUSEADDR:
            writer.write("SO_REUSEADDR")
        elif self == Self.SO_KEEPALIVE:
            writer.write("SO_KEEPALIVE")
        elif self == Self.SO_DONTROUTE:
            writer.write("SO_DONTROUTE")
        elif self == Self.SO_BROADCAST:
            writer.write("SO_BROADCAST")
        elif self == Self.SO_USELOOPBACK:
            writer.write("SO_USELOOPBACK")
        elif self == Self.SO_LINGER:
            writer.write("SO_LINGER")
        elif self == Self.SO_OOBINLINE:
            writer.write("SO_OOBINLINE")
        elif self == Self.SO_REUSEPORT:
            writer.write("SO_REUSEPORT")
        elif self == Self.SO_TIMESTAMP:
            writer.write("SO_TIMESTAMP")
        elif self == Self.SO_BINDANY:
            writer.write("SO_BINDANY")
        elif self == Self.SO_ZEROIZE:
            writer.write("SO_ZEROIZE")
        elif self == Self.SO_SNDBUF:
            writer.write("SO_SNDBUF")
        elif self == Self.SO_RCVBUF:
            writer.write("SO_RCVBUF")
        elif self == Self.SO_SNDLOWAT:
            writer.write("SO_SNDLOWAT")
        elif self == Self.SO_RCVLOWAT:
            writer.write("SO_RCVLOWAT")
        elif self == Self.SO_SNDTIMEO:
            writer.write("SO_SNDTIMEO")
        elif self == Self.SO_RCVTIMEO:
            writer.write("SO_RCVTIMEO")
        elif self == Self.SO_ERROR:
            writer.write("SO_ERROR")
        elif self == Self.SO_TYPE:
            writer.write("SO_TYPE")
        elif self == Self.SO_NETPROC:
            writer.write("SO_NETPROC")
        elif self == Self.SO_RTABLE:
            writer.write("SO_RTABLE")
        elif self == Self.SO_PEERCRED:
            writer.write("SO_PEERCRED")
        elif self == Self.SO_SPLICE:
            writer.write("SO_SPLICE")
        elif self == Self.SO_DOMAIN:
            writer.write("SO_DOMAIN")
        elif self == Self.SO_PROTOCOL:
            writer.write("SO_PROTOCOL")
        else:
            writer.write("SocketOption(", self.value, ")")

    fn __str__(self) -> String:
        return String.write(self)


# File open option flags
comptime O_NONBLOCK = 16384
comptime O_ACCMODE = 3
comptime O_CLOEXEC = 524288


# Socket Type constants
@fieldwise_init
@register_passable("trivial")
struct SocketType(Copyable, Equatable, Stringable, Writable):
    var value: c_int
    comptime SOCK_STREAM = Self(1)
    comptime SOCK_DGRAM = Self(2)
    comptime SOCK_RAW = Self(3)
    comptime SOCK_RDM = Self(4)
    comptime SOCK_SEQPACKET = Self(5)
    comptime SOCK_DCCP = Self(6)
    comptime SOCK_PACKET = Self(10)
    comptime SOCK_CLOEXEC = Self(O_CLOEXEC)
    comptime SOCK_NONBLOCK = Self(O_NONBLOCK)

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self == Self.SOCK_STREAM:
            writer.write("SOCK_STREAM")
        elif self == Self.SOCK_DGRAM:
            writer.write("SOCK_DGRAM")
        elif self == Self.SOCK_RAW:
            writer.write("SOCK_RAW")
        elif self == Self.SOCK_RDM:
            writer.write("SOCK_RDM")
        elif self == Self.SOCK_SEQPACKET:
            writer.write("SOCK_SEQPACKET")
        elif self == Self.SOCK_DCCP:
            writer.write("SOCK_DCCP")
        elif self == Self.SOCK_PACKET:
            writer.write("SOCK_PACKET")
        elif self == Self.SOCK_CLOEXEC:
            writer.write("SOCK_CLOEXEC")
        elif self == Self.SOCK_NONBLOCK:
            writer.write("SOCK_NONBLOCK")
        else:
            writer.write("SocketType(", self.value, ")")

    fn __str__(self) -> String:
        return String.write(self)


fn _socket(domain: c_int, type: c_int, protocol: c_int) -> c_int:
    """Libc POSIX `socket` function.

    Args:
        domain: Address Family see AF_ aliases.
        type: Socket Type see SOCK_ aliases.
        protocol: The protocol to use.

    Returns:
        A File Descriptor or -1 in case of failure.

    #### C Function
    ```c
    int socket(int domain, int type, int protocol);
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/socket.3p.html .
    """
    return external_call["socket", c_int, type_of(domain), type_of(type), type_of(protocol)](domain, type, protocol)


fn socket(domain: c_int, type: c_int, protocol: c_int) raises SocketError -> c_int:
    """Libc POSIX `socket` function.

    Args:
        domain: Address Family see AF_ aliases.
        type: Socket Type see SOCK_ aliases.
        protocol: The protocol to use.

    Returns:
        A File Descriptor or -1 in case of failure.

    Raises:
        SocketError: If an error occurs while creating the socket.
        * EACCES: Permission to create a socket of the specified type and/or protocol is denied.
        * EAFNOSUPPORT: The implementation does not support the specified address family.
        * EINVAL: Invalid flags in type, Unknown protocol, or protocol family not available.
        * EMFILE: The per-process limit on the number of open file descriptors has been reached.
        * ENFILE: The system-wide limit on the total number of open files has been reached.
        * ENOBUFS or ENOMEM: Insufficient memory is available. The socket cannot be created until sufficient resources are freed.
        * EPROTONOSUPPORT: The protocol type or the specified protocol is not supported within this domain.

    #### C Function
    ```c
    int socket(int domain, int type, int protocol)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/socket.3p.html .
    """
    var fd = _socket(domain, type, protocol)
    if fd == -1:
        var errno = get_errno()
        if errno == errno.EACCES:
            raise SocketEACCESError()
        elif errno == errno.EAFNOSUPPORT:
            raise SocketEAFNOSUPPORTError()
        elif errno == errno.EINVAL:
            raise SocketEINVALError()
        elif errno == errno.EMFILE:
            raise SocketEMFILEError()
        elif errno == errno.ENFILE:
            raise SocketENFILEError()
        elif errno in [errno.ENOBUFS, errno.ENOMEM]:
            raise SocketENOBUFSError()
        elif errno == errno.EPROTONOSUPPORT:
            raise SocketEPROTONOSUPPORTError()

    return fd


fn _setsockopt[
    origin: ImmutOrigin
](
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: UnsafePointer[c_void, origin],
    option_len: socklen_t,
) -> c_int:
    """Libc POSIX `setsockopt` function.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.
        option_value: A Pointer to the value to set.
        option_len: The size of the value.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/setsockopt.3p.html .
    """
    return external_call[
        "setsockopt",
        c_int,  # FnName, RetType
        type_of(socket),
        type_of(level),
        type_of(option_name),
        type_of(option_value),
        type_of(option_len),  # Args
    ](socket, level, option_name, option_value, option_len)


fn setsockopt(
    socket: FileDescriptor,
    level: c_int,
    option_name: c_int,
    option_value: c_int,
) raises SetsockoptError:
    """Libc POSIX `setsockopt` function. Manipulate options for the socket referred to by the file descriptor, `socket`.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.
        option_value: A UnsafePointer to the value to set.

    Raises:
        SetsockoptError: If an error occurs while setting the socket option.
        * EBADF: The argument `socket` is not a valid descriptor.
        * EFAULT: The argument `option_value` points outside the process's allocated address space.
        * EINVAL: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid.
        * ENOPROTOOPT: The option is unknown at the level indicated.
        * ENOTSOCK: The argument `socket` is not a socket.

    #### C Function
    ```c
    int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len);
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/setsockopt.3p.html .
    """
    var result = _setsockopt(
        socket.value,
        level,
        option_name,
        UnsafePointer(to=option_value).bitcast[c_void](),
        size_of[Int32](),
    )
    if result == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise SetsockoptEBADFError()
        elif errno == errno.EFAULT:
            raise SetsockoptEFAULTError()
        elif errno == errno.EINVAL:
            raise SetsockoptEINVALError()
        elif errno == errno.ENOPROTOOPT:
            raise SetsockoptENOPROTOOPTError()
        elif errno == errno.ENOTSOCK:
            raise SetsockoptENOTSOCKError()
        else:
            raise Error(
                "SetsockoptError: An error occurred while setting the socket option. Error code: ",
                errno,
            )


fn _getsockopt[
    origin: MutOrigin
](
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: ImmutUnsafePointer[c_void],
    option_len: Pointer[socklen_t, origin],
) -> c_int:
    """Libc POSIX `getsockopt` function.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.
        option_value: A Pointer to the value to set.
        option_len: The size of the value.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int getsockopt(int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len);
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockopt.3p.html
    """
    return external_call[
        "getsockopt",
        c_int,  # FnName, RetType
        type_of(socket),
        type_of(level),
        type_of(option_name),
        type_of(option_value),
        type_of(option_len),  # Args
    ](socket, level, option_name, option_value, option_len)


fn getsockopt(
    socket: FileDescriptor,
    level: c_int,
    option_name: c_int,
) raises GetsockoptError -> Int:
    """Libc POSIX `getsockopt` function.

    Manipulate options for the socket referred to by the file descriptor, `socket`.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.

    Returns:
        The value of the option.

    Raises:
        GetsockoptError: If an error occurs while getting the socket option.
        * EBADF: The argument `socket` is not a valid descriptor.
        * EFAULT: The argument `option_value` points outside the process's allocated address space.
        * EINVAL: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid.
        * ENOPROTOOPT: The option is unknown at the level indicated.
        * ENOTSOCK: The argument `socket` is not a socket.

    #### C Function
    ```c
    int getsockopt(int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len);
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockopt.3p.html .
    """
    var option_value = stack_allocation[1, c_void]()
    var option_len: socklen_t = size_of[Int]()
    var result = _getsockopt(socket.value, level, option_name, option_value, Pointer(to=option_len))
    if result == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise GetsockoptEBADFError()
        elif errno == errno.EFAULT:
            raise GetsockoptEFAULTError()
        elif errno == errno.EINVAL:
            raise GetsockoptEINVALError()
        elif errno == errno.ENOPROTOOPT:
            raise GetsockoptENOPROTOOPTError()
        elif errno == errno.ENOTSOCK:
            raise GetsockoptENOTSOCKError()
        else:
            raise Error(
                "GetsockoptError: An error occurred while getting the socket option. Error code: ",
                errno,
            )

    return option_value.bitcast[Int]().take_pointee()


fn _getsockname[
    origin: MutOrigin
](socket: c_int, address: MutUnsafePointer[sockaddr], address_len: Pointer[socklen_t, origin],) -> c_int:
    """Libc POSIX `getsockname` function.

    Args:
        socket: A File Descriptor.
        address: A UnsafePointer to a buffer to store the address of the peer.
        address_len: A Pointer to the size of the buffer.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int getsockname(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockname.3p.html
    """
    return external_call[
        "getsockname",
        c_int,  # FnName, RetType
        type_of(socket),
        type_of(address),
        type_of(address_len),  # Args
    ](socket, address, address_len)


fn getsockname(socket: FileDescriptor, mut address: SocketAddress) raises GetsocknameError:
    """Libc POSIX `getsockname` function.

    Args:
        socket: A File Descriptor.
        address: A to a buffer to store the address of the peer.

    Raises:
        Error: If an error occurs while getting the socket name.
        EBADF: The argument `socket` is not a valid descriptor.
        EFAULT: The `address` argument points to memory not in a valid part of the process address space.
        EINVAL: `address_len` is invalid (e.g., is negative).
        ENOBUFS: Insufficient resources were available in the system to perform the operation.
        ENOTSOCK: The argument `socket` is not a socket, it is a file.

    #### C Function
    ```c
    int getsockname(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockname.3p.html .
    """
    var sockaddr_size = address.SIZE
    var result = _getsockname(socket.value, address.unsafe_ptr(), Pointer(to=sockaddr_size))
    if result == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise GetsocknameEBADFError()
        elif errno == errno.EFAULT:
            raise GetsocknameEFAULTError()
        elif errno == errno.EINVAL:
            raise GetsocknameEINVALError()
        elif errno == errno.ENOBUFS:
            raise GetsocknameENOBUFSError()
        elif errno == errno.ENOTSOCK:
            raise GetsocknameENOTSOCKError()


fn _getpeername[
    origin: MutOrigin
](sockfd: c_int, addr: MutUnsafePointer[sockaddr], address_len: Pointer[socklen_t, origin],) -> c_int:
    """Libc POSIX `getpeername` function.

    Args:
        sockfd: A File Descriptor.
        addr: A UnsafePointer to a buffer to store the address of the peer.
        address_len: A UnsafePointer to the size of the buffer.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int getpeername(int socket, struct sockaddr *restrict addr, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man2/getpeername.2.html .
    """
    return external_call[
        "getpeername",
        c_int,  # FnName, RetType
        type_of(sockfd),
        type_of(addr),
        type_of(address_len),  # Args
    ](sockfd, addr, address_len)


fn getpeername(file_descriptor: FileDescriptor) raises GetpeernameError -> SocketAddress:
    """Libc POSIX `getpeername` function.

    Args:
        file_descriptor: A File Descriptor.

    Raises:
        Error: If an error occurs while getting the socket name.
        EBADF: The argument `socket` is not a valid descriptor.
        EFAULT: The `addr` argument points to memory not in a valid part of the process address space.
        EINVAL: `address_len` is invalid (e.g., is negative).
        ENOBUFS: Insufficient resources were available in the system to perform the operation.
        ENOTCONN: The socket is not connected.
        ENOTSOCK: The argument `socket` is not a socket, it is a file.

    #### C Function
    ```c
    int getpeername(int socket, struct sockaddr *restrict addr, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man2/getpeername.2.html .
    """
    var remote_address = SocketAddress()
    var sockaddr_size = remote_address.SIZE
    var result = _getpeername(
        file_descriptor.value,
        remote_address.unsafe_ptr(),
        Pointer(to=sockaddr_size),
    )
    if result == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise GetpeernameEBADFError()
        elif errno == errno.EFAULT:
            raise GetpeernameEFAULTError()
        elif errno == errno.EINVAL:
            raise GetpeernameEINVALError()
        elif errno == errno.ENOBUFS:
            raise GetpeernameENOBUFSError()
        elif errno == errno.ENOTCONN:
            raise GetpeernameENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise GetpeernameENOTSOCKError()

    return remote_address^


fn _bind[origin: ImmutOrigin](socket: c_int, address: Pointer[sockaddr_in, origin], address_len: socklen_t) -> c_int:
    """Libc POSIX `bind` function. Assigns the address specified by `address` to the socket referred to by
       the file descriptor `socket`.

    Args:
        socket: A File Descriptor.
        address: A UnsafePointer to the address to bind to.
        address_len: The size of the address.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int bind(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/bind.3p.html
    """
    return external_call["bind", c_int, type_of(socket), type_of(address), type_of(address_len)](
        socket, address, address_len
    )


fn bind(socket: FileDescriptor, mut address: SocketAddress) raises BindError:
    """Libc POSIX `bind` function.

    Args:
        socket: A File Descriptor.
        address: A UnsafePointer to the address to bind to.

    Raises:
        Error: If an error occurs while binding the socket.
        EACCES: The address, `address`, is protected, and the user is not the superuser.
        EADDRINUSE: The given address is already in use.
        EBADF: `socket` is not a valid descriptor.
        EINVAL: The socket is already bound to an address.
        ENOTSOCK: `socket` is a descriptor for a file, not a socket.

        # The following errors are specific to UNIX domain (AF_UNIX) sockets
        EACCES: Search permission is denied on a component of the path prefix. (See also path_resolution(7).)
        EADDRNOTAVAIL: A nonexistent interface was requested or the requested address was not local.
        EFAULT: `address` points outside the user's accessible address space.
        EINVAL: The `address_len` is wrong, or the socket was not in the AF_UNIX family.
        ELOOP: Too many symbolic links were encountered in resolving addr.
        ENAMETOOLONG: `address` is too long.
        ENOENT: The file does not exist.
        ENOMEM: Insufficient kernel memory was available.
        ENOTDIR: A component of the path prefix is not a directory.
        EROFS: The socket inode would reside on a read-only file system.

    #### C Function
    ```c
    int bind(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/bind.3p.html .
    """
    var result = _bind(socket.value, Pointer(to=address.as_sockaddr_in()), address.SIZE)
    if result == -1:
        var errno = get_errno()
        if errno == errno.EACCES:
            raise BindEACCESError()
        elif errno == errno.EADDRINUSE:
            raise BindEADDRINUSEError()
        elif errno == errno.EBADF:
            raise BindEBADFError()
        elif errno == errno.EINVAL:
            raise BindEINVALError()
        elif errno == errno.ENOTSOCK:
            raise BindENOTSOCKError()

        # The following errors are specific to UNIX domain (AF_UNIX) sockets. TODO: Pass address_family when unix sockets supported.
        # if address_family == AF_UNIX:
        #     if errno == errno.EACCES:
        #       raise BindEACCESError()

        raise Error(
            "bind: An error occurred while binding the socket. Error code: ",
            errno,
        )


fn _listen(socket: c_int, backlog: c_int) -> c_int:
    """Libc POSIX `listen` function.

    Args:
        socket: A File Descriptor.
        backlog: The maximum length of the queue of pending connections.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int listen(int socket, int backlog)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/listen.3p.html
    """
    return external_call["listen", c_int, type_of(socket), type_of(backlog)](socket, backlog)


fn listen(socket: FileDescriptor, backlog: c_int) raises ListenError:
    """Libc POSIX `listen` function.

    Args:
        socket: A File Descriptor.
        backlog: The maximum length of the queue of pending connections.

    Raises:
        Error: If an error occurs while listening on the socket.
        EADDRINUSE: Another socket is already listening on the same port.
        EBADF: `socket` is not a valid descriptor.
        ENOTSOCK: `socket` is a descriptor for a file, not a socket.
        EOPNOTSUPP: The socket is not of a type that supports the `listen()` operation.

    #### C Function
    ```c
    int listen(int socket, int backlog)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/listen.3p.html .
    """
    var result = _listen(socket.value, backlog)
    if result == -1:
        var errno = get_errno()
        if errno == errno.EADDRINUSE:
            raise ListenEADDRINUSEError()
        elif errno == errno.EBADF:
            raise ListenEBADFError()
        elif errno == errno.ENOTSOCK:
            raise ListenENOTSOCKError()
        elif errno == errno.EOPNOTSUPP:
            raise ListenEOPNOTSUPPError()


fn _accept[
    address_origin: MutOrigin, len_origin: MutOrigin
](socket: c_int, address: Pointer[sockaddr, address_origin], address_len: Pointer[socklen_t, len_origin],) -> c_int:
    """Libc POSIX `accept` function.

    Args:
        socket: A File Descriptor.
        address: A Pointer to a buffer to store the address of the peer.
        address_len: A Pointer to the size of the buffer.

    Returns:
        A File Descriptor or -1 in case of failure.

    #### C Function
    ```c
    int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/accept.3p.html .
    """
    return external_call["accept", c_int, type_of(socket), type_of(address), type_of(address_len)](  # FnName, RetType
        socket, address, address_len
    )


fn accept(socket: FileDescriptor) raises AcceptError -> FileDescriptor:
    """Libc POSIX `accept` function.

    Args:
        socket: A File Descriptor.

    Raises:
        Error: If an error occurs while listening on the socket.
        EAGAIN or EWOULDBLOCK: The socket is marked nonblocking and no connections are present to be accepted. POSIX.1-2001 allows either error to be returned for this case, and does not require these constants to have the same value, so a portable application should check for both possibilities.
        EBADF: `socket` is not a valid descriptor.
        ECONNABORTED: `socket` is not a valid descriptor.
        EFAULT: The `address` argument is not in a writable part of the user address space.
        EINTR: The system call was interrupted by a signal that was caught before a valid connection arrived; see `signal(7)`.
        EINVAL: Socket is not listening for connections, or `addr_length` is invalid (e.g., is negative).
        EMFILE: The per-process limit of open file descriptors has been reached.
        ENFILE: The system limit on the total number of open files has been reached.
        ENOBUFS or ENOMEM: Not enough free memory. This often means that the memory allocation is limited by the socket buffer limits, not by the system memory.
        ENOTSOCK: `socket` is a descriptor for a file, not a socket.
        EOPNOTSUPP: The referenced socket is not of type `SOCK_STREAM`.
        EPROTO: Protocol error.

        # Linux specific errors
        EPERM: Firewall rules forbid connection.

    #### C Function
    ```c
    int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/accept.3p.html .
    """
    var remote_address = sockaddr()
    # TODO: Should this be sizeof sockaddr?
    var buffer_size = socklen_t(size_of[socklen_t]())
    var result = _accept(socket.value, Pointer(to=remote_address), Pointer(to=buffer_size))
    if result == -1:
        var errno = get_errno()
        if errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
            raise AcceptEAGAINError()
        elif errno == errno.EBADF:
            raise AcceptEBADFError()
        elif errno == errno.ECONNABORTED:
            raise AcceptECONNABORTEDError()
        elif errno == errno.EFAULT:
            raise AcceptEFAULTError()
        elif errno == errno.EINTR:
            raise AcceptEINTRError()
        elif errno == errno.EINVAL:
            raise AcceptEINVALError()
        elif errno == errno.EMFILE:
            raise AcceptEMFILEError()
        elif errno == errno.ENFILE:
            raise AcceptENFILEError()
        elif errno in [errno.ENOBUFS, errno.ENOMEM]:
            raise AcceptENOBUFSError()
        elif errno == errno.ENOTSOCK:
            raise AcceptENOTSOCKError()
        elif errno == errno.EOPNOTSUPP:
            raise AcceptEOPNOTSUPPError()
        elif errno == errno.EPROTO:
            raise AcceptEPROTOError()

        @parameter
        if CompilationTarget.is_linux():
            if errno == errno.EPERM:
                raise AcceptEPERMError()

    return FileDescriptor(Int(result))


fn _connect[origin: ImmutOrigin](socket: c_int, address: Pointer[sockaddr_in, origin], address_len: socklen_t) -> c_int:
    """Libc POSIX `connect` function.

    Args:
        socket: A File Descriptor.
        address: A Pointer to the address to connect to.
        address_len: The size of the address.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int connect(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/connect.3p.html
    """
    return external_call[
        "connect",
        c_int,
        type_of(socket),
        type_of(address),
        type_of(address_len),
    ](socket, address, address_len)


fn connect(socket: FileDescriptor, mut address: SocketAddress) raises ConnectError:
    """Libc POSIX `connect` function.

    Args:
        socket: A File Descriptor.
        address: The address to connect to.

    Raises:
        Error: If an error occurs while connecting to the socket.
        EACCES: For UNIX domain sockets, which are identified by pathname: Write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix. (See also path_resolution(7)).
        EADDRINUSE: Local address is already in use.
        EAGAIN: No more free local ports or insufficient entries in the routing cache.
        EALREADY: The socket is nonblocking and a previous connection attempt has not yet been completed.
        EBADF: The file descriptor is not a valid index in the descriptor table.
        ECONNREFUSED: No-one listening on the remote address.
        EFAULT: The socket structure address is outside the user's address space.
        EINPROGRESS: The socket is nonblocking and the connection cannot be completed immediately. It is possible to select(2) or poll(2) for completion by selecting the socket for writing. After select(2) indicates writability, use getsockopt(2) to read the SO_ERROR option at level SOL_SOCKET to determine whether connect() completed successfully (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error codes listed here, explaining the reason for the failure).
        EINTR: The system call was interrupted by a signal that was caught.
        EISCONN: The socket is already connected.
        ENETUNREACH: Network is unreachable.
        ENOTSOCK: The file descriptor is not associated with a socket.
        EAFNOSUPPORT: The passed address didn't have the correct address family in its `sa_family` field.
        ETIMEDOUT: Timeout while attempting connection. The server may be too busy to accept new connections.

    #### C Function
    ```c
    int connect(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/connect.3p.html .
    """
    var result = _connect(socket.value, Pointer(to=address.as_sockaddr_in()), address.SIZE)
    if result == -1:
        var errno = get_errno()
        if errno == errno.EACCES:
            raise ConnectEACCESError()
        elif errno == errno.EADDRINUSE:
            raise ConnectEADDRINUSEError()
        elif errno == errno.EAGAIN:
            raise ConnectEAGAINError()
        elif errno == errno.EALREADY:
            raise ConnectEALREADYError()
        elif errno == errno.EBADF:
            raise ConnectEBADFError()
        elif errno == errno.ECONNREFUSED:
            raise ConnectECONNREFUSEDError()
        elif errno == errno.EFAULT:
            raise ConnectEFAULTError()
        elif errno == errno.EINPROGRESS:
            raise ConnectEINPROGRESSError()
        elif errno == errno.EINTR:
            raise ConnectEINTRError()
        elif errno == errno.EISCONN:
            raise ConnectEISCONNError()
        elif errno == errno.ENETUNREACH:
            raise ConnectENETUNREACHError()
        elif errno == errno.ENOTSOCK:
            raise ConnectENOTSOCKError()
        elif errno == errno.EAFNOSUPPORT:
            raise ConnectEAFNOSUPPORTError()
        elif errno == errno.ETIMEDOUT:
            raise ConnectETIMEDOUTError()


fn _recv(
    socket: c_int,
    buffer: MutUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
) -> c_ssize_t:
    """Libc POSIX `recv` function.

    Args:
        socket: A File Descriptor.
        buffer: A UnsafePointer to the buffer to store the received data.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes received or -1 in case of failure.

    #### C Function
    ```c
    ssize_t recv(int socket, void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recv.3p.html
    """
    return external_call[
        "recv",
        c_ssize_t,  # FnName, RetType
        type_of(socket),
        type_of(buffer),
        type_of(length),
        type_of(flags),  # Args
    ](socket, buffer, length, flags)


fn recv[
    origin: MutOrigin
](socket: FileDescriptor, buffer: Span[c_uchar, origin], length: c_size_t, flags: c_int,) raises RecvError -> c_size_t:
    """Libc POSIX `recv` function.

    Args:
        socket: A File Descriptor.
        buffer: A UnsafePointer to the buffer to store the received data.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes received.

    Raises:
        RecvError: If an error occurs while receiving data from the socket.

    #### C Function
    ```c
    ssize_t recv(int socket, void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recv.3p.html .
    """
    var result = _recv(socket.value, buffer.unsafe_ptr().bitcast[c_void](), length, flags)
    if result == -1:
        var errno = get_errno()
        if errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
            raise RecvEAGAINError()
        elif errno == errno.EBADF:
            raise RecvEBADFError()
        elif errno == errno.ECONNREFUSED:
            raise RecvECONNREFUSEDError()
        elif errno == errno.EFAULT:
            raise RecvEFAULTError()
        elif errno == errno.EINTR:
            raise RecvEINTRError()
        elif errno == errno.ENOTCONN:
            raise RecvENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise RecvENOTSOCKError()
        else:
            raise Error(
                "RecvError: An error occurred while attempting to receive data from the socket. Error code: ",
                errno,
            )

    return UInt(result)


fn _recvfrom[
    origin: MutOrigin
](
    socket: c_int,
    buffer: MutUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
    address: MutUnsafePointer[sockaddr],
    address_len: Pointer[socklen_t, origin],
) -> c_ssize_t:
    """Libc POSIX `recvfrom` function.

    Args:
        socket: Specifies the socket file descriptor.
        buffer: Points to the buffer where the message should be stored.
        length: Specifies the length in bytes of the buffer pointed to by the buffer argument.
        flags: Specifies the type of message reception.
        address: A null pointer, or points to a sockaddr structure in which the sending address is to be stored.
        address_len: Either a null pointer, if address is a null pointer, or a pointer to a socklen_t object which on input specifies the length of the supplied sockaddr structure, and on output specifies the length of the stored address.

    Returns:
        The number of bytes received or -1 in case of failure.

    #### C Function
    ```c
    ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
        int flags, struct sockaddr *restrict address,
        socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recvfrom.3p.html .
    * Valid Flags:
        * `MSG_PEEK`: Peeks at an incoming message. The data is treated as unread and the next recvfrom() or similar function shall still return this data.
        * `MSG_OOB`: Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_WAITALL`: On SOCK_STREAM sockets this requests that the function block until the full amount of data can be returned. The function may return the smaller amount of data if the socket is a message-based socket, if a signal is caught, if the connection is terminated, if MSG_PEEK was specified, or if an error is pending for the socket.

    """
    return external_call[
        "recvfrom",
        c_ssize_t,
        type_of(socket),
        type_of(buffer),
        type_of(length),
        type_of(flags),
        type_of(address),
        type_of(address_len),
    ](socket, buffer, length, flags, address, address_len)


fn recvfrom[
    origin: MutOrigin
](
    socket: FileDescriptor,
    buffer: Span[c_uchar, origin],
    length: c_size_t,
    flags: c_int,
    mut address: SocketAddress,
) raises RecvfromError -> c_size_t:
    """Libc POSIX `recvfrom` function.

    Args:
        socket: Specifies the socket file descriptor.
        buffer: Points to the buffer where the message should be stored.
        length: Specifies the length in bytes of the buffer pointed to by the buffer argument.
        flags: Specifies the type of message reception.
        address: A null pointer, or points to a sockaddr structure in which the sending address is to be stored.

    Returns:
        The number of bytes received.

    Raises:
        RecvfromError: If an error occurs while receiving data from the socket.

    #### C Function
    ```c
    ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
        int flags, struct sockaddr *restrict address,
        socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recvfrom.3p.html .
    * Valid Flags:
        * `MSG_PEEK`: Peeks at an incoming message. The data is treated as unread and the next recvfrom() or similar function shall still return this data.
        * `MSG_OOB`: Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_WAITALL`: On SOCK_STREAM sockets this requests that the function block until the full amount of data can be returned. The function may return the smaller amount of data if the socket is a message-based socket, if a signal is caught, if the connection is terminated, if MSG_PEEK was specified, or if an error is pending for the socket.
    """
    var address_buffer_size = address.SIZE
    var result = _recvfrom(
        socket.value,
        buffer.unsafe_ptr().bitcast[c_void](),
        length,
        flags,
        address.unsafe_ptr(),
        Pointer(to=address_buffer_size),
    )
    if result == -1:
        var errno = get_errno()
        if errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
            raise RecvfromEAGAINError()
        elif errno == errno.EBADF:
            raise RecvfromEBADFError()
        elif errno == errno.ECONNRESET:
            raise RecvfromECONNRESETError()
        elif errno == errno.EINTR:
            raise RecvfromEINTRError()
        elif errno == errno.EINVAL:
            raise RecvfromEINVALError()
        elif errno == errno.ENOTCONN:
            raise RecvfromENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise RecvfromENOTSOCKError()
        elif errno == errno.EOPNOTSUPP:
            raise RecvfromEOPNOTSUPPError()
        elif errno == errno.ETIMEDOUT:
            raise RecvfromETIMEDOUTError()
        elif errno == errno.EIO:
            raise RecvfromEIOError()
        elif errno == errno.ENOBUFS:
            raise RecvfromENOBUFSError()
        elif errno == errno.ENOMEM:
            raise RecvfromENOMEMError()
        else:
            raise Error(
                "RecvfromError: An error occurred while attempting to receive data from the socket. Error code: ",
                errno,
            )

    return UInt(result)


fn _send(
    socket: c_int,
    buffer: ImmutUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
) -> c_ssize_t:
    """Libc POSIX `send` function.

    Args:
        socket: A File Descriptor.
        buffer: A UnsafePointer to the buffer to send.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes sent or -1 in case of failure.

    #### C Function
    ```c
    ssize_t send(int socket, const void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/send.3p.html
    """
    return external_call[
        "send",
        c_ssize_t,
        type_of(socket),
        type_of(buffer),
        type_of(length),
        type_of(flags),
    ](socket, buffer, length, flags)


fn send[
    origin: ImmutOrigin
](socket: FileDescriptor, buffer: Span[c_uchar, origin], length: c_size_t, flags: c_int,) raises SendError -> c_size_t:
    """Libc POSIX `send` function.

    Args:
        socket: A File Descriptor.
        buffer: A UnsafePointer to the buffer to send.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes sent.

    Raises:
        Error: If an error occurs while attempting to receive data from the socket.
        EAGAIN or EWOULDBLOCK: The socket is marked nonblocking and the receive operation would block, or a receive timeout had been set and the timeout expired before data was received.
        EBADF: The argument `socket` is an invalid descriptor.
        ECONNRESET: Connection reset by peer.
        EDESTADDRREQ: The socket is not connection-mode, and no peer address is set.
        ECONNREFUSED: The remote host refused to allow the network connection (typically because it is not running the requested service).
        EFAULT: `buffer` points outside the process's address space.
        EINTR: The receive was interrupted by delivery of a signal before any data were available.
        EINVAL: Invalid argument passed.
        EISCONN: The connection-mode socket was connected already but a recipient was specified.
        EMSGSIZE: The socket type requires that message be sent atomically, and the size of the message to be sent made this impossible.
        ENOBUFS: The output queue for a network interface was full. This generally indicates that the interface has stopped sending, but may be caused by transient congestion.
        ENOMEM: No memory available.
        ENOTCONN: The socket is not connected.
        ENOTSOCK: The file descriptor is not associated with a socket.
        EOPNOTSUPP: Some bit in the flags argument is inappropriate for the socket type.
        EPIPE: The local end has been shut down on a connection oriented socket. In this case the process will also receive a SIGPIPE unless MSG_NOSIGNAL is set.

    #### C Function
    ```c
    ssize_t send(int socket, const void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/send.3p.html .
    """
    var result = _send(socket.value, buffer.unsafe_ptr().bitcast[c_void](), length, flags)
    if result == -1:
        var errno = get_errno()
        if errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
            raise SendEAGAINError()
        elif errno == errno.EBADF:
            raise SendEBADFError()
        elif errno == errno.ECONNRESET:
            raise SendECONNRESETError()
        elif errno == errno.EDESTADDRREQ:
            raise SendEDESTADDRREQError()
        elif errno == errno.ECONNREFUSED:
            raise SendECONNREFUSEDError()
        elif errno == errno.EFAULT:
            raise SendEFAULTError()
        elif errno == errno.EINTR:
            raise SendEINTRError()
        elif errno == errno.EINVAL:
            raise SendEINVALError()
        elif errno == errno.EISCONN:
            raise SendEISCONNError()
        elif errno == errno.ENOBUFS:
            raise SendENOBUFSError()
        elif errno == errno.ENOMEM:
            raise SendENOMEMError()
        elif errno == errno.ENOTCONN:
            raise SendENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise SendENOTSOCKError()
        elif errno == errno.EOPNOTSUPP:
            raise SendEOPNOTSUPPError()
        else:
            raise Error(
                "SendError: An error occurred while attempting to send data to the socket. Error code: ",
                errno,
            )

    return UInt(result)


fn _sendto(
    socket: c_int,
    message: ImmutUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
    dest_addr: ImmutUnsafePointer[sockaddr],
    dest_len: socklen_t,
) -> c_ssize_t:
    """Libc POSIX `sendto` function

    Args:
        socket: Specifies the socket file descriptor.
        message: Points to a buffer containing the message to be sent.
        length: Specifies the size of the message in bytes.
        flags: Specifies the type of message transmission.
        dest_addr: Points to a sockaddr structure containing the destination address.
        dest_len: Specifies the length of the sockaddr.

    Returns:
        The number of bytes sent or -1 in case of failure.

    #### C Function
    ```c
    ssize_t sendto(int socket, const void *message, size_t length,
    int flags, const struct sockaddr *dest_addr,
    socklen_t dest_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/sendto.3p.html
    * Valid Flags:
        * `MSG_EOR`: Terminates a record (if supported by the protocol).
        * `MSG_OOB`: Sends out-of-band data on sockets that support out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_NOSIGNAL`: Requests not to send the SIGPIPE signal if an attempt to send is made on a stream-oriented socket that is no longer connected. The [EPIPE] error shall still be returned.
    """
    return external_call[
        "sendto",
        c_ssize_t,
        type_of(socket),
        type_of(message),
        type_of(length),
        type_of(flags),
        type_of(dest_addr),
        type_of(dest_len),
    ](socket, message, length, flags, dest_addr, dest_len)


fn sendto[
    origin: ImmutOrigin
](
    socket: FileDescriptor,
    message: Span[c_uchar, origin],
    length: c_size_t,
    flags: c_int,
    mut dest_addr: SocketAddress,
) raises SendtoError -> c_size_t:
    """Libc POSIX `sendto` function.

    Args:
        socket: Specifies the socket file descriptor.
        message: Points to a buffer containing the message to be sent.
        length: Specifies the size of the message in bytes.
        flags: Specifies the type of message transmission.
        dest_addr: Points to a sockaddr structure containing the destination address.

    Raises:
        SendtoError: If an error occurs while sending data to the socket.

    #### C Function
    ```c
    ssize_t sendto(int socket, const void *message, size_t length,
    int flags, const struct sockaddr *dest_addr,
    socklen_t dest_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/sendto.3p.html
    * Valid Flags:
        * `MSG_EOR`: Terminates a record (if supported by the protocol).
        * `MSG_OOB`: Sends out-of-band data on sockets that support out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_NOSIGNAL`: Requests not to send the SIGPIPE signal if an attempt to send is made on a stream-oriented socket that is no longer connected. The [EPIPE] error shall still be returned.

    """
    var result = _sendto(
        socket.value,
        message.unsafe_ptr().bitcast[c_void](),
        length,
        flags,
        dest_addr.unsafe_ptr().as_immutable(),
        dest_addr.SIZE,
    )
    if result == -1:
        var errno = get_errno()
        if errno == errno.EAFNOSUPPORT:
            raise SendtoEAFNOSUPPORTError()
        elif errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
            raise SendtoEAGAINError()
        elif errno == errno.EBADF:
            raise SendtoEBADFError()
        elif errno == errno.ECONNRESET:
            raise SendtoECONNRESETError()
        elif errno == errno.EINTR:
            raise SendtoEINTRError()
        elif errno == errno.EMSGSIZE:
            raise SendtoEMSGSIZEError()
        elif errno == errno.ENOTCONN:
            raise SendtoENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise SendtoENOTSOCKError()
        elif errno == errno.EPIPE:
            raise SendtoEPIPEError()
        elif errno == errno.EACCES:
            raise SendtoEACCESError()
        elif errno == errno.EDESTADDRREQ:
            raise SendtoEDESTADDRREQError()
        elif errno == errno.EHOSTUNREACH:
            raise SendtoEHOSTUNREACHError()
        elif errno == errno.EINVAL:
            raise SendtoEINVALError()
        elif errno == errno.EIO:
            raise SendtoEIOError()
        elif errno == errno.EISCONN:
            raise SendtoEISCONNError()
        elif errno == errno.ENETDOWN:
            raise SendtoENETDOWNError()
        elif errno == errno.ENETUNREACH:
            raise SendtoENETUNREACHError()
        elif errno == errno.ENOBUFS:
            raise SendtoENOBUFSError()
        elif errno == errno.ENOMEM:
            raise SendtoENOMEMError()
        elif errno == errno.ELOOP:
            raise SendtoELOOPError()
        elif errno == errno.ENAMETOOLONG:
            raise SendtoENAMETOOLONGError()
        else:
            raise Error(
                "SendtoError: An error occurred while attempting to send data to the socket. Error code: ",
                errno,
            )

    return UInt(result)


fn _shutdown(socket: c_int, how: c_int) -> c_int:
    """Libc POSIX `shutdown` function.

    Args:
        socket: A File Descriptor.
        how: How to shutdown the socket.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int shutdown(int socket, int how)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/shutdown.3p.html .
    """
    return external_call["shutdown", c_int, type_of(socket), type_of(how)](socket, how)


fn shutdown(socket: FileDescriptor, how: ShutdownOption) raises ShutdownError:
    """Libc POSIX `shutdown` function.

    Args:
        socket: A File Descriptor.
        how: How to shutdown the socket.

    Raises:
        Error: If an error occurs while attempting to receive data from the socket.
        EBADF: The argument `socket` is an invalid descriptor.
        EINVAL: Invalid argument passed.
        ENOTCONN: The socket is not connected.
        ENOTSOCK: The file descriptor is not associated with a socket.

    #### C Function
    ```c
    int shutdown(int socket, int how)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/shutdown.3p.html .
    """
    var result = _shutdown(socket.value, how.value)
    if result == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise ShutdownEBADFError()
        elif errno == errno.EINVAL:
            raise ShutdownEINVALError()
        elif errno == errno.ENOTCONN:
            raise ShutdownENOTCONNError()
        elif errno == errno.ENOTSOCK:
            raise ShutdownENOTSOCKError()


fn _close(fildes: c_int) -> c_int:
    """Libc POSIX `close` function.

    Args:
        fildes: A File Descriptor to close.

    Returns:
        Upon successful completion, 0 shall be returned; otherwise, -1
        shall be returned and errno set to indicate the error.

    #### C Function
    ```c
    int close(int fildes).
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/close.3p.html
    """
    return external_call["close", c_int, type_of(fildes)](fildes)


fn close(file_descriptor: FileDescriptor) raises CloseError:
    """Libc POSIX `close` function.

    Args:
        file_descriptor: A File Descriptor to close.

    Raises:
        SocketError: If an error occurs while creating the socket.
        EACCES: Permission to create a socket of the specified type and/or protocol is denied.
        EAFNOSUPPORT: The implementation does not support the specified address family.
        EINVAL: Invalid flags in type, Unknown protocol, or protocol family not available.
        EMFILE: The per-process limit on the number of open file descriptors has been reached.
        ENFILE: The system-wide limit on the total number of open files has been reached.
        ENOBUFS or ENOMEM: Insufficient memory is available. The socket cannot be created until sufficient resources are freed.
        EPROTONOSUPPORT: The protocol type or the specified protocol is not supported within this domain.

    #### C Function
    ```c
    int close(int fildes)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/close.3p.html .
    """
    if _close(file_descriptor.value) == -1:
        var errno = get_errno()
        if errno == errno.EBADF:
            raise CloseEBADFError()
        elif errno == errno.EINTR:
            raise CloseEINTRError()
        elif errno == errno.EIO:
            raise CloseEIOError()
        elif errno in [errno.ENOSPC, errno.EDQUOT]:
            raise CloseENOSPCError()
