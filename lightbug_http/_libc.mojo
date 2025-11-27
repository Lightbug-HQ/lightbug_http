from utils import StaticTuple
from sys.ffi import external_call, c_char, c_int, c_size_t, c_ssize_t, c_uchar, c_ushort, c_uint
from sys.info import size_of, CompilationTarget
from memory import memcpy, LegacyUnsafePointer, stack_allocation
from lightbug_http.io.bytes import Bytes

alias IPPROTO_IPV6 = 41
alias IPV6_V6ONLY = 26
alias EPROTONOSUPPORT = 93

# Adapted from https://github.com/gabrieldemarmiesse/mojo-stdlib-extensions/ . Huge thanks to Gabriel!

alias SUCCESS = 0
alias GRND_NONBLOCK: UInt8 = 1

# Adapted from https://github.com/crisadamo/mojo-Libc . Huge thanks to Cristian!
# C types
alias c_void = UInt8


# --- ( error.h Constants )-----------------------------------------------------
# TODO: These are probably platform specific, we should check the values on each linux and macos.
alias EPERM = 1
alias ENOENT = 2
alias ESRCH = 3
alias EINTR = 4
alias EIO = 5
alias ENXIO = 6
alias E2BIG = 7
alias ENOEXEC = 8
alias EBADF = 9
alias ECHILD = 10
alias EAGAIN = 11
alias ENOMEM = 12
alias EACCES = 13
alias EFAULT = 14
alias ENOTBLK = 15
alias EBUSY = 16
alias EEXIST = 17
alias EXDEV = 18
alias ENODEV = 19
alias ENOTDIR = 20
alias EISDIR = 21
alias EINVAL = 22
alias ENFILE = 23
alias EMFILE = 24
alias ENOTTY = 25
alias ETXTBSY = 26
alias EFBIG = 27
alias ENOSPC = 28
alias ESPIPE = 29
alias EROFS = 30
alias EMLINK = 31
alias EPIPE = 32
alias EDOM = 33
alias ERANGE = 34
alias EWOULDBLOCK = EAGAIN
alias EINPROGRESS = 36 if CompilationTarget.is_macos() else 115
alias EALREADY = 37 if CompilationTarget.is_macos() else 114
alias ENOTSOCK = 38 if CompilationTarget.is_macos() else 88
alias EDESTADDRREQ = 39 if CompilationTarget.is_macos() else 89
alias EMSGSIZE = 40 if CompilationTarget.is_macos() else 90
alias ENOPROTOOPT = 42 if CompilationTarget.is_macos() else 92
alias EAFNOSUPPORT = 47 if CompilationTarget.is_macos() else 97
alias EADDRINUSE = 48 if CompilationTarget.is_macos() else 98
alias EADDRNOTAVAIL = 49 if CompilationTarget.is_macos() else 99
alias ENETDOWN = 50 if CompilationTarget.is_macos() else 100
alias ENETUNREACH = 51 if CompilationTarget.is_macos() else 101
alias ECONNABORTED = 53 if CompilationTarget.is_macos() else 103
alias ECONNRESET = 54 if CompilationTarget.is_macos() else 104
alias ENOBUFS = 55 if CompilationTarget.is_macos() else 105
alias EISCONN = 56 if CompilationTarget.is_macos() else 106
alias ENOTCONN = 57 if CompilationTarget.is_macos() else 107
alias ETIMEDOUT = 60 if CompilationTarget.is_macos() else 110
alias ECONNREFUSED = 61 if CompilationTarget.is_macos() else 111
alias ELOOP = 62 if CompilationTarget.is_macos() else 40
alias ENAMETOOLONG = 63 if CompilationTarget.is_macos() else 36
alias EHOSTUNREACH = 65 if CompilationTarget.is_macos() else 113
alias EDQUOT = 69 if CompilationTarget.is_macos() else 122
alias ENOMSG = 91 if CompilationTarget.is_macos() else 42
alias EPROTO = 100 if CompilationTarget.is_macos() else 71
alias EOPNOTSUPP = 102 if CompilationTarget.is_macos() else 95

# --- ( Network Related Constants )---------------------------------------------
alias sa_family_t = c_ushort
alias socklen_t = c_uint
alias in_addr_t = c_uint
alias in_port_t = c_ushort


# TODO: These might vary on each platform...we should confirm this.
# Taken from: https://github.com/openbsd/src/blob/master/sys/sys/socket.h#L250
# Address Family Constants
@fieldwise_init
@register_passable("trivial")
struct AddressFamily(EqualityComparable & Copyable & Movable):
    var value: Int32
    alias AF_UNSPEC = Self(0)
    """unspecified"""
    alias AF_UNIX = Self(1)
    """local to host"""
    alias AF_LOCAL = Self.AF_UNIX
    """draft POSIX compatibility"""
    alias AF_INET = Self(2)
    """internetwork: UDP, TCP, etc."""
    alias AF_IMPLINK = Self(3)
    """arpanet imp addresses"""
    alias AF_PUP = Self(4)
    """pup protocols: e.g. BSP"""
    alias AF_CHAOS = Self(5)
    """mit CHAOS protocols"""
    alias AF_NS = Self(6)
    """XEROX NS protocols"""
    alias AF_ISO = Self(7)
    """ISO protocols"""
    alias AF_OSI = Self.AF_ISO
    alias AF_ECMA = Self(8)
    """european computer manufacturers"""
    alias AF_DATAKIT = Self(9)
    """datakit protocols"""
    alias AF_CCITT = Self(10)
    """CCITT protocols, X.25 etc"""
    alias AF_SNA = Self(11)
    """IBM SNA"""
    alias AF_DECnet = Self(12)
    """DECnet"""
    alias AF_DLI = Self(13)
    """DEC Direct data link interface"""
    alias AF_LAT = Self(14)
    """LAT"""
    alias AF_HYLINK = Self(15)
    """NSC Hyperchannel"""
    alias AF_APPLETALK = Self(16)
    """Apple Talk"""
    alias AF_ROUTE = Self(17)
    """Internal Routing Protocol"""
    alias AF_LINK = Self(18)
    """Link layer interface"""
    alias pseudo_AF_XTP = Self(19)
    """eXpress Transfer Protocol (no AF)"""
    alias AF_COIP = Self(20)
    """connection-oriented IP, aka ST II"""
    alias AF_CNT = Self(21)
    """Computer Network Technology"""
    alias pseudo_AF_RTIP = Self(22)
    """Help Identify RTIP packets"""
    alias AF_IPX = Self(23)
    """Novell Internet Protocol"""
    alias AF_INET6 = Self(24)
    """IPv6"""
    alias pseudo_AF_PIP = Self(25)
    """Help Identify PIP packets"""
    alias AF_ISDN = Self(26)
    """Integrated Services Digital Network"""
    alias AF_E164 = Self.AF_ISDN
    """CCITT E.164 recommendation"""
    alias AF_NATM = Self(27)
    """native ATM access"""
    alias AF_ENCAP = Self(28)
    alias AF_SIP = Self(29)
    """Simple Internet Protocol"""
    alias AF_KEY = Self(30)
    alias pseudo_AF_HDRCMPLT = Self(31)
    """Used by BPF to not rewrite headers in interface output routine"""
    alias AF_BLUETOOTH = Self(32)
    """Bluetooth"""
    alias AF_MPLS = Self(33)
    """MPLS"""
    alias pseudo_AF_PFLOW = Self(34)
    """pflow"""
    alias pseudo_AF_PIPEX = Self(35)
    """PIPEX"""
    alias AF_FRAME = Self(36)
    """frame (Ethernet) sockets"""
    alias AF_MAX = Self(37)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `AddressFamily` instances for equality.

        Args:
            other: The other `AddressFamily` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn __ne__(self, other: Self) -> Bool:
        """Compares two `AddressFamily` instances for inequality.

        Args:
            other: The other `AddressFamily` instance to compare to.

        Returns:
            True if the two instances are not equal, False otherwise.
        """
        return self.value != other.value


@fieldwise_init
@register_passable("trivial")
struct AddressLength:
    var value: Int
    alias INET_ADDRSTRLEN = Self(16)
    alias INET6_ADDRSTRLEN = Self(46)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `AddressLength` instances for equality.

        Args:
            other: The other `AddressLength` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn __ne__(self, other: Self) -> Bool:
        """Compares two `AddressLength` instances for inequality.

        Args:
            other: The other `AddressLength` instance to compare to.

        Returns:
            True if the two instances are not equal, False otherwise.
        """
        return self.value != other.value


# Protocol families, same as address families for now.
alias PF_UNSPEC = AddressFamily.AF_UNSPEC
alias PF_LOCAL = AddressFamily.AF_LOCAL
alias PF_UNIX = AddressFamily.AF_UNIX
alias PF_INET = AddressFamily.AF_INET
alias PF_IMPLINK = AddressFamily.AF_IMPLINK
alias PF_PUP = AddressFamily.AF_PUP
alias PF_CHAOS = AddressFamily.AF_CHAOS
alias PF_NS = AddressFamily.AF_NS
alias PF_ISO = AddressFamily.AF_ISO
alias PF_OSI = AddressFamily.AF_ISO
alias PF_ECMA = AddressFamily.AF_ECMA
alias PF_DATAKIT = AddressFamily.AF_DATAKIT
alias PF_CCITT = AddressFamily.AF_CCITT
alias PF_SNA = AddressFamily.AF_SNA
alias PF_DECnet = AddressFamily.AF_DECnet
alias PF_DLI = AddressFamily.AF_DLI
alias PF_LAT = AddressFamily.AF_LAT
alias PF_HYLINK = AddressFamily.AF_HYLINK
alias PF_APPLETALK = AddressFamily.AF_APPLETALK
alias PF_ROUTE = AddressFamily.AF_ROUTE
alias PF_LINK = AddressFamily.AF_LINK
alias PF_XTP = AddressFamily.pseudo_AF_XTP  # really just proto family, no AF
alias PF_COIP = AddressFamily.AF_COIP
alias PF_CNT = AddressFamily.AF_CNT
alias PF_IPX = AddressFamily.AF_IPX  # same format as = AddressFamily.AF_NS
alias PF_INET6 = AddressFamily.AF_INET6
alias PF_RTIP = AddressFamily.pseudo_AF_RTIP  # same format as AF_INET
alias PF_PIP = AddressFamily.pseudo_AF_PIP
alias PF_ISDN = AddressFamily.AF_ISDN
alias PF_NATM = AddressFamily.AF_NATM
alias PF_ENCAP = AddressFamily.AF_ENCAP
alias PF_SIP = AddressFamily.AF_SIP
alias PF_KEY = AddressFamily.AF_KEY
alias PF_BPF = AddressFamily.pseudo_AF_HDRCMPLT
alias PF_BLUETOOTH = AddressFamily.AF_BLUETOOTH
alias PF_MPLS = AddressFamily.AF_MPLS
alias PF_PFLOW = AddressFamily.pseudo_AF_PFLOW
alias PF_PIPEX = AddressFamily.pseudo_AF_PIPEX
alias PF_FRAME = AddressFamily.AF_FRAME
alias PF_MAX = AddressFamily.AF_MAX

# Socket Type constants
alias SOCK_STREAM = 1
alias SOCK_DGRAM = 2
alias SOCK_RAW = 3
alias SOCK_RDM = 4
alias SOCK_SEQPACKET = 5
alias SOCK_DCCP = 6
alias SOCK_PACKET = 10
alias SOCK_CLOEXEC = O_CLOEXEC
alias SOCK_NONBLOCK = O_NONBLOCK

# Address Information
alias AI_PASSIVE = 1
alias AI_CANONNAME = 2
alias AI_NUMERICHOST = 4
alias AI_V4MAPPED = 8
alias AI_ALL = 16
alias AI_ADDRCONFIG = 32
alias AI_IDN = 64


alias SHUT_RD = 0
alias SHUT_WR = 1
alias SHUT_RDWR = 2

alias SOL_SOCKET = 0xFFFF

# Socket option flags
# TODO: These are probably platform specific, on MacOS I have these values, but we should check on Linux.
# Taken from: https://github.com/openbsd/src/blob/master/sys/sys/socket.h
alias SO_DEBUG = 0x0001
alias SO_ACCEPTCONN = 0x0002
alias SO_REUSEADDR = 0x0004
alias SO_KEEPALIVE = 0x0008
alias SO_DONTROUTE = 0x0010
alias SO_BROADCAST = 0x0020
alias SO_USELOOPBACK = 0x0040
alias SO_LINGER = 0x0080
alias SO_OOBINLINE = 0x0100
alias SO_REUSEPORT = 0x0200
alias SO_TIMESTAMP = 0x0800
alias SO_BINDANY = 0x1000
alias SO_ZEROIZE = 0x2000
alias SO_SNDBUF = 0x1001
alias SO_RCVBUF = 0x1002
alias SO_SNDLOWAT = 0x1003
alias SO_RCVLOWAT = 0x1004
alias SO_SNDTIMEO = 0x1005
alias SO_RCVTIMEO = 0x1006
alias SO_ERROR = 0x1007
alias SO_TYPE = 0x1008
alias SO_NETPROC = 0x1020
alias SO_RTABLE = 0x1021
alias SO_PEERCRED = 0x1022
alias SO_SPLICE = 0x1023
alias SO_DOMAIN = 0x1024
alias SO_PROTOCOL = 0x1025


# --- ( Network Related Structs )-----------------------------------------------
@fieldwise_init
@register_passable("trivial")
struct in_addr:
    var s_addr: in_addr_t


@fieldwise_init
@register_passable("trivial")
struct in6_addr:
    var s6_addr: StaticTuple[c_char, 16]


@register_passable("trivial")
struct sockaddr:
    var sa_family: sa_family_t
    var sa_data: StaticTuple[c_char, 14]

    fn __init__(out self, family: sa_family_t = 0, data: StaticTuple[c_char, 14] = StaticTuple[c_char, 14]()):
        self.sa_family = family
        self.sa_data = data


@fieldwise_init
@register_passable("trivial")
struct sockaddr_in:
    var sin_family: sa_family_t
    var sin_port: in_port_t
    var sin_addr: in_addr
    var sin_zero: StaticTuple[c_char, 8]

    fn __init__(out self, address_family: Int, port: UInt16, binary_ip: UInt32):
        """Construct a sockaddr_in struct.

        Args:
            address_family: The address family.
            port: A 16-bit integer port in host byte order, gets converted to network byte order via `htons`.
            binary_ip: The binary representation of the IP address.
        """
        self.sin_family = address_family
        self.sin_port = htons(port)
        self.sin_addr = in_addr(binary_ip)
        self.sin_zero = StaticTuple[c_char, 8](0, 0, 0, 0, 0, 0, 0, 0)


@fieldwise_init
@register_passable("trivial")
struct sockaddr_in6:
    var sin6_family: sa_family_t
    var sin6_port: in_port_t
    var sin6_flowinfo: c_uint
    var sin6_addr: in6_addr
    var sin6_scope_id: c_uint


@fieldwise_init
@register_passable("trivial")
struct addrinfo:
    var ai_flags: c_int
    var ai_family: c_int
    var ai_socktype: c_int
    var ai_protocol: c_int
    var ai_addrlen: socklen_t
    var ai_addr: LegacyUnsafePointer[sockaddr]
    var ai_canonname: LegacyUnsafePointer[c_char]
    var ai_next: LegacyUnsafePointer[c_void]

    fn __init__(out self):
        self.ai_flags = 0
        self.ai_family = 0
        self.ai_socktype = 0
        self.ai_protocol = 0
        self.ai_addrlen = 0
        self.ai_addr = LegacyUnsafePointer[sockaddr]()
        self.ai_canonname = LegacyUnsafePointer[c_char]()
        self.ai_next = LegacyUnsafePointer[c_void]()


# --- ( Network Related Syscalls & Structs )------------------------------------


fn htonl(hostlong: c_uint) -> c_uint:
    """Libc POSIX `htonl` function.

    Args:
        hostlong: A 32-bit integer in host byte order.

    Returns:
        The value provided in network byte order.

    #### C Function
    ```c
    uint32_t htonl(uint32_t hostlong)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/htonl.3p.html .
    """
    return external_call["htonl", c_uint, c_uint](hostlong)


fn htons(hostshort: c_ushort) -> c_ushort:
    """Libc POSIX `htons` function.

    Args:
        hostshort: A 16-bit integer in host byte order.

    Returns:
        The value provided in network byte order.

    #### C Function
    ```c
    uint16_t htons(uint16_t hostshort)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/htonl.3p.html .
    """
    return external_call["htons", c_ushort, c_ushort](hostshort)


fn ntohl(netlong: c_uint) -> c_uint:
    """Libc POSIX `ntohl` function.

    Args:
        netlong: A 32-bit integer in network byte order.

    Returns:
        The value provided in host byte order.

    #### C Function
    ```c
    uint32_t ntohl(uint32_t netlong)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/htonl.3p.html .
    """
    return external_call["ntohl", c_uint, c_uint](netlong)


fn ntohs(netshort: c_ushort) -> c_ushort:
    """Libc POSIX `ntohs` function.

    Args:
        netshort: A 16-bit integer in network byte order.

    Returns:
        The value provided in host byte order.

    #### C Function
    ```c
    uint16_t ntohs(uint16_t netshort)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/htonl.3p.html .
    """
    return external_call["ntohs", c_ushort, c_ushort](netshort)


fn _inet_ntop(
    af: c_int,
    src: LegacyUnsafePointer[c_void, mut=False],
    dst: LegacyUnsafePointer[c_char],
    size: socklen_t,
) raises -> LegacyUnsafePointer[c_char, mut=False]:
    """Libc POSIX `inet_ntop` function.

    Args:
        af: Address Family see AF_ aliases.
        src: A LegacyUnsafePointer to a binary address.
        dst: A LegacyUnsafePointer to a buffer to store the result.
        size: The size of the buffer.

    Returns:
        A LegacyUnsafePointer to the buffer containing the result.

    #### C Function
    ```c
    const char *inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/inet_ntop.3p.html .
    """
    return external_call[
        "inet_ntop",
        LegacyUnsafePointer[c_char, mut=False],  # FnName, RetType
        c_int,
        LegacyUnsafePointer[c_void, mut=False],
        LegacyUnsafePointer[c_char],
        socklen_t,  # Args
    ](af, src, dst, size)


fn inet_ntop[address_family: AddressFamily, address_length: AddressLength](ip_address: UInt32) raises -> String:
    """Libc POSIX `inet_ntop` function.

    Parameters:
        address_family: Address Family see AF_ aliases.
        address_length: Address length.

    Args:
        ip_address: Binary IP address.

    Returns:
        The IP Address in the human readable format.

    Raises:
        Error: If an error occurs while converting the address.
        EAFNOSUPPORT: `*src` was not an `AF_INET` or `AF_INET6` family address.
        ENOSPC: The buffer size, `size`, was not large enough to store the presentation form of the address.

    #### C Function
    ```c
    const char *inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/inet_ntop.3p.html.
    """
    constrained[
        address_family in [AddressFamily.AF_INET, AddressFamily.AF_INET6],
        "Address family must be either AF_INET or AF_INET6.",
    ]()

    # TODO: For some reason, using a pointer instead of a String here leads to a "tried to free invalid ptr crash".
    # Ideally we should try not to modify private members of the String.
    var dst = LegacyUnsafePointer[c_char].alloc(address_length.value + 1)
    var result = _inet_ntop(
        address_family.value,
        LegacyUnsafePointer(to=ip_address).bitcast[c_void](),
        dst,
        address_length.value,
    )

    # `inet_ntop` returns NULL on error.
    if not result:
        var errno = get_errno()
        if errno == EAFNOSUPPORT:
            raise Error("inet_ntop Error: `*src` was not an `AF_INET` or `AF_INET6` family address.")
        elif errno == ENOSPC:
            raise Error(
                "inet_ntop Error: The buffer size, `size`, was not large enough to store the presentation form of the"
                " address."
            )
        else:
            raise Error("inet_ntop Error: An error occurred while converting the address. Error code: " + String(errno))

    var i = 0
    while i <= address_length.value:
        if result[i] == 0:
            break
        i += 1

    # Copy the dst pointer's contents into a new String.
    return String(StringSlice(ptr=dst.bitcast[c_uchar](), length=i))


fn _inet_pton(af: c_int, src: LegacyUnsafePointer[c_char, mut=False], dst: LegacyUnsafePointer[c_void]) -> c_int:
    """Libc POSIX `inet_pton` function. Converts a presentation format address (that is, printable form as held in a character string)
    to network format (usually a struct in_addr or some other internal binary representation, in network byte order).
    It returns 1 if the address was valid for the specified address family, or 0 if the address was not parseable in the specified address family,
    or -1 if some system error occurred (in which case errno will have been set).

    Args:
        af: Address Family: `AF_INET` or `AF_INET6`.
        src: A LegacyUnsafePointer to a string containing the address.
        dst: A LegacyUnsafePointer to a buffer to store the result.

    Returns:
        1 on success, 0 if the input is not a valid address, -1 on error.

    #### C Function
    ```c
    int inet_pton(int af, const char *restrict src, void *restrict dst)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/inet_ntop.3p.html .
    """
    return external_call[
        "inet_pton",
        c_int,
        c_int,
        LegacyUnsafePointer[c_char, mut=False],
        LegacyUnsafePointer[c_void],
    ](af, src, dst)


fn inet_pton[address_family: AddressFamily](var src: String) raises -> c_uint:
    """Libc POSIX `inet_pton` function. Converts a presentation format address (that is, printable form as held in a character string)
    to network format (usually a struct in_addr or some other internal binary representation, in network byte order).

    Parameters:
        address_family: Address Family: `AF_INET` or `AF_INET6`.

    Args:
        src: A LegacyUnsafePointer to a string containing the address.

    Returns:
        The binary representation of the ip address.

    Raises:
        Error: If an error occurs while converting the address or the input is not a valid address.

    #### C Function
    ```c
    int inet_pton(int af, const char *restrict src, void *restrict dst)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/inet_ntop.3p.html .
    * This function is valid for `AF_INET` and `AF_INET6`.
    """
    constrained[
        address_family in [AddressFamily.AF_INET, AddressFamily.AF_INET6],
        "Address family must be either AF_INET or AF_INET6.",
    ]()
    var ip_buffer: LegacyUnsafePointer[c_void]

    @parameter
    if address_family == AddressFamily.AF_INET6:
        ip_buffer = stack_allocation[16, c_void]()
    else:
        ip_buffer = stack_allocation[4, c_void]()

    var result = _inet_pton(address_family.value, src.unsafe_cstr_ptr(), ip_buffer)
    if result == 0:
        raise Error("inet_pton Error: The input is not a valid address.")
    elif result == -1:
        var errno = get_errno()
        raise Error("inet_pton Error: An error occurred while converting the address. Error code: ", errno)

    return ip_buffer.bitcast[c_uint]().take_pointee()


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
    int socket(int domain, int type, int protocol)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/socket.3p.html .
    """
    return external_call["socket", c_int, c_int, c_int, c_int](domain, type, protocol)


fn socket(domain: c_int, type: c_int, protocol: c_int) raises -> c_int:
    """Libc POSIX `socket` function.

    Args:
        domain: Address Family see AF_ aliases.
        type: Socket Type see SOCK_ aliases.
        protocol: The protocol to use.

    Returns:
        A File Descriptor or -1 in case of failure.

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
    int socket(int domain, int type, int protocol)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/socket.3p.html .
    """
    var fd = _socket(domain, type, protocol)
    if fd == -1:
        var errno = get_errno()
        if errno == EACCES:
            raise Error(
                "SocketError (EACCES): Permission to create a socket of the specified type and/or protocol is denied."
            )
        elif errno == EAFNOSUPPORT:
            raise Error("SocketError (EAFNOSUPPORT): The implementation does not support the specified address family.")
        elif errno == EINVAL:
            raise Error(
                "SocketError (EINVAL): Invalid flags in type, Unknown protocol, or protocol family not available."
            )
        elif errno == EMFILE:
            raise Error(
                "SocketError (EMFILE): The per-process limit on the number of open file descriptors has been reached."
            )
        elif errno == ENFILE:
            raise Error(
                "SocketError (ENFILE): The system-wide limit on the total number of open files has been reached."
            )
        elif Int(errno) in [ENOBUFS, ENOMEM]:
            raise Error(
                "SocketError (ENOBUFS or ENOMEM): Insufficient memory is available. The socket cannot be created until"
                " sufficient resources are freed."
            )
        elif errno == EPROTONOSUPPORT:
            raise Error(
                "SocketError (EPROTONOSUPPORT): The protocol type or the specified protocol is not supported within"
                " this domain."
            )
        else:
            raise Error("SocketError: An error occurred while creating the socket. Error code: " + String(errno))

    return fd


fn _setsockopt[
    origin: ImmutOrigin
](
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: Pointer[c_void, origin],
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
        c_int,
        c_int,
        c_int,
        Pointer[c_void, origin],
        socklen_t,  # Args
    ](socket, level, option_name, option_value, option_len)


fn setsockopt(
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: c_void,
) raises:
    """Libc POSIX `setsockopt` function. Manipulate options for the socket referred to by the file descriptor, `socket`.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.
        option_value: A LegacyUnsafePointer to the value to set.

    Raises:
        Error: If an error occurs while setting the socket option.
        EBADF: The argument `socket` is not a valid descriptor.
        EFAULT: The argument `option_value` points outside the process's allocated address space.
        EINVAL: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid.
        ENOPROTOOPT: The option is unknown at the level indicated.
        ENOTSOCK: The argument `socket` is not a socket.

    #### C Function
    ```c
    int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/setsockopt.3p.html .
    """
    var result = _setsockopt(socket, level, option_name, Pointer(to=option_value), size_of[Int]())
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("setsockopt: The argument `socket` is not a valid descriptor.")
        elif errno == EFAULT:
            raise Error("setsockopt: The argument `option_value` points outside the process's allocated address space.")
        elif errno == EINVAL:
            raise Error(
                "setsockopt: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid."
            )
        elif errno == ENOPROTOOPT:
            raise Error("setsockopt [InvalidProtocol]: The option is unknown at the level indicated.")
        elif errno == ENOTSOCK:
            raise Error("setsockopt: The argument `socket` is not a socket.")
        else:
            raise Error("setsockopt: An error occurred while setting the socket option. Error code: " + String(errno))


fn _getsockopt[
    len_origin: Origin
](
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: LegacyUnsafePointer[c_void, mut=False],
    option_len: Pointer[socklen_t, len_origin],
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
    int getsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/setsockopt.3p.html .
    """
    return external_call[
        "getsockopt",
        c_int,  # FnName, RetType
        c_int,
        c_int,
        c_int,
        LegacyUnsafePointer[c_void, mut=False],
        Pointer[socklen_t, len_origin],  # Args
    ](socket, level, option_name, option_value, option_len)


fn getsockopt(
    socket: c_int,
    level: c_int,
    option_name: c_int,
) raises -> Int:
    """Libc POSIX `getsockopt` function. Manipulate options for the socket referred to by the file descriptor, `socket`.

    Args:
        socket: A File Descriptor.
        level: The protocol level.
        option_name: The option to set.

    Returns:
        The value of the option.

    Raises:
        Error: If an error occurs while setting the socket option.
        EBADF: The argument `socket` is not a valid descriptor.
        EFAULT: The argument `option_value` points outside the process's allocated address space.
        EINVAL: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid.
        ENOPROTOOPT: The option is unknown at the level indicated.
        ENOTSOCK: The argument `socket` is not a socket.

    #### C Function
    ```c
    int getsockopt(int sockfd, int level, int optname, void optval[restrict *.optlen], socklen_t *restrict optlen);
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockopt.3p.html .
    """
    var option_value = stack_allocation[1, c_void]()
    var option_len: socklen_t = size_of[Int]()
    var result = _getsockopt(socket, level, option_name, option_value, Pointer(to=option_len))
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("getsockopt: The argument `socket` is not a valid descriptor.")
        elif errno == EFAULT:
            raise Error("getsockopt: The argument `option_value` points outside the process's allocated address space.")
        elif errno == EINVAL:
            raise Error(
                "getsockopt: The argument `option_len` is invalid. Can sometimes occur when `option_value` is invalid."
            )
        elif errno == ENOPROTOOPT:
            raise Error("getsockopt: The option is unknown at the level indicated.")
        elif errno == ENOTSOCK:
            raise Error("getsockopt: The argument `socket` is not a socket.")
        else:
            raise Error("getsockopt: An error occurred while setting the socket option. Error code: " + String(errno))

    return option_value.bitcast[Int]().take_pointee()


fn _getsockname[
    origin: Origin
](socket: c_int, address: LegacyUnsafePointer[sockaddr], address_len: Pointer[socklen_t, origin],) -> c_int:
    """Libc POSIX `getsockname` function.

    Args:
        socket: A File Descriptor.
        address: A LegacyUnsafePointer to a buffer to store the address of the peer.
        address_len: A LegacyUnsafePointer to the size of the buffer.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int getsockname(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getsockname.3p.html .
    """
    return external_call[
        "getsockname",
        c_int,  # FnName, RetType
        c_int,
        LegacyUnsafePointer[sockaddr],
        Pointer[socklen_t, origin],  # Args
    ](socket, address, address_len)


fn getsockname[
    origin: Origin
](socket: c_int, address: LegacyUnsafePointer[sockaddr], address_len: Pointer[socklen_t, origin],) raises:
    """Libc POSIX `getsockname` function.

    Args:
        socket: A File Descriptor.
        address: A LegacyUnsafePointer to a buffer to store the address of the peer.
        address_len: A LegacyUnsafePointer to the size of the buffer.

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
    var result = _getsockname(socket, address, address_len)
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("getsockname: The argument `socket` is not a valid descriptor.")
        elif errno == EFAULT:
            raise Error(
                "getsockname: The `address` argument points to memory not in a valid part of the process address space."
            )
        elif errno == EINVAL:
            raise Error("getsockname: `address_len` is invalid (e.g., is negative).")
        elif errno == ENOBUFS:
            raise Error("getsockname: Insufficient resources were available in the system to perform the operation.")
        elif errno == ENOTSOCK:
            raise Error("getsockname: The argument `socket` is not a socket, it is a file.")
        else:
            raise Error("getsockname: An error occurred while getting the socket name. Error code: " + String(errno))


fn _getpeername[
    origin: Origin
](sockfd: c_int, addr: LegacyUnsafePointer[sockaddr], address_len: Pointer[socklen_t, origin],) -> c_int:
    """Libc POSIX `getpeername` function.

    Args:
        sockfd: A File Descriptor.
        addr: A LegacyUnsafePointer to a buffer to store the address of the peer.
        address_len: A LegacyUnsafePointer to the size of the buffer.

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
        c_int,
        LegacyUnsafePointer[sockaddr],
        Pointer[socklen_t, origin],  # Args
    ](sockfd, addr, address_len)


fn getpeername(file_descriptor: c_int) raises -> sockaddr_in:
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
    var remote_address = stack_allocation[1, sockaddr]()
    var result = _getpeername(file_descriptor, remote_address, Pointer(to=socklen_t(size_of[sockaddr]())))
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("getpeername: The argument `socket` is not a valid descriptor.")
        elif errno == EFAULT:
            raise Error(
                "getpeername: The `addr` argument points to memory not in a valid part of the process address space."
            )
        elif errno == EINVAL:
            raise Error("getpeername: `address_len` is invalid (e.g., is negative).")
        elif errno == ENOBUFS:
            raise Error("getpeername: Insufficient resources were available in the system to perform the operation.")
        elif errno == ENOTCONN:
            raise Error("getpeername: The socket is not connected.")
        elif errno == ENOTSOCK:
            raise Error("getpeername: The argument `socket` is not a socket, it is a file.")
        else:
            raise Error("getpeername: An error occurred while getting the socket name. Error code: " + String(errno))

    # Cast sockaddr struct to sockaddr_in
    return remote_address.bitcast[sockaddr_in]().take_pointee()


fn _bind[
    origin: ImmutOrigin
](socket: c_int, address: Pointer[sockaddr_in, origin], address_len: socklen_t) -> c_int:
    """Libc POSIX `bind` function. Assigns the address specified by `address` to the socket referred to by
       the file descriptor `socket`.

    Args:
        socket: A File Descriptor.
        address: A LegacyUnsafePointer to the address to bind to.
        address_len: The size of the address.

    Returns:
        0 on success, -1 on error.

    #### C Function
    ```c
    int bind(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/bind.3p.html .
    """
    return external_call["bind", c_int, c_int, Pointer[sockaddr_in, origin], socklen_t](socket, address, address_len)


fn bind(socket: c_int, address: sockaddr_in) raises:
    """Libc POSIX `bind` function.

    Args:
        socket: A File Descriptor.
        address: A LegacyUnsafePointer to the address to bind to.

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
    var result = _bind(socket, Pointer(to=address), size_of[sockaddr_in]())
    if result == -1:
        var errno = get_errno()
        if errno == EACCES:
            raise Error("bind: The address, `address`, is protected, and the user is not the superuser.")
        elif errno == EADDRINUSE:
            raise Error("bind: The given address is already in use.")
        elif errno == EBADF:
            raise Error("bind: `socket` is not a valid descriptor.")
        elif errno == EINVAL:
            raise Error("bind: The socket is already bound to an address.")
        elif errno == ENOTSOCK:
            raise Error("bind: `socket` is a descriptor for a file, not a socket.")

        # The following errors are specific to UNIX domain (AF_UNIX) sockets. TODO: Pass address_family when unix sockets supported.
        # if address_family == AF_UNIX:
        #     if errno == EACCES:
        #         raise Error("bind: Search permission is denied on a component of the path prefix. (See also path_resolution(7).)")
        #     elif errno == EADDRNOTAVAIL:
        #         raise Error("bind: A nonexistent interface was requested or the requested address was not local.")
        #     elif errno == EFAULT:
        #         raise Error("bind: `address` points outside the user's accessible address space.")
        #     elif errno == EINVAL:
        #         raise Error("bind: The `address_len` is wrong, or the socket was not in the AF_UNIX family.")
        #     elif errno == ELOOP:
        #         raise Error("bind: Too many symbolic links were encountered in resolving addr.")
        #     elif errno == ENAMETOOLONG:
        #         raise Error("bind: `address` is too long.")
        #     elif errno == ENOENT:
        #         raise Error("bind: The file does not exist.")
        #     elif errno == ENOMEM:
        #         raise Error("bind: Insufficient kernel memory was available.")
        #     elif errno == ENOTDIR:
        #         raise Error("bind: A component of the path prefix is not a directory.")
        #     elif errno == EROFS:
        #         raise Error("bind: The socket inode would reside on a read-only file system.")

        raise Error("bind: An error occurred while binding the socket. Error code: " + String(errno))


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
    * Reference: https://man7.org/linux/man-pages/man3/listen.3p.html .
    """
    return external_call["listen", c_int, c_int, c_int](socket, backlog)


fn listen(socket: c_int, backlog: c_int) raises:
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
    var result = _listen(socket, backlog)
    if result == -1:
        var errno = get_errno()
        if errno == EADDRINUSE:
            raise Error("listen: Another socket is already listening on the same port.")
        elif errno == EBADF:
            raise Error("listen: `socket` is not a valid descriptor.")
        elif errno == ENOTSOCK:
            raise Error("listen: `socket` is a descriptor for a file, not a socket.")
        elif errno == EOPNOTSUPP:
            raise Error("listen: The socket is not of a type that supports the `listen()` operation.")
        else:
            raise Error("listen: An error occurred while listening on the socket. Error code: " + String(errno))


fn _accept[
    address_origin: MutOrigin, len_origin: Origin
](socket: c_int, address: Pointer[sockaddr, address_origin], address_len: Pointer[socklen_t, len_origin],) -> c_int:
    """Libc POSIX `accept` function.

    Args:
        socket: A File Descriptor.
        address: A LegacyUnsafePointer to a buffer to store the address of the peer.
        address_len: A LegacyUnsafePointer to the size of the buffer.

    Returns:
        A File Descriptor or -1 in case of failure.

    #### C Function
    ```c
    int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/accept.3p.html .
    """
    return external_call[
        "accept", c_int, c_int, Pointer[sockaddr, address_origin], Pointer[socklen_t, len_origin]  # FnName, RetType
    ](socket, address, address_len)


fn accept(socket: c_int) raises -> c_int:
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
    var result = _accept(socket, Pointer(to=remote_address), Pointer(to=socklen_t(size_of[socklen_t]())))
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error(
                "accept: The socket is marked nonblocking and no connections are present to be accepted. POSIX.1-2001"
                " allows either error to be returned for this case, and does not require these constants to have the"
                " same value, so a portable application should check for both possibilities.."
            )
        elif errno == EBADF:
            raise Error("accept: `socket` is not a valid descriptor.")
        elif errno == ECONNABORTED:
            raise Error("accept: `socket` is not a valid descriptor.")
        elif errno == EFAULT:
            raise Error("accept: The `address` argument is not in a writable part of the user address space.")
        elif errno == EINTR:
            raise Error(
                "accept: The system call was interrupted by a signal that was caught before a valid connection arrived;"
                " see `signal(7)`."
            )
        elif errno == EINVAL:
            raise Error(
                "accept: Socket is not listening for connections, or `addr_length` is invalid (e.g., is negative)."
            )
        elif errno == EMFILE:
            raise Error("accept: The per-process limit of open file descriptors has been reached.")
        elif errno == ENFILE:
            raise Error("accept: The system limit on the total number of open files has been reached.")
        elif Int(errno) in [ENOBUFS, ENOMEM]:
            raise Error(
                "accept: Not enough free memory. This often means that the memory allocation is limited by the socket"
                " buffer limits, not by the system memory."
            )
        elif errno == ENOTSOCK:
            raise Error("accept: `socket` is a descriptor for a file, not a socket.")
        elif errno == EOPNOTSUPP:
            raise Error("accept: The referenced socket is not of type `SOCK_STREAM`.")
        elif errno == EPROTO:
            raise Error("accept: Protocol error.")

        @parameter
        if CompilationTarget.is_linux():
            if errno == EPERM:
                raise Error("accept: Firewall rules forbid connection.")
        raise Error("accept: An error occurred while listening on the socket. Error code: " + String(errno))

    return result


fn _connect[
    origin: ImmutOrigin
](socket: c_int, address: Pointer[sockaddr_in, origin], address_len: socklen_t) -> c_int:
    """Libc POSIX `connect` function.

    Args: socket: A File Descriptor.
        address: A LegacyUnsafePointer to the address to connect to.
        address_len: The size of the address.
    Returns: 0 on success, -1 on error.

    #### C Function
    ```c
    int connect(int socket, const struct sockaddr *address, socklen_t address_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/connect.3p.html .
    """
    return external_call["connect", c_int](socket, address, address_len)


fn connect(socket: c_int, address: sockaddr_in) raises:
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
    var result = _connect(socket, Pointer(to=address), size_of[sockaddr_in]())
    if result == -1:
        var errno = get_errno()
        if errno == EACCES:
            raise Error(
                "connect: For UNIX domain sockets, which are identified by pathname: Write permission is denied on the"
                " socket file, or search permission is denied for one of the directories in the path prefix. (See also"
                " path_resolution(7))."
            )
        elif errno == EADDRINUSE:
            raise Error("connect: Local address is already in use.")
        elif errno == EAGAIN:
            raise Error("connect: No more free local ports or insufficient entries in the routing cache.")
        elif errno == EALREADY:
            raise Error(
                "connect: The socket is nonblocking and a previous connection attempt has not yet been completed."
            )
        elif errno == EBADF:
            raise Error("connect: The file descriptor is not a valid index in the descriptor table.")
        elif errno == ECONNREFUSED:
            raise Error("connect: No-one listening on the remote address.")
        elif errno == EFAULT:
            raise Error("connect: The socket structure address is outside the user's address space.")
        elif errno == EINPROGRESS:
            raise Error(
                "connect: The socket is nonblocking and the connection cannot be completed immediately. It is possible"
                " to select(2) or poll(2) for completion by selecting the socket for writing. After select(2) indicates"
                " writability, use getsockopt(2) to read the SO_ERROR option at level SOL_SOCKET to determine whether"
                " connect() completed successfully (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual"
                " error codes listed here, explaining the reason for the failure)."
            )
        elif errno == EINTR:
            raise Error("connect: The system call was interrupted by a signal that was caught.")
        elif errno == EISCONN:
            raise Error("connect: The socket is already connected.")
        elif errno == ENETUNREACH:
            raise Error("connect: Network is unreachable.")
        elif errno == ENOTSOCK:
            raise Error("connect: The file descriptor is not associated with a socket.")
        elif errno == EAFNOSUPPORT:
            raise Error("connect: The passed address didn't have the correct address family in its `sa_family` field.")
        elif errno == ETIMEDOUT:
            raise Error(
                "connect: Timeout while attempting connection. The server may be too busy to accept new connections."
            )
        else:
            raise Error("connect: An error occurred while connecting to the socket. Error code: " + String(errno))


fn _recv(
    socket: c_int,
    buffer: LegacyUnsafePointer[UInt8],
    length: c_size_t,
    flags: c_int,
) -> c_ssize_t:
    """Libc POSIX `recv` function.

    Args:
        socket: A File Descriptor.
        buffer: A LegacyUnsafePointer to the buffer to store the received data.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes received or -1 in case of failure.

    #### C Function
    ```c
    ssize_t recv(int socket, void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recv.3p.html .
    """
    return external_call[
        "recv",
        c_ssize_t,  # FnName, RetType
        c_int,
        LegacyUnsafePointer[UInt8],
        c_size_t,
        c_int,  # Args
    ](socket, buffer, length, flags)


fn recv(
    socket: c_int,
    buffer: LegacyUnsafePointer[UInt8],
    length: c_size_t,
    flags: c_int,
) raises -> c_size_t:
    """Libc POSIX `recv` function.

    Args:
        socket: A File Descriptor.
        buffer: A LegacyUnsafePointer to the buffer to store the received data.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes received.

    #### C Function
    ```c
    ssize_t recv(int socket, void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/recv.3p.html .
    """
    var result = _recv(socket, buffer, length, flags)
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error(
                "ReceiveError: The socket is marked nonblocking and the receive operation would block, or a receive"
                " timeout had been set and the timeout expired before data was received."
            )
        elif errno == EBADF:
            raise Error("ReceiveError: The argument `socket` is an invalid descriptor.")
        elif errno == ECONNREFUSED:
            raise Error(
                "ReceiveError: The remote host refused to allow the network connection (typically because it is not"
                " running the requested service)."
            )
        elif errno == EFAULT:
            raise Error("ReceiveError: `buffer` points outside the process's address space.")
        elif errno == EINTR:
            raise Error(
                "ReceiveError: The receive was interrupted by delivery of a signal before any data were available."
            )
        elif errno == ENOTCONN:
            raise Error("ReceiveError: The socket is not connected.")
        elif errno == ENOTSOCK:
            raise Error("ReceiveError: The file descriptor is not associated with a socket.")
        else:
            raise Error(
                "ReceiveError: An error occurred while attempting to receive data from the socket. Error code: "
                + String(errno)
            )

    return UInt(result)


fn _recvfrom[
    origin: Origin
](
    socket: c_int,
    buffer: LegacyUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
    address: LegacyUnsafePointer[sockaddr],
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
        c_int,
        LegacyUnsafePointer[c_void],
        c_size_t,
        c_int,
        LegacyUnsafePointer[sockaddr],
        Pointer[socklen_t, origin],
    ](socket, buffer, length, flags, address, address_len)


fn recvfrom(
    socket: c_int,
    buffer: LegacyUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
    address: LegacyUnsafePointer[sockaddr],
) raises -> c_size_t:
    """Libc POSIX `recvfrom` function.

    Args:
        socket: Specifies the socket file descriptor.
        buffer: Points to the buffer where the message should be stored.
        length: Specifies the length in bytes of the buffer pointed to by the buffer argument.
        flags: Specifies the type of message reception.
        address: A null pointer, or points to a sockaddr structure in which the sending address is to be stored.

    Returns:
        The number of bytes received.

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
    var result = _recvfrom(socket, buffer, length, flags, address, Pointer[socklen_t](to=size_of[sockaddr]()))
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise "ReceiveError: The socket's file descriptor is marked `O_NONBLOCK` and no data is waiting to be received; or MSG_OOB is set and no out-of-band data is available and either the socket's file descriptor is marked `O_NONBLOCK` or the socket does not support blocking to await out-of-band data."
        elif errno == EBADF:
            raise "ReceiveError: The socket argument is not a valid file descriptor."
        elif errno == ECONNRESET:
            raise "ReceiveError: A connection was forcibly closed by a peer."
        elif errno == EINTR:
            raise "ReceiveError: A signal interrupted `recvfrom()` before any data was available."
        elif errno == EINVAL:
            raise "ReceiveError: The `MSG_OOB` flag is set and no out-of-band data is available."
        elif errno == ENOTCONN:
            raise "ReceiveError: A receive is attempted on a connection-mode socket that is not connected."
        elif errno == ENOTSOCK:
            raise "ReceiveError: The socket argument does not refer to a socket."
        elif errno == EOPNOTSUPP:
            raise "ReceiveError: The specified flags are not supported for this socket type."
        elif errno == ETIMEDOUT:
            raise "ReceiveError: The connection timed out during connection establishment, or due to a transmission timeout on active connection."
        elif errno == EIO:
            raise "ReceiveError: An I/O error occurred while reading from or writing to the file system."
        elif errno == ENOBUFS:
            raise "ReceiveError: Insufficient resources were available in the system to perform the operation."
        elif errno == ENOMEM:
            raise "ReceiveError: Insufficient memory was available to fulfill the request."
        else:
            raise Error("ReceiveError: An error occurred while attempting to receive data from the socket. Error code: " + String(
                errno
            ))

    return UInt(result)


fn _send(socket: c_int, buffer: LegacyUnsafePointer[c_void, mut=False], length: c_size_t, flags: c_int) -> c_ssize_t:
    """Libc POSIX `send` function.

    Args:
        socket: A File Descriptor.
        buffer: A LegacyUnsafePointer to the buffer to send.
        length: The size of the buffer.
        flags: Flags to control the behaviour of the function.

    Returns:
        The number of bytes sent or -1 in case of failure.

    #### C Function
    ```c
    ssize_t send(int socket, const void *buffer, size_t length, int flags)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/send.3p.html .
    """
    return external_call["send", c_ssize_t](socket, buffer, length, flags)


fn send(socket: c_int, buffer: LegacyUnsafePointer[c_void, mut=False], length: c_size_t, flags: c_int) raises -> c_size_t:
    """Libc POSIX `send` function.

    Args:
        socket: A File Descriptor.
        buffer: A LegacyUnsafePointer to the buffer to send.
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
    var result = _send(socket, buffer, length, flags)
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error(
                "SendError: The socket is marked nonblocking and the receive operation would block, or a receive"
                " timeout had been set and the timeout expired before data was received."
            )
        elif errno == EBADF:
            raise Error("SendError: The argument `socket` is an invalid descriptor.")
        elif errno == EAGAIN:
            raise Error("SendError: No more free local ports or insufficient entries in the routing cache.")
        elif errno == ECONNRESET:
            raise Error("SendError: Connection reset by peer.")
        elif errno == EDESTADDRREQ:
            raise Error("SendError: The socket is not connection-mode, and no peer address is set.")
        elif errno == ECONNREFUSED:
            raise Error(
                "SendError: The remote host refused to allow the network connection (typically because it is not"
                " running the requested service)."
            )
        elif errno == EFAULT:
            raise Error("SendError: `buffer` points outside the process's address space.")
        elif errno == EINTR:
            raise Error(
                "SendError: The receive was interrupted by delivery of a signal before any data were available."
            )
        elif errno == EINVAL:
            raise Error("SendError: Invalid argument passed.")
        elif errno == EISCONN:
            raise Error("SendError: The connection-mode socket was connected already but a recipient was specified.")
        elif errno == EMSGSIZE:
            raise Error(
                "SendError: The socket type requires that message be sent atomically, and the size of the message to be"
                " sent made this impossible.."
            )
        elif errno == ENOBUFS:
            raise Error(
                "SendError: The output queue for a network interface was full. This generally indicates that the"
                " interface has stopped sending, but may be caused by transient congestion."
            )
        elif errno == ENOMEM:
            raise Error("SendError: No memory available.")
        elif errno == ENOTCONN:
            raise Error("SendError: The socket is not connected.")
        elif errno == ENOTSOCK:
            raise Error("SendError: The file descriptor is not associated with a socket.")
        elif errno == EOPNOTSUPP:
            raise Error("SendError: Some bit in the flags argument is inappropriate for the socket type.")
        elif errno == EPIPE:
            raise Error(
                "SendError: The local end has been shut down on a connection oriented socket. In this case the process"
                " will also receive a SIGPIPE unless MSG_NOSIGNAL is set."
            )
        else:
            raise Error(
                "SendError: An error occurred while attempting to receive data from the socket. Error code: "
                + String(errno)
            )

    return UInt(result)


fn _sendto(
    socket: c_int,
    message: LegacyUnsafePointer[c_void, mut=False],
    length: c_size_t,
    flags: c_int,
    dest_addr: LegacyUnsafePointer[sockaddr, mut=False],
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
    * Reference: https://man7.org/linux/man-pages/man3/sendto.3p.html .
    * Valid Flags:
        * `MSG_EOR`: Terminates a record (if supported by the protocol).
        * `MSG_OOB`: Sends out-of-band data on sockets that support out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_NOSIGNAL`: Requests not to send the SIGPIPE signal if an attempt to send is made on a stream-oriented socket that is no longer connected. The [EPIPE] error shall still be returned.
    """
    return external_call[
        "sendto",
        c_ssize_t,
        c_int,
        LegacyUnsafePointer[c_void, mut=False],
        c_size_t,
        c_int,
        LegacyUnsafePointer[sockaddr, mut=False],
        socklen_t,
    ](socket, message, length, flags, dest_addr, dest_len)


fn sendto(
    socket: c_int,
    message: LegacyUnsafePointer[c_void],
    length: c_size_t,
    flags: c_int,
    dest_addr: LegacyUnsafePointer[sockaddr],
) raises -> c_size_t:
    """Libc POSIX `sendto` function.

    Args:
        socket: Specifies the socket file descriptor.
        message: Points to a buffer containing the message to be sent.
        length: Specifies the size of the message in bytes.
        flags: Specifies the type of message transmission.
        dest_addr: Points to a sockaddr structure containing the destination address.

    Raises:
        Error: If an error occurs while attempting to send data to the socket.
        EAFNOSUPPORT: Addresses in the specified address family cannot be used with this socket.
        EAGAIN or EWOULDBLOCK: The socket's file descriptor is marked `O_NONBLOCK` and the requested operation would block.
        EBADF: The socket argument is not a valid file descriptor.
        ECONNRESET: A connection was forcibly closed by a peer.
        EINTR: A signal interrupted `sendto()` before any data was transmitted.
        EMSGSIZE: The message is too large to be sent all at once, as the socket requires.
        ENOTCONN: The socket is connection-mode but is not connected.
        ENOTSOCK: The socket argument does not refer to a socket.
        EPIPE: The socket is shut down for writing, or the socket is connection-mode and is no longer connected.
        EACCES: Search permission is denied for a component of the path prefix; or write access to the named socket is denied.
        EDESTADDRREQ: The socket is not connection-mode and does not have its peer address set, and no destination address was specified.
        EHOSTUNREACH: The destination host cannot be reached (probably because the host is down or a remote router cannot reach it).
        EINVAL: The `dest_len` argument is not a valid length for the address family.
        EIO: An I/O error occurred while reading from or writing to the file system.
        ENETDOWN: The local network interface used to reach the destination is down.
        ENETUNREACH: No route to the network is present.
        ENOBUFS: Insufficient resources were available in the system to perform the operation.
        ENOMEM: Insufficient memory was available to fulfill the request.
        ELOOP: More than `SYMLOOP_MAX` symbolic links were encountered during resolution of the pathname in the socket address.
        ENAMETOOLONG: The length of a pathname exceeds `PATH_MAX`, or pathname resolution of a symbolic link produced an intermediate result with a length that exceeds `PATH_MAX`.

    #### C Function
    ```c
    ssize_t sendto(int socket, const void *message, size_t length,
    int flags, const struct sockaddr *dest_addr,
    socklen_t dest_len)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/sendto.3p.html .
    * Valid Flags:
        * `MSG_EOR`: Terminates a record (if supported by the protocol).
        * `MSG_OOB`: Sends out-of-band data on sockets that support out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        * `MSG_NOSIGNAL`: Requests not to send the SIGPIPE signal if an attempt to send is made on a stream-oriented socket that is no longer connected. The [EPIPE] error shall still be returned.

    """
    var result = _sendto(socket, message, length, flags, dest_addr, size_of[sockaddr]())
    if result == -1:
        var errno = get_errno()
        if errno == EAFNOSUPPORT:
            raise "SendToError (EAFNOSUPPORT): Addresses in the specified address family cannot be used with this socket."
        elif Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise "SendToError (EAGAIN/EWOULDBLOCK): The socket's file descriptor is marked `O_NONBLOCK` and the requested operation would block."
        elif errno == EBADF:
            raise "SendToError (EBADF): The socket argument is not a valid file descriptor."
        elif errno == ECONNRESET:
            raise "SendToError (ECONNRESET): A connection was forcibly closed by a peer."
        elif errno == EINTR:
            raise "SendToError (EINTR): A signal interrupted `sendto()` before any data was transmitted."
        elif errno == EMSGSIZE:
            raise "SendToError (EMSGSIZE): The message is too large to be sent all at once, as the socket requires."
        elif errno == ENOTCONN:
            raise "SendToError (ENOTCONN): The socket is connection-mode but is not connected."
        elif errno == ENOTSOCK:
            raise "SendToError (ENOTSOCK): The socket argument does not refer to a socket."
        elif errno == EPIPE:
            raise "SendToError (EPIPE): The socket is shut down for writing, or the socket is connection-mode and is no longer connected."
        elif errno == EACCES:
            raise "SendToError (EACCES): Search permission is denied for a component of the path prefix; or write access to the named socket is denied."
        elif errno == EDESTADDRREQ:
            raise "SendToError (EDESTADDRREQ): The socket is not connection-mode and does not have its peer address set, and no destination address was specified."
        elif errno == EHOSTUNREACH:
            raise "SendToError (EHOSTUNREACH): The destination host cannot be reached (probably because the host is down or a remote router cannot reach it)."
        elif errno == EINVAL:
            raise "SendToError (EINVAL): The dest_len argument is not a valid length for the address family."
        elif errno == EIO:
            raise "SendToError (EIO): An I/O error occurred while reading from or writing to the file system."
        elif errno == EISCONN:
            raise "SendToError (EISCONN): A destination address was specified and the socket is already connected."
        elif errno == ENETDOWN:
            raise "SendToError (ENETDOWN): The local network interface used to reach the destination is down."
        elif errno == ENETUNREACH:
            raise "SendToError (ENETUNREACH): No route to the network is present."
        elif errno == ENOBUFS:
            raise "SendToError (ENOBUFS): Insufficient resources were available in the system to perform the operation."
        elif errno == ENOMEM:
            raise "SendToError (ENOMEM): Insufficient memory was available to fulfill the request."
        elif errno == ELOOP:
            raise "SendToError (ELOOP): More than `SYMLOOP_MAX` symbolic links were encountered during resolution of the pathname in the socket address."
        elif errno == ENAMETOOLONG:
            raise "SendToError (ENAMETOOLONG): The length of a pathname exceeds `PATH_MAX`, or pathname resolution of a symbolic link produced an intermediate result with a length that exceeds `PATH_MAX`."
        else:
            raise Error("SendToError: An error occurred while attempting to send data to the socket. Error code: " + String(
                errno
            ))

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
    return external_call["shutdown", c_int, c_int, c_int](socket, how)


alias ShutdownInvalidDescriptorError = "ShutdownError (EBADF): The argument `socket` is an invalid descriptor."
alias ShutdownInvalidArgumentError = "ShutdownError (EINVAL): Invalid argument passed."
alias ShutdownNotConnectedError = "ShutdownError (ENOTCONN): The socket is not connected."
alias ShutdownNotSocketError = "ShutdownError (ENOTSOCK): The file descriptor is not associated with a socket."


fn shutdown(socket: c_int, how: c_int) raises:
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
    var result = _shutdown(socket, how)
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise ShutdownInvalidDescriptorError
        elif errno == EINVAL:
            raise ShutdownInvalidArgumentError
        elif errno == ENOTCONN:
            raise ShutdownNotConnectedError
        elif errno == ENOTSOCK:
            raise ShutdownNotSocketError
        else:
            raise Error(
                "ShutdownError: An error occurred while attempting to receive data from the socket. Error code: "
                + String(errno)
            )


fn gai_strerror(ecode: c_int) -> UnsafePointer[mut=True, c_char, MutAnyOrigin]:
    """Libc POSIX `gai_strerror` function.

    Args:
        ecode: The error code.

    Returns:
        An UnsafePointer to a string describing the error.

    #### C Function
    ```c
    const char *gai_strerror(int ecode)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/gai_strerror.3p.html .
    """
    return external_call["gai_strerror", UnsafePointer[mut=True, c_char, MutAnyOrigin], c_int](ecode)


# --- ( File Related Syscalls & Structs )---------------------------------------
alias O_NONBLOCK = 16384
alias O_ACCMODE = 3
alias O_CLOEXEC = 524288


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
    * Reference: https://man7.org/linux/man-pages/man3/close.3p.html .
    """
    return external_call["close", c_int, c_int](fildes)


alias CloseInvalidDescriptorError = "CloseError (EBADF): The file_descriptor argument is not a valid open file descriptor."
alias CloseInterruptedError = "CloseError (EINTR): The close() function was interrupted by a signal."
alias CloseRWError = "CloseError (EIO): An I/O error occurred while reading from or writing to the file system."
alias CloseOutOfSpaceError = "CloseError (ENOSPC or EDQUOT): On NFS, these errors are not normally reported against the first write which exceeds the available storage space, but instead against a subsequent write(2), fsync(2), or close()."


fn close(file_descriptor: c_int) raises:
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
    if _close(file_descriptor) == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise CloseInvalidDescriptorError
        elif errno == EINTR:
            raise CloseInterruptedError
        elif errno == EIO:
            raise CloseRWError
        elif Int(errno) in [ENOSPC, EDQUOT]:
            raise CloseOutOfSpaceError
        else:
            raise Error("SocketError: An error occurred while creating the socket. Error code: " + String(errno))


fn get_errno() -> c_int:
    """Get a copy of the current value of the `errno` global variable for
    the current thread.

    Returns:
        A copy of the current value of `errno` for the current thread.
    """

    @parameter
    if CompilationTarget.is_linux():
        return external_call["__errno_location", LegacyUnsafePointer[c_int]]()[]
    elif CompilationTarget.is_macos():
        return external_call["__error", LegacyUnsafePointer[c_int]]()[]
    else:
        var errno = stack_allocation[1, c_int]()
        _ = external_call["_get_errno", c_void](errno)
        return errno[]
