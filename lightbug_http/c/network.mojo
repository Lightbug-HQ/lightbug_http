from sys.ffi import c_char, c_int, c_uint, c_ushort, external_call, get_errno

from lightbug_http.c.address import AddressFamily, AddressLength
from lightbug_http.c.aliases import ExternalImmutUnsafePointer, ExternalMutUnsafePointer, c_void
from memory import stack_allocation
from utils import StaticTuple


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
    return external_call["htonl", c_uint, type_of(hostlong)](hostlong)


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
    return external_call["htons", c_ushort, type_of(hostshort)](hostshort)


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
    return external_call["ntohl", c_uint, type_of(netlong)](netlong)


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
    return external_call["ntohs", c_ushort, type_of(netshort)](netshort)


comptime sa_family_t = c_ushort
"""Address family type."""
comptime socklen_t = c_uint
"""Used to represent the length of socket addresses and other related data structures in bytes."""
comptime in_addr_t = c_uint
"""Used to represent IPv4 Internet addresses."""
comptime in_port_t = c_ushort
"""Used to represent port numbers."""


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
    var ai_addr: ExternalMutUnsafePointer[sockaddr]
    var ai_canonname: ExternalMutUnsafePointer[c_char]
    var ai_next: ExternalMutUnsafePointer[c_void]

    fn __init__(out self):
        self.ai_flags = 0
        self.ai_family = 0
        self.ai_socktype = 0
        self.ai_protocol = 0
        self.ai_addrlen = 0
        self.ai_addr = ExternalMutUnsafePointer[sockaddr]()
        self.ai_canonname = ExternalMutUnsafePointer[c_char]()
        self.ai_next = ExternalMutUnsafePointer[c_void]()


fn _inet_ntop(
    af: c_int,
    src: ImmutUnsafePointer[c_void],
    dst: MutUnsafePointer[c_char],
    size: socklen_t,
) raises -> ExternalImmutUnsafePointer[c_char]:
    """Libc POSIX `inet_ntop` function.

    Args:
        af: Address Family see AF_ aliases.
        src: A UnsafePointer to a binary address.
        dst: A UnsafePointer to a buffer to store the result.
        size: The size of the buffer.

    Returns:
        A UnsafePointer to the buffer containing the result.

    #### C Function
    ```c
    const char *inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/inet_ntop.3p.html .
    """
    return external_call[
        "inet_ntop",
        ExternalImmutUnsafePointer[c_char],  # FnName, RetType
        type_of(af),
        type_of(src),
        type_of(dst),
        type_of(size),  # Args
    ](af, src, dst, size)


fn inet_ntop[
    address_family: AddressFamily where address_family.is_inet(), address_length: AddressLength
](ip_address: UInt32) raises -> String:
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
    var dst = List[Byte](capacity=address_length.value + 1)

    # `inet_ntop` returns NULL on error.
    if not _inet_ntop(
        address_family.value,
        UnsafePointer(to=ip_address).bitcast[c_void](),
        dst.unsafe_ptr().bitcast[c_char](),
        address_length.value,
    ):
        var errno = get_errno()
        if errno == errno.EAFNOSUPPORT:
            raise Error("inet_ntop Error: `*src` was not an `AF_INET` or `AF_INET6` family address.")
        elif errno == errno.ENOSPC:
            raise Error(
                "inet_ntop Error: The buffer size, `size`, was not large enough to store the presentation form of the"
                " address."
            )
        else:
            raise Error("inet_ntop Error: An error occurred while converting the address. Error code: ", errno)

    # Copy the dst contents into a new String.
    return String(bytes=Span(dst))


fn _inet_pton(af: c_int, src: ImmutUnsafePointer[c_char], dst: MutUnsafePointer[c_void]) -> c_int:
    """Libc POSIX `inet_pton` function. Converts a presentation format address (that is, printable form as held in a character string)
    to network format (usually a struct in_addr or some other internal binary representation, in network byte order).
    It returns 1 if the address was valid for the specified address family, or 0 if the address was not parseable in the specified address family,
    or -1 if some system error occurred (in which case errno will have been set).

    Args:
        af: Address Family: `AF_INET` or `AF_INET6`.
        src: A UnsafePointer to a string containing the address.
        dst: A UnsafePointer to a buffer to store the result.

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
        type_of(af),
        type_of(src),
        type_of(dst),
    ](af, src, dst)


fn inet_pton[address_family: AddressFamily where address_family.is_inet()](var src: String) raises -> c_uint:
    """Libc POSIX `inet_pton` function. Converts a presentation format address (that is, printable form as held in a character string)
    to network format (usually a struct in_addr or some other internal binary representation, in network byte order).

    Parameters:
        address_family: Address Family: `AF_INET` or `AF_INET6`.

    Args:
        src: A UnsafePointer to a string containing the address.

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
    var ip_buffer: ExternalMutUnsafePointer[c_void]

    @parameter
    if address_family == AddressFamily.AF_INET6:
        ip_buffer = stack_allocation[16, c_void]()
    else:
        ip_buffer = stack_allocation[4, c_void]()

    var result = _inet_pton(address_family.value, src.as_c_string_slice().unsafe_ptr(), ip_buffer)
    if result == 0:
        raise Error("inet_pton Error: The input is not a valid address.")
    elif result == -1:
        var errno = get_errno()
        raise Error("inet_pton Error: An error occurred while converting the address. Error code: ", errno)

    return ip_buffer.bitcast[c_uint]().take_pointee()
