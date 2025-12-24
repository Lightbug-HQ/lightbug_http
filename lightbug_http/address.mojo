from sys.ffi import CompilationTarget, c_char, c_int, c_uchar, external_call

from lightbug_http.c.address import AddressFamily, AddressLength
from lightbug_http.c.aliases import ExternalImmutUnsafePointer, ExternalMutUnsafePointer, c_void
from lightbug_http.c.network import in_addr_t, inet_ntop, ntohs, sockaddr, sockaddr_in, socklen_t
from lightbug_http.c.socket import SocketType, socket
from lightbug_http.socket import Socket


comptime MAX_PORT = 65535
comptime MIN_PORT = 0
comptime DEFAULT_IP_PORT = UInt16(0)


struct AddressConstants:
    """Constants used in address parsing."""

    comptime LOCALHOST = "localhost"
    comptime IPV4_LOCALHOST = "127.0.0.1"
    comptime IPV6_LOCALHOST = "::1"
    comptime EMPTY = ""


trait Addr(
    Copyable,
    Defaultable,
    Equatable,
    ImplicitlyCopyable,
    Representable,
    Stringable,
    Writable,
):
    comptime _type: StaticString

    fn __init__(out self, ip: String, port: UInt16):
        ...

    @always_inline
    fn address_family(self) -> Int:
        ...

    @always_inline
    fn is_v4(self) -> Bool:
        ...

    @always_inline
    fn is_v6(self) -> Bool:
        ...

    @always_inline
    fn is_unix(self) -> Bool:
        ...


trait AnAddrInfo(Copyable):
    fn has_next(self) -> Bool:
        ...

    fn next(self) -> ExternalMutUnsafePointer[Self]:
        ...


@fieldwise_init
struct NetworkType(Equatable, ImplicitlyCopyable):
    var value: UInt8

    comptime empty = Self(0)
    comptime tcp = Self(1)
    comptime tcp4 = Self(2)
    comptime tcp6 = Self(3)
    comptime udp = Self(4)
    comptime udp4 = Self(5)
    comptime udp6 = Self(6)
    comptime ip = Self(7)
    comptime ip4 = Self(8)
    comptime ip6 = Self(9)
    comptime unix = Self(10)

    comptime SUPPORTED_TYPES = [
        Self.tcp,
        Self.tcp4,
        Self.tcp6,
        Self.udp,
        Self.udp4,
        Self.udp6,
        Self.ip,
        Self.ip4,
        Self.ip6,
    ]
    comptime TCP_TYPES = [
        Self.tcp,
        Self.tcp4,
        Self.tcp6,
    ]
    comptime UDP_TYPES = [
        Self.udp,
        Self.udp4,
        Self.udp6,
    ]
    comptime IP_TYPES = [
        Self.ip,
        Self.ip4,
        Self.ip6,
    ]

    fn __eq__(self, other: NetworkType) -> Bool:
        return self.value == other.value

    fn is_ip_protocol(self) -> Bool:
        """Check if the network type is an IP protocol."""
        return self in (NetworkType.ip, NetworkType.ip4, NetworkType.ip6)

    fn is_ipv4(self) -> Bool:
        """Check if the network type is IPv4."""
        return self in (NetworkType.tcp4, NetworkType.udp4, NetworkType.ip4)

    fn is_ipv6(self) -> Bool:
        """Check if the network type is IPv6."""
        return self in (NetworkType.tcp6, NetworkType.udp6, NetworkType.ip6)


# @fieldwise_init
struct TCPAddr[network: NetworkType = NetworkType.tcp4](Addr, ImplicitlyCopyable):
    comptime _type = "TCPAddr"
    var ip: String
    var port: UInt16
    var zone: String  # IPv6 addressing zone

    fn __init__(out self):
        self.ip = "127.0.0.1"
        self.port = 8000
        self.zone = ""

    fn __init__(out self, ip: String = "127.0.0.1", port: UInt16 = 8000):
        self.ip = ip
        self.port = port
        self.zone = ""

    fn __init__(out self, ip: String, port: UInt16, zone: String):
        self.ip = ip
        self.port = port
        self.zone = zone

    @always_inline
    fn address_family(self) -> Int:
        if Self.network == NetworkType.tcp4:
            return Int(AddressFamily.AF_INET.value)
        elif Self.network == NetworkType.tcp6:
            return Int(AddressFamily.AF_INET6.value)
        else:
            return Int(AddressFamily.AF_UNSPEC.value)

    @always_inline
    fn is_v4(self) -> Bool:
        return Self.network == NetworkType.tcp4

    @always_inline
    fn is_v6(self) -> Bool:
        return Self.network == NetworkType.tcp6

    @always_inline
    fn is_unix(self) -> Bool:
        return False

    fn __eq__(self, other: Self) -> Bool:
        return self.ip == other.ip and self.port == other.port and self.zone == other.zone

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(self.ip + "%" + self.zone, String(self.port))
        return join_host_port(self.ip, String(self.port))

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(
            "TCPAddr(",
            "ip=",
            repr(self.ip),
            ", port=",
            String(self.port),
            ", zone=",
            repr(self.zone),
            ")",
        )


@fieldwise_init
struct UDPAddr[network: NetworkType = NetworkType.udp4](Addr, ImplicitlyCopyable):
    comptime _type = "UDPAddr"
    var ip: String
    var port: UInt16
    var zone: String  # IPv6 addressing zone

    fn __init__(out self):
        self.ip = "127.0.0.1"
        self.port = 8000
        self.zone = ""

    fn __init__(out self, ip: String = "127.0.0.1", port: UInt16 = 8000):
        self.ip = ip
        self.port = port
        self.zone = ""

    @always_inline
    fn address_family(self) -> Int:
        if Self.network == NetworkType.udp4:
            return Int(AddressFamily.AF_INET.value)
        elif Self.network == NetworkType.udp6:
            return Int(AddressFamily.AF_INET6.value)
        else:
            return Int(AddressFamily.AF_UNSPEC.value)

    @always_inline
    fn is_v4(self) -> Bool:
        return Self.network == NetworkType.udp4

    @always_inline
    fn is_v6(self) -> Bool:
        return Self.network == NetworkType.udp6

    @always_inline
    fn is_unix(self) -> Bool:
        return False

    fn __eq__(self, other: Self) -> Bool:
        return self.ip == other.ip and self.port == other.port and self.zone == other.zone

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(self.ip + "%" + self.zone, String(self.port))
        return join_host_port(self.ip, String(self.port))

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(
            "UDPAddr(",
            "ip=",
            repr(self.ip),
            ", port=",
            String(self.port),
            ", zone=",
            repr(self.zone),
            ")",
        )


@fieldwise_init
@register_passable("trivial")
struct addrinfo_macos(AnAddrInfo):
    """
    For MacOS, I had to swap the order of ai_canonname and ai_addr.
    https://stackoverflow.com/questions/53575101/calling-getaddrinfo-directly-from-python-ai-addr-is-null-pointer.
    """

    var ai_flags: c_int
    var ai_family: c_int
    var ai_socktype: c_int
    var ai_protocol: c_int
    var ai_addrlen: socklen_t
    var ai_canonname: ExternalMutUnsafePointer[c_char]
    var ai_addr: ExternalMutUnsafePointer[sockaddr]
    var ai_next: ExternalMutUnsafePointer[addrinfo_macos]

    fn __init__(
        out self,
        ai_flags: c_int = 0,
        ai_family: AddressFamily = AddressFamily.AF_UNSPEC,
        ai_socktype: SocketType = SocketType.SOCK_STREAM,
        ai_protocol: AddressFamily = AddressFamily.AF_UNSPEC,
        ai_addrlen: socklen_t = 0,
    ):
        self.ai_flags = ai_flags
        self.ai_family = ai_family.value
        self.ai_socktype = ai_socktype.value
        self.ai_protocol = 0
        self.ai_addrlen = ai_addrlen
        self.ai_canonname = {}
        self.ai_addr = {}
        self.ai_next = {}

    fn has_next(self) -> Bool:
        return Bool(self.ai_next)

    fn next(self) -> ExternalMutUnsafePointer[Self]:
        return self.ai_next


@fieldwise_init
@register_passable("trivial")
struct addrinfo_unix(AnAddrInfo):
    """Standard addrinfo struct for Unix systems.
    Overwrites the existing libc `getaddrinfo` function to adhere to the AnAddrInfo trait.
    """

    var ai_flags: c_int
    var ai_family: c_int
    var ai_socktype: c_int
    var ai_protocol: c_int
    var ai_addrlen: socklen_t
    var ai_addr: ExternalMutUnsafePointer[sockaddr]
    var ai_canonname: ExternalMutUnsafePointer[c_char]
    var ai_next: ExternalMutUnsafePointer[addrinfo_unix]

    fn __init__(
        out self,
        ai_flags: c_int = 0,
        ai_family: AddressFamily = AddressFamily.AF_UNSPEC,
        ai_socktype: SocketType = SocketType.SOCK_STREAM,
        ai_protocol: AddressFamily = AddressFamily.AF_UNSPEC,
        ai_addrlen: socklen_t = 0,
    ):
        self.ai_flags = ai_flags
        self.ai_family = ai_family.value
        self.ai_socktype = ai_socktype.value
        self.ai_protocol = ai_protocol.value
        self.ai_addrlen = ai_addrlen
        self.ai_addr = {}
        self.ai_canonname = {}
        self.ai_next = {}

    fn has_next(self) -> Bool:
        return Bool(self.ai_addr)

    fn next(self) -> ExternalMutUnsafePointer[Self]:
        return self.ai_next


fn get_ip_address(mut host: String, address_family: AddressFamily, sock_type: SocketType) raises -> in_addr_t:
    """Returns an IP address based on the host.
    This is a Unix-specific implementation.

    Args:
        host: The host to get IP from.
        address_family: The address family to use.
        sock_type: The socket type to use.

    Returns:
        The IP address.
    """

    @parameter
    if CompilationTarget.is_macos():
        var result: CAddrInfo[addrinfo_macos]
        var hints = addrinfo_macos(
            ai_flags=0,
            ai_family=address_family,
            ai_socktype=sock_type,
            ai_protocol=address_family,
        )
        var service = String()
        try:
            result = getaddrinfo(host, service, hints)
        except e:
            raise e^

        if not result.unsafe_ptr()[].ai_addr:
            raise Error("Failed to get IP address because the response's `ai_addr` was null.")

        # extend result's lifetime to avoid invalid access of pointer, it'd get freed early
        return (
            result.unsafe_ptr()[]
            .ai_addr.bitcast[sockaddr_in]()
            .unsafe_origin_cast[origin_of(result)]()[]
            .sin_addr.s_addr
        )
    else:
        var result: CAddrInfo[addrinfo_unix]
        var hints = addrinfo_unix(
            ai_flags=0,
            ai_family=address_family,
            ai_socktype=sock_type,
            ai_protocol=address_family,
        )
        var service = String()
        try:
            result = getaddrinfo(host, service, hints)
        except e:
            raise e^

        if not result.unsafe_ptr()[].ai_addr:
            raise Error("Failed to get IP address because the response's `ai_addr` was null.")

        return (
            result.unsafe_ptr()[]
            .ai_addr.bitcast[sockaddr_in]()
            .unsafe_origin_cast[origin_of(result)]()[]
            .sin_addr.s_addr
        )


fn is_ip_protocol(network: NetworkType) -> Bool:
    """Check if the network type is an IP protocol."""
    return network in (NetworkType.ip, NetworkType.ip4, NetworkType.ip6)


fn is_ipv4(network: NetworkType) -> Bool:
    """Check if the network type is IPv4."""
    return network in (NetworkType.tcp4, NetworkType.udp4, NetworkType.ip4)


fn is_ipv6(network: NetworkType) -> Bool:
    """Check if the network type is IPv6."""
    return network in (NetworkType.tcp6, NetworkType.udp6, NetworkType.ip6)


struct ParseError(Stringable, Writable):
    var message: String

    fn __init__(out self, var message: String):
        self.message = message^

    fn write_to[W: Writer, //](self, mut writer: W) -> None:
        writer.write(self.message)

    fn __str__(self) -> String:
        return self.message.copy()


comptime TooManyColonsError = ParseError("too many colons in address")


fn parse_ipv6_bracketed_address[
    origin: ImmutOrigin
](address: StringSlice[origin]) raises ParseError -> Tuple[StringSlice[origin], UInt16]:
    """Parse an IPv6 address enclosed in brackets.

    Returns:
        Tuple of (host, colon_index_offset).
    """
    if address[0] != "[":
        return address, UInt16(0)

    var end_bracket_index = address.find("]")
    if end_bracket_index == -1:
        raise ParseError("Failed to parse ipv6 address: missing ']'")

    if end_bracket_index + 1 == len(address):
        raise ParseError("Failed to parse ipv6 address: missing port in address")

    var colon_index = end_bracket_index + 1
    if address[colon_index] != ":":
        raise ParseError("Failed to parse ipv6 address: missing port in address")

    return address[1:end_bracket_index], UInt16(end_bracket_index + 1)


fn validate_no_brackets[
    origin: ImmutOrigin
](address: StringSlice[origin], start_idx: UInt16, end_idx: Optional[UInt16] = None,) raises ParseError:
    """Validate that the address segment contains no brackets."""
    var segment: StringSlice[origin]

    if end_idx is None:
        segment = address[Int(start_idx) :]
    else:
        segment = address[Int(start_idx) : Int(end_idx.value())]

    if segment.find("[") != -1:
        raise ParseError("Address failed bracket validation, unexpectedly contained '['")
    if segment.find("]") != -1:
        raise ParseError("Address failed bracket validation, unexpectedly contained ']'")


fn parse_port[origin: ImmutOrigin](port_str: StringSlice[origin]) raises ParseError -> UInt16:
    """Parse and validate port number."""
    if port_str == AddressConstants.EMPTY:
        raise ParseError("Failed to parse port: port string is empty.")

    var port: Int
    try:
        port = Int(String(port_str))
    except e:
        raise ParseError(
            String(
                "Failed to parse port: invalid integer value. Received: ",
                port_str,
            )
        )

    if port < MIN_PORT or port > MAX_PORT:
        raise ParseError(
            String(
                "Failed to parse port: Port number out of range (0-65535). Received: ",
                port_str,
            )
        )

    return UInt16(port)


@fieldwise_init
struct HostPort(Movable):
    var host: String
    var port: UInt16


fn parse_address[
    origin: ImmutOrigin,
    //,
    network: NetworkType,
](address: StringSlice[origin]) raises ParseError -> HostPort:
    """Parse an address string into a host and port.

    Parameters:
        origin: The origin of the address string.
        network: The network type.

    Args:
        address: The address string.

    Returns:
        Tuple containing the host and port.
    """
    if address == AddressConstants.EMPTY:
        raise ParseError("Failed to parse address: received empty address string.")

    if address == AddressConstants.LOCALHOST:

        @parameter
        if network.is_ipv4():
            return HostPort(AddressConstants.IPV4_LOCALHOST, DEFAULT_IP_PORT)
        elif network.is_ipv6():
            return HostPort(AddressConstants.IPV6_LOCALHOST, DEFAULT_IP_PORT)

    @parameter
    if network.is_ip_protocol():
        if network == NetworkType.ip6 and address.find(":") != -1:
            return HostPort(String(address), DEFAULT_IP_PORT)

        if address.find(":") != -1:
            raise ParseError("IP protocol addresses should not include ports")

        return HostPort(String(address), DEFAULT_IP_PORT)

    var colon_index = address.rfind(":")
    if colon_index == -1:
        raise ParseError("Failed to parse address: missing port separator ':' in address.")

    var host: StringSlice[origin]
    var port: UInt16

    if address[0] == "[":
        var bracket_offset: UInt16
        (host, bracket_offset) = parse_ipv6_bracketed_address(address)
        validate_no_brackets(address, bracket_offset)
    else:
        host = address[:colon_index]
        if host.find(":") != -1:
            raise ParseError("Failed to parse address: too many colons in address")

    port = parse_port(address[colon_index + 1 :])
    if host == AddressConstants.LOCALHOST:

        @parameter
        if network.is_ipv4():
            return HostPort(AddressConstants.IPV4_LOCALHOST, port)
        elif network.is_ipv6():
            return HostPort(AddressConstants.IPV6_LOCALHOST, port)

    return HostPort(String(host), port)


# TODO: Support IPv6 long form.
fn join_host_port(host: String, port: String) -> String:
    if host.find(":") != -1:  # must be IPv6 literal
        return String("[", host, "]:", port)
    return String(host, ":", port)


fn binary_port_to_int(port: UInt16) -> Int:
    """Convert a binary port to an integer.

    Args:
        port: The binary port.

    Returns:
        The port as an integer.
    """
    return Int(ntohs(port))


fn binary_ip_to_string[address_family: AddressFamily](ip_address: UInt32) raises -> String:
    """Convert a binary IP address to a string by calling `inet_ntop`.

    Parameters:
        address_family: The address family of the IP address.

    Args:
        ip_address: The binary IP address.

    Returns:
        The IP address as a string.
    """

    @parameter
    if address_family == AddressFamily.AF_INET:
        return inet_ntop[address_family, AddressLength.INET_ADDRSTRLEN](ip_address)
    else:
        return inet_ntop[address_family, AddressLength.INET6_ADDRSTRLEN](ip_address)


fn freeaddrinfo[T: AnAddrInfo, //](ptr: ExternalMutUnsafePointer[T]):
    """Free the memory allocated by `getaddrinfo`."""
    external_call["freeaddrinfo", NoneType, type_of(ptr)](ptr)


@fieldwise_init
struct _CAddrInfoIterator[
    mut: Bool,
    //,
    T: AnAddrInfo,
    origin: Origin[mut],
](ImplicitlyCopyable, Iterable, Iterator):
    """Iterator for List.

    Parameters:
        mut: Whether the reference to the list is mutable.
        T: The type of the elements in the list.
        origin: The origin of the List
    """

    comptime Element = Self.T  # FIXME(MOCO-2068): shouldn't be needed.

    comptime IteratorType[iterable_mut: Bool, //, iterable_origin: Origin[iterable_mut]]: Iterator = Self

    var index: Int
    var src: Pointer[CAddrInfo[Self.T], Self.origin]

    @always_inline
    fn __iter__(ref self) -> Self.IteratorType[origin_of(self)]:
        return self.copy()

    fn __has_next__(self) -> Bool:
        """Checks if there are more elements in the iterator.

        Returns:
            True if there are more elements, False otherwise.
        """
        if not self.src[].ptr:
            return False

        return self.src[].ptr[].has_next()

    fn __next__(mut self) -> Self.Element:
        """Returns the next element from the iterator.

        Returns:
            The next element.
        """
        var current = self.src[].ptr
        for _ in range(self.index):
            current = current[].next()
        self.index += 1

        return current[].copy()


@fieldwise_init
struct CAddrInfo[T: AnAddrInfo](Iterable):
    """A wrapper around an ExternalMutUnsafePointer to an addrinfo struct.

    This struct will call `freeaddrinfo` when it is deinitialized to free the memory allocated
    by `getaddrinfo`. Make sure to use the data method to access the underlying pointer, so Mojo
    knows that there's a reference to the pointer. If you access ptr directly, Mojo might destroy
    the struct and free the pointer while you're still using it.
    """

    comptime IteratorType[iterable_mut: Bool, //, iterable_origin: Origin[iterable_mut]]: Iterator = _CAddrInfoIterator[
        Self.T, iterable_origin
    ]
    var ptr: ExternalMutUnsafePointer[Self.T]

    fn unsafe_ptr[
        origin: Origin, address_space: AddressSpace, //
    ](ref [origin, address_space]self) -> UnsafePointer[Self.T, origin, address_space=address_space]:
        """Retrieves a pointer to the underlying memory.

        Parameters:
            origin: The origin of the `CAddrInfo`.
            address_space: The `AddressSpace` of the `CAddrInfo`.

        Returns:
            The pointer to the underlying memory.
        """
        return self.ptr.unsafe_mut_cast[origin.mut]().unsafe_origin_cast[origin]().address_space_cast[address_space]()

    fn __del__(deinit self):
        if self.ptr:
            print("Freeing addrinfo memory...")
            freeaddrinfo(self.ptr)

    fn __iter__(ref self) -> Self.IteratorType[origin_of(self)]:
        """Iterate over elements of the list, returning immutable references.

        Returns:
            An iterator of immutable references to the list elements.
        """
        return {0, Pointer(to=self)}


fn gai_strerror(ecode: c_int) -> ExternalImmutUnsafePointer[c_char]:
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
    return external_call["gai_strerror", ExternalImmutUnsafePointer[c_char], type_of(ecode)](ecode)


fn _getaddrinfo[
    T: AnAddrInfo,
    node_origin: ImmutOrigin,
    serv_origin: ImmutOrigin,
    hints_origin: ImmutOrigin,
    result_origin: MutOrigin,
    //,
](
    nodename: ImmutUnsafePointer[c_char, node_origin],
    servname: ImmutUnsafePointer[c_char, serv_origin],
    hints: Pointer[T, hints_origin],
    res: Pointer[ExternalMutUnsafePointer[T], result_origin],
) -> c_int:
    """Libc POSIX `getaddrinfo` function.

    Args:
        nodename: The node name.
        servname: The service name.
        hints: A Pointer to the hints.
        res: A Pointer to an UnsafePointer the result.

    Returns:
        0 on success, an error code on failure.

    #### C Function
    ```c
    int getaddrinfo(const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getaddrinfo.3p.html
    """
    return external_call[
        "getaddrinfo",
        c_int,
        type_of(nodename),
        type_of(servname),
        type_of(hints),
        type_of(res),
    ](nodename, servname, hints, res)


fn getaddrinfo[T: AnAddrInfo, //](mut node: String, mut service: String, hints: T) raises -> CAddrInfo[T]:
    """Libc POSIX `getaddrinfo` function.

    Args:
        node: The node name.
        service: The service name.
        hints: An addrinfo struct containing hints for the lookup.

    Raises:
        Error: If an error occurs while attempting to receive data from the socket.
        * EAI_AGAIN: The name could not be resolved at this time. Future attempts may succeed.
        * EAI_BADFLAGS: The `ai_flags` value was invalid.
        * EAI_FAIL: A non-recoverable error occurred when attempting to resolve the name.
        * EAI_FAMILY: The `ai_family` member of the `hints` argument is not supported.
        * EAI_MEMORY: Out of memory.
        * EAI_NONAME: The name does not resolve for the supplied parameters.
        * EAI_SERVICE: The `servname` is not supported for `ai_socktype`.
        * EAI_SOCKTYPE: The `ai_socktype` is not supported.
        * EAI_SYSTEM: A system error occurred. `errno` is set in this case.

    #### C Function
    ```c
    int getaddrinfo(const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getaddrinfo.3p.html.
    """
    var ptr = ExternalMutUnsafePointer[T]()
    var result = _getaddrinfo(
        node.as_c_string_slice().unsafe_ptr(),
        service.as_c_string_slice().unsafe_ptr(),
        Pointer(to=hints),
        Pointer(to=ptr),
    )

    if result != 0:
        raise Error(
            "getaddrinfo: ",
            StringSlice(unsafe_from_utf8_ptr=gai_strerror(result)),
        )

    # CAddrInfo will be responsible for freeing the memory allocated by getaddrinfo.
    return CAddrInfo[T](ptr=ptr)
