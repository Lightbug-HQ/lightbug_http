from memory import UnsafePointer
from sys.ffi import external_call, OpaquePointer
from lightbug_http.strings import NetworkType, to_string
from lightbug_http._libc import (
    c_int,
    c_char,
    in_addr,
    sockaddr,
    sockaddr_in,
    socklen_t,
    AF_INET,
    AF_INET6,
    AF_UNSPEC,
    SOCK_STREAM,
    ntohs,
    inet_ntop,
    socket,
    gai_strerror,
    INET_ADDRSTRLEN,
    INET6_ADDRSTRLEN,
)
from lightbug_http._logger import logger
from lightbug_http.socket import Socket

alias MAX_PORT = 65535
alias MIN_PORT = 0
alias DEFAULT_IP_PORT = UInt16(0)

struct AddressConstants:
    """Constants used in address parsing."""
    alias LOCALHOST = "localhost"
    alias IPV4_LOCALHOST = "127.0.0.1"
    alias IPV6_LOCALHOST = "::1"
    alias EMPTY = ""

trait Addr(Stringable, Representable, Writable, EqualityComparableCollectionElement):
    alias _type: StringLiteral

    fn __init__(out self):
        ...

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


trait AnAddrInfo:
    fn get_ip_address(self, host: String) raises -> in_addr:
        """TODO: Once default functions can be implemented in traits, this should use the functions currently
        implemented in the `addrinfo_macos` and `addrinfo_unix` structs.
        """
        ...

@value
struct TCPAddr[network: NetworkType = NetworkType.tcp4](Addr):
    alias _type = "TCPAddr"
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

    fn __init__(out self, network: NetworkType, ip: String, port: UInt16, zone: String = ""):
        self.ip = ip
        self.port = port
        self.zone = zone
    
    @always_inline
    fn address_family(self) -> Int:
        if network == NetworkType.tcp4:
            return AF_INET
        elif network == NetworkType.tcp6:
            return AF_INET6
        else:
            return AF_UNSPEC
    
    @always_inline
    fn is_v4(self) -> Bool:
        return network == NetworkType.tcp4
    
    @always_inline
    fn is_v6(self) -> Bool:
        return network == NetworkType.tcp6
    
    @always_inline
    fn is_unix(self) -> Bool:
        return False

    fn __eq__(self, other: Self) -> Bool:
        return self.ip == other.ip and self.port == other.port and self.zone == other.zone

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(self.ip + "%" + self.zone, str(self.port))
        return join_host_port(self.ip, str(self.port))

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("TCPAddr(", "ip=", repr(self.ip), ", port=", str(self.port), ", zone=", repr(self.zone), ")")


@value
struct UDPAddr[network: NetworkType = NetworkType.udp4](Addr):
    alias _type = "UDPAddr"
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

    fn __init__(out self, network: NetworkType, ip: String, port: UInt16):
        self.ip = ip
        self.port = port
        self.zone = ""
    
    @always_inline
    fn address_family(self) -> Int:
        if network == NetworkType.udp4:
            return AF_INET
        elif network == NetworkType.udp6:
            return AF_INET6
        else:
            return AF_UNSPEC
    
    @always_inline
    fn is_v4(self) -> Bool:
        return network == NetworkType.udp4
    
    @always_inline
    fn is_v6(self) -> Bool:
        return network == NetworkType.udp6
    
    @always_inline
    fn is_unix(self) -> Bool:
        return False

    fn __eq__(self, other: Self) -> Bool:
        return self.ip == other.ip and self.port == other.port and self.zone == other.zone

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(self.ip + "%" + self.zone, str(self.port))
        return join_host_port(self.ip, str(self.port))

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("UDPAddr(", "ip=", repr(self.ip), ", port=", str(self.port), ", zone=", repr(self.zone), ")")

@value
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
    var ai_canonname: UnsafePointer[c_char]
    var ai_addr: UnsafePointer[sockaddr]
    var ai_next: OpaquePointer

    fn __init__(
        out self,
        ai_flags: c_int = 0,
        ai_family: c_int = 0,
        ai_socktype: c_int = 0,
        ai_protocol: c_int = 0,
        ai_addrlen: socklen_t = 0,
    ):
        self.ai_flags = ai_flags
        self.ai_family = ai_family
        self.ai_socktype = ai_socktype
        self.ai_protocol = ai_protocol
        self.ai_addrlen = ai_addrlen
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_next = OpaquePointer()

    fn get_ip_address(self, host: String) raises -> in_addr:
        """Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            The IP address.
        """
        var result = UnsafePointer[Self]()
        var hints = Self(ai_flags=0, ai_family=AF_INET, ai_socktype=SOCK_STREAM, ai_protocol=0)
        try:
            getaddrinfo(host, String(), hints, result)
        except e:
            logger.error("Failed to get IP address.")
            raise e

        if not result[].ai_addr:
            freeaddrinfo(result)
            raise Error("Failed to get IP address because the response's `ai_addr` was null.")

        var ip = result[].ai_addr.bitcast[sockaddr_in]()[].sin_addr
        freeaddrinfo(result)
        return ip


@value
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
    var ai_addr: UnsafePointer[sockaddr]
    var ai_canonname: UnsafePointer[c_char]
    var ai_next: OpaquePointer

    fn __init__(
        out self,
        ai_flags: c_int = 0,
        ai_family: c_int = 0,
        ai_socktype: c_int = 0,
        ai_protocol: c_int = 0,
        ai_addrlen: socklen_t = 0,
    ):
        self.ai_flags = ai_flags
        self.ai_family = ai_family
        self.ai_socktype = ai_socktype
        self.ai_protocol = ai_protocol
        self.ai_addrlen = ai_addrlen
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_next = OpaquePointer()

    fn get_ip_address(self, host: String) raises -> in_addr:
        """Returns an IP address based on the host.
        This is a Unix-specific implementation.

        Args:
            host: String - The host to get IP from.

        Returns:
            The IP address.
        """
        var result = UnsafePointer[Self]()
        var hints = Self(ai_flags=0, ai_family=AF_INET, ai_socktype=SOCK_STREAM, ai_protocol=0)
        try:
            getaddrinfo(host, String(), hints, result)
        except e:
            logger.error("Failed to get IP address.")
            raise e

        if not result[].ai_addr:
            freeaddrinfo(result)
            raise Error("Failed to get IP address because the response's `ai_addr` was null.")

        var ip = result[].ai_addr.bitcast[sockaddr_in]()[].sin_addr
        freeaddrinfo(result)
        return ip

fn is_ip_protocol(network: NetworkType) -> Bool:
    """Check if the network type is an IP protocol."""
    return network in (NetworkType.ip, NetworkType.ip4, NetworkType.ip6)

fn is_ipv4(network: NetworkType) -> Bool:
    """Check if the network type is IPv4."""
    return network in (NetworkType.tcp4, NetworkType.udp4, NetworkType.ip4)

fn is_ipv6(network: NetworkType) -> Bool:
    """Check if the network type is IPv6."""
    return network in (NetworkType.tcp6, NetworkType.udp6, NetworkType.ip6)

fn resolve_localhost(host: String, network: NetworkType) -> String:
    """Resolve localhost to the appropriate IP address based on network type."""
    if host != AddressConstants.LOCALHOST:
        return host
        
    if is_ipv4(network):
        return AddressConstants.IPV4_LOCALHOST
    elif is_ipv6(network):
        return AddressConstants.IPV6_LOCALHOST
    return host

fn parse_ipv6_bracketed_address(address: String) raises -> (String, Int):
    """Parse an IPv6 address enclosed in brackets.
    
    Returns:
        Tuple of (host, colon_index_offset)
    """
    if address[0] != "[":
        return address, 0
        
    var end_bracket_index = address.find("]")
    if end_bracket_index == -1:
        raise Error("missing ']' in address")
        
    if end_bracket_index + 1 == len(address):
        raise MissingPortError
        
    var colon_index = end_bracket_index + 1
    if address[colon_index] != ":":
        raise MissingPortError
        
    return (
        address[1:end_bracket_index],
        end_bracket_index + 1
    )

fn validate_no_brackets(address: String, start_idx: Int, end_idx: Int = -1) raises:
    """Validate that the address segment contains no brackets."""
    if address[start_idx:end_idx].find("[") != -1:
        raise Error("unexpected '[' in address")
    if address[start_idx:end_idx].find("]") != -1:
        raise Error("unexpected ']' in address")

fn parse_port(port_str: String) raises -> UInt16:
    """Parse and validate port number."""
    if port_str == AddressConstants.EMPTY:
        raise MissingPortError
        
    var port = int(port_str)
    if port < MIN_PORT or port > MAX_PORT:
        raise Error("Port number out of range (0-65535)")
        
    return UInt16(port)

fn parse_address(network: NetworkType, address: String) raises -> (String, UInt16):
    """Parse an address string into a host and port.

    Args:
        network: The network type (tcp, tcp4, tcp6, udp, udp4, udp6, ip, ip4, ip6, unix)
        address: The address string

    Returns:
        Tuple containing the host and port
    """
    if is_ip_protocol(network):
        var host = resolve_localhost(address, network)
        if host == AddressConstants.EMPTY:
            raise Error("missing host")
            
        # For IPv6 addresses in IP protocol mode, we need to handle the address as-is
        if network == NetworkType.ip6 and host.find(":") != -1:
            return host, DEFAULT_IP_PORT
            
        # For other IP protocols, no colons allowed
        if host.find(":") != -1:
            raise Error("IP protocol addresses should not include ports")
            
        return host, DEFAULT_IP_PORT

    var colon_index = address.rfind(":")
    if colon_index == -1:
        raise MissingPortError

    var host: String
    var bracket_offset: Int = 0

    # Handle IPv6 addresses
    if address[0] == "[":
        try:
            (host, bracket_offset) = parse_ipv6_bracketed_address(address)
        except e:
            raise e
        
        validate_no_brackets(address, bracket_offset)
    else:
        # For IPv4, simply split at the last colon
        host = address[:colon_index]
        if host.find(":") != -1:
            raise TooManyColonsError

    var port = parse_port(address[colon_index + 1:])

    host = resolve_localhost(host, network)
    if host == AddressConstants.EMPTY:
        raise Error("missing host")

    return host, port


# TODO: Support IPv6 long form.
fn join_host_port(host: String, port: String) -> String:
    if host.find(":") != -1:  # must be IPv6 literal
        return "[" + host + "]:" + port
    return host + ":" + port


alias MissingPortError = Error("missing port in address")
alias TooManyColonsError = Error("too many colons in address")

fn binary_port_to_int(port: UInt16) -> Int:
    """Convert a binary port to an integer.

    Args:
        port: The binary port.

    Returns:
        The port as an integer.
    """
    return int(ntohs(port))


fn binary_ip_to_string[address_family: Int32](owned ip_address: UInt32) raises -> String:
    """Convert a binary IP address to a string by calling `inet_ntop`.

    Parameters:
        address_family: The address family of the IP address.

    Args:
        ip_address: The binary IP address.

    Returns:
        The IP address as a string.
    """
    constrained[int(address_family) in [AF_INET, AF_INET6], "Address family must be either AF_INET or AF_INET6."]()
    var ip: String

    @parameter
    if address_family == AF_INET:
        ip = inet_ntop[address_family, INET_ADDRSTRLEN](ip_address)
    else:
        ip = inet_ntop[address_family, INET6_ADDRSTRLEN](ip_address)

    return ip


fn _getaddrinfo[
    T: AnAddrInfo, hints_origin: MutableOrigin, result_origin: MutableOrigin, //
](
    nodename: UnsafePointer[c_char],
    servname: UnsafePointer[c_char],
    hints: Pointer[T, hints_origin],
    res: Pointer[UnsafePointer[T], result_origin],
) -> c_int:
    """Libc POSIX `getaddrinfo` function.

    Args:
        nodename: The node name.
        servname: The service name.
        hints: A Pointer to the hints.
        res: A UnsafePointer to the result.

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
        c_int,  # FnName, RetType
        UnsafePointer[c_char],
        UnsafePointer[c_char],
        Pointer[T, hints_origin],  # Args
        Pointer[UnsafePointer[T], result_origin],  # Args
    ](nodename, servname, hints, res)


fn getaddrinfo[
    T: AnAddrInfo, //
](node: String, service: String, mut hints: T, mut res: UnsafePointer[T],) raises:
    """Libc POSIX `getaddrinfo` function.

    Args:
        node: The node name.
        service: The service name.
        hints: A Pointer to the hints.
        res: A UnsafePointer to the result.

    Raises:
        Error: If an error occurs while attempting to receive data from the socket.
        EAI_AGAIN: The name could not be resolved at this time. Future attempts may succeed.
        EAI_BADFLAGS: The `ai_flags` value was invalid.
        EAI_FAIL: A non-recoverable error occurred when attempting to resolve the name.
        EAI_FAMILY: The `ai_family` member of the `hints` argument is not supported.
        EAI_MEMORY: Out of memory.
        EAI_NONAME: The name does not resolve for the supplied parameters.
        EAI_SERVICE: The `servname` is not supported for `ai_socktype`.
        EAI_SOCKTYPE: The `ai_socktype` is not supported.
        EAI_SYSTEM: A system error occurred. `errno` is set in this case.

    #### C Function
    ```c
    int getaddrinfo(const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getaddrinfo.3p.html
    """
    var result = _getaddrinfo(
        node.unsafe_ptr(), service.unsafe_ptr(), Pointer.address_of(hints), Pointer.address_of(res)
    )
    if result != 0:
        # gai_strerror returns a char buffer that we don't know the length of.
        # TODO: Perhaps switch to writing bytes once the Writer trait allows writing individual bytes.
        var err = gai_strerror(result)
        var msg = List[Byte, True]()
        var i = 0
        while err[i] != 0:
            msg.append(err[i])
            i += 1
        msg.append(0)
        raise Error("getaddrinfo: " + String(msg^))


fn freeaddrinfo[T: AnAddrInfo, //](ptr: UnsafePointer[T]):
    """Free the memory allocated by `getaddrinfo`."""
    external_call["freeaddrinfo", NoneType, UnsafePointer[T]](ptr)
