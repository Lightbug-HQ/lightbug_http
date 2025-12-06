from sys.ffi import c_int

from lightbug_http.c.aliases import ExternalImmutUnsafePointer, ExternalMutUnsafePointer, c_void


@fieldwise_init
@register_passable("trivial")
struct ShutdownOption(Copyable, Equatable, Stringable, Writable):
    var value: c_int
    comptime AI_PASSIVE = Self(1)
    comptime AI_CANONNAME = Self(2)
    comptime AI_NUMERICHOST = Self(4)
    comptime AI_V4MAPPED = Self(8)
    comptime AI_ALL = Self(16)
    comptime AI_ADDRCONFIG = Self(32)
    comptime AI_IDN = Self(64)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `ShutdownOption` instances for equality.

        Args:
            other: The other `ShutdownOption` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes the `ShutdownOption` to a writer.

        Params:
            W: The type of the writer.

        Args:
            writer: The writer to write to.
        """
        if self == Self.AI_PASSIVE:
            writer.write("AI_PASSIVE")
        elif self == Self.AI_CANONNAME:
            writer.write("AI_CANONNAME")
        elif self == Self.AI_NUMERICHOST:
            writer.write("AI_NUMERICHOST")
        elif self == Self.AI_V4MAPPED:
            writer.write("AI_V4MAPPED")
        elif self == Self.AI_ALL:
            writer.write("AI_ALL")
        elif self == Self.AI_ADDRCONFIG:
            writer.write("AI_ADDRCONFIG")
        elif self == Self.AI_IDN:
            writer.write("AI_IDN")
        else:
            writer.write("ShutdownOption(", self.value, ")")

    fn __str__(self) -> String:
        """Converts the `ShutdownOption` to a string.

        Returns:
            The string representation of the `ShutdownOption`.
        """
        return String.write(self)


# TODO: These might vary on each platform...we should confirm this.
# Taken from: https://github.com/openbsd/src/blob/master/sys/sys/socket.h#L250
@fieldwise_init
@register_passable("trivial")
struct AddressFamily(Copyable, Equatable, Stringable, Writable):
    """Address families, used to specify the type of addresses that your socket can communicate with."""

    var value: c_int
    """Address family value."""
    comptime AF_UNSPEC = Self(0)
    """unspecified"""
    comptime AF_UNIX = Self(1)
    """local to host"""
    comptime AF_LOCAL = Self.AF_UNIX
    """draft POSIX compatibility"""
    comptime AF_INET = Self(2)
    """internetwork: UDP, TCP, etc."""
    comptime AF_IMPLINK = Self(3)
    """arpanet imp addresses"""
    comptime AF_PUP = Self(4)
    """pup protocols: e.g. BSP"""
    comptime AF_CHAOS = Self(5)
    """mit CHAOS protocols"""
    comptime AF_NS = Self(6)
    """XEROX NS protocols"""
    comptime AF_ISO = Self(7)
    """ISO protocols"""
    comptime AF_OSI = Self.AF_ISO
    comptime AF_ECMA = Self(8)
    """european computer manufacturers"""
    comptime AF_DATAKIT = Self(9)
    """datakit protocols"""
    comptime AF_CCITT = Self(10)
    """CCITT protocols, X.25 etc"""
    comptime AF_SNA = Self(11)
    """IBM SNA"""
    comptime AF_DECnet = Self(12)
    """DECnet"""
    comptime AF_DLI = Self(13)
    """DEC Direct data link interface"""
    comptime AF_LAT = Self(14)
    """LAT"""
    comptime AF_HYLINK = Self(15)
    """NSC Hyperchannel"""
    comptime AF_APPLETALK = Self(16)
    """Apple Talk"""
    comptime AF_ROUTE = Self(17)
    """Internal Routing Protocol"""
    comptime AF_LINK = Self(18)
    """Link layer interface"""
    comptime pseudo_AF_XTP = Self(19)
    """eXpress Transfer Protocol (no AF)"""
    comptime AF_COIP = Self(20)
    """connection-oriented IP, aka ST II"""
    comptime AF_CNT = Self(21)
    """Computer Network Technology"""
    comptime pseudo_AF_RTIP = Self(22)
    """Help Identify RTIP packets"""
    comptime AF_IPX = Self(23)
    """Novell Internet Protocol"""
    comptime AF_INET6 = Self(24)
    """IPv6"""
    comptime pseudo_AF_PIP = Self(25)
    """Help Identify PIP packets"""
    comptime AF_ISDN = Self(26)
    """Integrated Services Digital Network"""
    comptime AF_E164 = Self.AF_ISDN
    """CCITT E.164 recommendation"""
    comptime AF_NATM = Self(27)
    """native ATM access"""
    comptime AF_ENCAP = Self(28)
    comptime AF_SIP = Self(29)
    """Simple Internet Protocol"""
    comptime AF_KEY = Self(30)
    comptime pseudo_AF_HDRCMPLT = Self(31)
    """Used by BPF to not rewrite headers in interface output routine"""
    comptime AF_BLUETOOTH = Self(32)
    """Bluetooth"""
    comptime AF_MPLS = Self(33)
    """MPLS"""
    comptime pseudo_AF_PFLOW = Self(34)
    """pflow"""
    comptime pseudo_AF_PIPEX = Self(35)
    """PIPEX"""
    comptime AF_FRAME = Self(36)
    """frame (Ethernet) sockets"""
    comptime AF_MAX = Self(37)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `AddressFamily` instances for equality.

        Args:
            other: The other `AddressFamily` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes the `AddressFamily` to a writer.

        Params:
            W: The type of the writer.

        Args:
            writer: The writer to write to.
        """
        # TODO: Only writing the important AF for now.
        var value: String
        if self == Self.AF_UNIX:
            value = "AF_UNIX"
        elif self == Self.AF_INET:
            value = "AF_INET"
        elif self == Self.AF_INET6:
            value = "AF_INET6"
        else:
            value = String("AddressFamily(", self.value, ")")
        writer.write(value)

    fn __str__(self) -> String:
        """Converts the `AddressFamily` to a string.

        Returns:
            The string representation of the `AddressFamily`.
        """
        return String.write(self)

    @always_inline("nodebug")
    fn is_inet(self) -> Bool:
        """Checks if the AddressFamily is either AF_INET or AF_INET6.

        Returns:
            True if the AddressFamily is either AF_INET or AF_INET6, False otherwise.
        """
        return self == Self.AF_INET or self == Self.AF_INET6


@fieldwise_init
@register_passable("trivial")
struct AddressLength(Copyable, Equatable, Stringable, Writable):
    var value: Int
    comptime INET_ADDRSTRLEN = Self(16)
    comptime INET6_ADDRSTRLEN = Self(46)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `AddressLength` instances for equality.

        Args:
            other: The other `AddressLength` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes the `AddressFamily` to a writer.

        Params:
            W: The type of the writer.

        Args:
            writer: The writer to write to.
        """
        var value: StaticString
        if self == Self.INET_ADDRSTRLEN:
            value = "INET_ADDRSTRLEN"
        else:
            value = "INET6_ADDRSTRLEN"
        writer.write(value)

    fn __str__(self) -> String:
        """Converts the `AddressFamily` to a string.

        Returns:
            The string representation of the `AddressFamily`.
        """
        return String.write(self)


@fieldwise_init
@register_passable("trivial")
struct ProtocolFamily(Copyable, Equatable, Stringable, Writable):
    """Protocol families, same as address families for now."""

    var value: c_int
    comptime PF_UNSPEC = Self(AddressFamily.AF_UNSPEC.value)
    comptime PF_LOCAL = Self(AddressFamily.AF_LOCAL.value)
    comptime PF_UNIX = Self(AddressFamily.AF_UNIX.value)
    comptime PF_INET = Self(AddressFamily.AF_INET.value)
    comptime PF_IMPLINK = Self(AddressFamily.AF_IMPLINK.value)
    comptime PF_PUP = Self(AddressFamily.AF_PUP.value)
    comptime PF_CHAOS = Self(AddressFamily.AF_CHAOS.value)
    comptime PF_NS = Self(AddressFamily.AF_NS.value)
    comptime PF_ISO = Self(AddressFamily.AF_ISO.value)
    comptime PF_OSI = Self(AddressFamily.AF_ISO.value)
    comptime PF_ECMA = Self(AddressFamily.AF_ECMA.value)
    comptime PF_DATAKIT = Self(AddressFamily.AF_DATAKIT.value)
    comptime PF_CCITT = Self(AddressFamily.AF_CCITT.value)
    comptime PF_SNA = Self(AddressFamily.AF_SNA.value)
    comptime PF_DECnet = Self(AddressFamily.AF_DECnet.value)
    comptime PF_DLI = Self(AddressFamily.AF_DLI.value)
    comptime PF_LAT = Self(AddressFamily.AF_LAT.value)
    comptime PF_HYLINK = Self(AddressFamily.AF_HYLINK.value)
    comptime PF_APPLETALK = Self(AddressFamily.AF_APPLETALK.value)
    comptime PF_ROUTE = Self(AddressFamily.AF_ROUTE.value)
    comptime PF_LINK = Self(AddressFamily.AF_LINK.value)
    comptime PF_XTP = Self(AddressFamily.pseudo_AF_XTP.value)  # really just proto family, no AF
    comptime PF_COIP = Self(AddressFamily.AF_COIP.value)
    comptime PF_CNT = Self(AddressFamily.AF_CNT.value)
    comptime PF_IPX = Self(AddressFamily.AF_IPX.value)  # same format as = AddressFamily.AF_NS
    comptime PF_INET6 = Self(AddressFamily.AF_INET6.value)
    comptime PF_RTIP = Self(AddressFamily.pseudo_AF_RTIP.value)  # same format as AF_INET
    comptime PF_PIP = Self(AddressFamily.pseudo_AF_PIP.value)
    comptime PF_ISDN = Self(AddressFamily.AF_ISDN.value)
    comptime PF_NATM = Self(AddressFamily.AF_NATM.value)
    comptime PF_ENCAP = Self(AddressFamily.AF_ENCAP.value)
    comptime PF_SIP = Self(AddressFamily.AF_SIP.value)
    comptime PF_KEY = Self(AddressFamily.AF_KEY.value)
    comptime PF_BPF = Self(AddressFamily.pseudo_AF_HDRCMPLT.value)
    comptime PF_BLUETOOTH = Self(AddressFamily.AF_BLUETOOTH.value)
    comptime PF_MPLS = Self(AddressFamily.AF_MPLS.value)
    comptime PF_PFLOW = Self(AddressFamily.pseudo_AF_PFLOW.value)
    comptime PF_PIPEX = Self(AddressFamily.pseudo_AF_PIPEX.value)
    comptime PF_FRAME = Self(AddressFamily.AF_FRAME.value)
    comptime PF_MAX = Self(AddressFamily.AF_MAX.value)

    fn __eq__(self, other: Self) -> Bool:
        """Compares two `ProtocolFamily` instances for equality.

        Args:
            other: The other `ProtocolFamily` instance to compare to.

        Returns:
            True if the two instances are equal, False otherwise.
        """
        return self.value == other.value

    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes the `ProtocolFamily` to a writer.

        Params:
            W: The type of the writer.

        Args:
            writer: The writer to write to.
        """
        writer.write("ProtocolFamily(", self.value, ")")

    fn __str__(self) -> String:
        """Returns the string representation of the `ProtocolFamily`.

        Returns:
            The string representation of the `ProtocolFamily`.
        """
        return String.write(self)
