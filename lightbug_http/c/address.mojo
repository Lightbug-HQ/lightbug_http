from sys.ffi import c_int

from lightbug_http.c.aliases import ExternalImmutUnsafePointer, ExternalMutUnsafePointer, c_void


@fieldwise_init
@register_passable("trivial")
struct AddressInformation(Copyable, Equatable, Stringable, Writable):
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
    """Unspecified, will use either IPv4 or IPv6."""
    comptime AF_INET = Self(2)
    """IPv4: UDP, TCP, etc."""
    comptime AF_INET6 = Self(24)
    """IPv6: UDP, TCP, etc."""

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
        if self == Self.AF_UNSPEC:
            writer.write("AF_UNSPEC")
        elif self == Self.AF_INET:
            writer.write("AF_INET")
        elif self == Self.AF_INET6:
            writer.write("AF_INET6")
        else:
            writer.write("AddressFamily(", self.value, ")")

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
