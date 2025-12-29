trait CustomError(Movable, Stringable, Writable):
    """Trait for error marker structs with comptime messages.

    Provides default implementations for write_to and __str__ that use
    the comptime 'message' field.
    """

    comptime message: String

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message
