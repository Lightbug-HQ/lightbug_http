trait CustomError(Movable, Stringable, Writable):
    """Trait for error marker structs with comptime messages.

    Provides default implementations for write_to and __str__ that use
    the comptime 'message' field.
    """

    comptime message: String
