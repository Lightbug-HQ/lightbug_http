from collections import Optional
from memory import UnsafePointer, alloc

struct ErrorWithCause(
    Boolable,
    Representable,
    Stringable,
    Writable,
    Movable,
):
    """
    An error that can wrap another ErrorWithCause as its cause. 
    This has performance overhead compared to stdlib Error, so prefer the stdlib version where possible.

    Example:
        fn throw_error_with_cause() raises ErrorWithCause:
            try:
                raise Error("Something went wrong")
            except err:
                raise ErrorWithCause(
                    "Additional context for the error",
                    ErrorWithCause(err^) # Convert stdlib Error to ErrorWithCause
                )
    """
    
    comptime CausePointer = UnsafePointer[ErrorWithCause, MutOrigin.external]
    
    var error: Error
    var __cause__: Self.CausePointer
    
    fn __init__(out self, message: String):
        self.error = Error(message)
        self.__cause__ = Self.CausePointer()
    
    fn __init__(out self, message: StringLiteral):
        self.error = Error(message)
        self.__cause__ = Self.CausePointer()
    
    fn __init__(out self, var error: Error):
        self.error = error^
        self.__cause__ = Self.CausePointer()
    
    fn __init__(out self, message: String, var cause: ErrorWithCause):
        self.error = Error(message)
        var cause_ptr = alloc[ErrorWithCause](1)
        cause_ptr.init_pointee_move(cause^)
        self.__cause__ = cause_ptr
    
    fn __init__(out self, message: StringLiteral, var cause: ErrorWithCause):
        self.error = Error(message)
        var cause_ptr = alloc[ErrorWithCause](1)
        cause_ptr.init_pointee_move(cause^)
        self.__cause__ = cause_ptr
    
    fn __init__(out self, var error: Error, var cause: ErrorWithCause):
        self.error = error^
        var cause_ptr = alloc[ErrorWithCause](1)
        cause_ptr.init_pointee_move(cause^)
        self.__cause__ = cause_ptr
    
    fn __del__(deinit self):
        if self.__cause__:
            self.__cause__.destroy_pointee()
            self.__cause__.free()
    
    fn __bool__(self) -> Bool:
        return Bool(self.error)
    
    fn __str__(self) -> String:
        var result = String(self.error)
        if self.__cause__:
            result += "\n  Caused by: " + String(self.__cause__[])
        return result
    
    fn __repr__(self) -> String:
        return String("ErrorWithCause('", self.error, "')")
    
    fn write_to(self, mut writer: Some[Writer]):
        writer.write(String(self))
    
    fn get_stack_trace(self) -> Optional[String]:
        return self.error.get_stack_trace()
