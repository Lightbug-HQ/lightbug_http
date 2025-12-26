"""
Auto-generated typed errors for socket operations.
Generated from socket.mojo error handling patterns.
Follows the pattern from typed_errors.mojo.
"""

from sys.ffi import c_int, external_call, get_errno
from utils import Variant
from lightbug_http.utils import CustomError


# ===== ERROR STRUCTS (one per errno) =====

@fieldwise_init
@register_passable("trivial")
struct EACCESError(CustomError):
    comptime message = "SendToError (EACCES): Search permission is denied for a component of the path prefix; or write access to the named socket is denied."

@fieldwise_init
@register_passable("trivial")
struct EADDRINUSEError(CustomError):
    comptime message = "connect (EADDRINUSE): Local address is already in use."

@fieldwise_init
@register_passable("trivial")
struct EAFNOSUPPORTError(CustomError):
    comptime message = "SendToError (EAFNOSUPPORT): Addresses in the specified address family cannot be used with this socket."

@fieldwise_init
@register_passable("trivial")
struct EAGAINError(CustomError):
    comptime message = "SendToError (EAGAIN/EWOULDBLOCK) (EAGAIN): The socket's file descriptor is marked `O_NONBLOCK` and the requested operation would block."

@fieldwise_init
@register_passable("trivial")
struct EALREADYError(CustomError):
    comptime message = "connect (EALREADY): The file descriptor is not a valid index in the descriptor table."

@fieldwise_init
@register_passable("trivial")
struct EBADFError(CustomError):
    comptime message = "CloseError (EBADF): The file_descriptor argument is not a valid open file descriptor."

@fieldwise_init
@register_passable("trivial")
struct ECONNABORTEDError(CustomError):
    comptime message = "accept (ECONNABORTED): `socket` is not a valid descriptor."

@fieldwise_init
@register_passable("trivial")
struct ECONNREFUSEDError(CustomError):
    comptime message = "SendError (ECONNREFUSED): `buffer` points outside the process's address space."

@fieldwise_init
@register_passable("trivial")
struct ECONNRESETError(CustomError):
    comptime message = "SendToError (ECONNRESET): A connection was forcibly closed by a peer."

@fieldwise_init
@register_passable("trivial")
struct EDESTADDRREQError(CustomError):
    comptime message = "SendToError (EDESTADDRREQ): The socket is not connection-mode and does not have its peer address set, and no destination address was specified."

@fieldwise_init
@register_passable("trivial")
struct EFAULTError(CustomError):
    comptime message = "SendError (EFAULT): `buffer` points outside the process's address space."

@fieldwise_init
@register_passable("trivial")
struct EHOSTUNREACHError(CustomError):
    comptime message = "SendToError (EHOSTUNREACH): The destination host cannot be reached (probably because the host is down or a remote router cannot reach it)."

@fieldwise_init
@register_passable("trivial")
struct EINTRError(CustomError):
    comptime message = "CloseError (EINTR): The close() function was interrupted by a signal."

@fieldwise_init
@register_passable("trivial")
struct EINVALError(CustomError):
    comptime message = "ShutdownError (EINVAL): Invalid argument passed."

@fieldwise_init
@register_passable("trivial")
struct EIOError(CustomError):
    comptime message = "CloseError (EIO): An I/O error occurred while reading from or writing to the file system."

@fieldwise_init
@register_passable("trivial")
struct EISCONNError(CustomError):
    comptime message = "SendToError (EISCONN): A destination address was specified and the socket is already connected."

@fieldwise_init
@register_passable("trivial")
struct ELOOPError(CustomError):
    comptime message = "SendToError (ELOOP): More than `SYMLOOP_MAX` symbolic links were encountered during resolution of the pathname in the socket address."

@fieldwise_init
@register_passable("trivial")
struct EMFILEError(CustomError):
    comptime message = "accept (EMFILE): The per-process limit of open file descriptors has been reached."

@fieldwise_init
@register_passable("trivial")
struct EMSGSIZEError(CustomError):
    comptime message = "SendToError (EMSGSIZE): The message is too large to be sent all at once, as the socket requires."

@fieldwise_init
@register_passable("trivial")
struct ENAMETOOLONGError(CustomError):
    comptime message = "SendToError (ENAMETOOLONG): The length of a pathname exceeds `PATH_MAX`, or pathname resolution of a symbolic link produced an intermediate result with a length that exceeds `PATH_MAX`."

@fieldwise_init
@register_passable("trivial")
struct ENETDOWNError(CustomError):
    comptime message = "SendToError (ENETDOWN): The local network interface used to reach the destination is down."

@fieldwise_init
@register_passable("trivial")
struct ENETUNREACHError(CustomError):
    comptime message = "SendToError (ENETUNREACH): No route to the network is present."

@fieldwise_init
@register_passable("trivial")
struct ENFILEError(CustomError):
    comptime message = "accept (ENFILE): The system limit on the total number of open files has been reached."

@fieldwise_init
@register_passable("trivial")
struct ENOBUFSError(CustomError):
    comptime message = "SendToError (ENOBUFS): Insufficient resources were available in the system to perform the operation."

@fieldwise_init
@register_passable("trivial")
struct ENOMEMError(CustomError):
    comptime message = "SendToError (ENOMEM): Insufficient memory was available to fulfill the request."

@fieldwise_init
@register_passable("trivial")
struct ENOPROTOOPTError(CustomError):
    comptime message = "getsockopt (ENOPROTOOPT): The option is unknown at the level indicated."

@fieldwise_init
@register_passable("trivial")
struct ENOSPCError(CustomError):
    comptime message = "CloseError (ENOSPC or EDQUOT): On NFS, these errors are not normally reported against the first write which exceeds the available storage space, but instead against a subsequent write(2), fsync(2), or close()."

@fieldwise_init
@register_passable("trivial")
struct ENOTCONNError(CustomError):
    comptime message = "ShutdownError (ENOTCONN): The socket is not connected."

@fieldwise_init
@register_passable("trivial")
struct ENOTSOCKError(CustomError):
    comptime message = "ShutdownError (ENOTSOCK): The file descriptor is not associated with a socket."

@fieldwise_init
@register_passable("trivial")
struct EOPNOTSUPPError(CustomError):
    comptime message = "SendError (EOPNOTSUPP): Some bit in the flags argument is inappropriate for the socket type."

@fieldwise_init
@register_passable("trivial")
struct EPERMError(CustomError):
    comptime message = "accept (EPERM): Firewall rules forbid connection."

@fieldwise_init
@register_passable("trivial")
struct EPIPEError(CustomError):
    comptime message = "SendToError (EPIPE): The socket is shut down for writing, or the socket is connection-mode and is no longer connected."

@fieldwise_init
@register_passable("trivial")
struct EPROTOError(CustomError):
    comptime message = "accept (EPROTO): Protocol error."

@fieldwise_init
@register_passable("trivial")
struct EPROTONOSUPPORTError(CustomError):
    comptime message = "SocketError (EPROTONOSUPPORT): The protocol type or the specified protocol is not supported within this domain."

@fieldwise_init
@register_passable("trivial")
struct ETIMEDOUTError(CustomError):
    comptime message = "ReceiveError (ETIMEDOUT): The connection timed out during connection establishment, or due to a transmission timeout on active connection."


# ===== VARIANT ERROR TYPES (one per function) =====

@fieldwise_init
struct AcceptError(Movable, Stringable, Writable):
    """Typed error variant for accept() function."""

    comptime type = Variant[
        EBADFError,
        ECONNABORTEDError,
        EFAULTError,
        EINVALError,
        EMFILEError,
        ENFILEError,
        ENOBUFSError,
        ENOTSOCKError,
        EOPNOTSUPPError,
        EPERMError,
        EPROTOError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNABORTEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: EMFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: EOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, value: EPERMError):
        self.value = value

    @implicit
    fn __init__(out self, value: EPROTOError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNABORTEDError]():
            writer.write(self.value[ECONNABORTEDError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[EMFILEError]():
            writer.write(self.value[EMFILEError])
        elif self.value.isa[ENFILEError]():
            writer.write(self.value[ENFILEError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[EOPNOTSUPPError]():
            writer.write(self.value[EOPNOTSUPPError])
        elif self.value.isa[EPERMError]():
            writer.write(self.value[EPERMError])
        elif self.value.isa[EPROTOError]():
            writer.write(self.value[EPROTOError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct BindError(Movable, Stringable, Writable):
    """Typed error variant for bind() function."""

    comptime type = Variant[
        EACCESError,
        EADDRINUSEError,
        EBADFError,
        EFAULTError,
        EINVALError,
        ELOOPError,
        ENAMETOOLONGError,
        ENOMEMError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: EADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ELOOPError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENAMETOOLONGError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EACCESError]():
            writer.write(self.value[EACCESError])
        elif self.value.isa[EADDRINUSEError]():
            writer.write(self.value[EADDRINUSEError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ELOOPError]():
            writer.write(self.value[ELOOPError])
        elif self.value.isa[ENAMETOOLONGError]():
            writer.write(self.value[ENAMETOOLONGError])
        elif self.value.isa[ENOMEMError]():
            writer.write(self.value[ENOMEMError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct CloseError(Movable, Stringable, Writable):
    """Typed error variant for close() function."""

    comptime type = Variant[
        EBADFError,
        EINTRError,
        EIOError,
        ENOSPCError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOSPCError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EIOError]():
            writer.write(self.value[EIOError])
        elif self.value.isa[ENOSPCError]():
            writer.write(self.value[ENOSPCError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct ConnectError(Movable, Stringable, Writable):
    """Typed error variant for connect() function."""

    comptime type = Variant[
        EACCESError,
        EADDRINUSEError,
        EAFNOSUPPORTError,
        EAGAINError,
        EALREADYError,
        EBADFError,
        ECONNREFUSEDError,
        EFAULTError,
        EINTRError,
        EISCONNError,
        ENETUNREACHError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: EADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: EAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: EALREADYError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENETUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EACCESError]():
            writer.write(self.value[EACCESError])
        elif self.value.isa[EADDRINUSEError]():
            writer.write(self.value[EADDRINUSEError])
        elif self.value.isa[EAFNOSUPPORTError]():
            writer.write(self.value[EAFNOSUPPORTError])
        elif self.value.isa[EAGAINError]():
            writer.write(self.value[EAGAINError])
        elif self.value.isa[EALREADYError]():
            writer.write(self.value[EALREADYError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNREFUSEDError]():
            writer.write(self.value[ECONNREFUSEDError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EISCONNError]():
            writer.write(self.value[EISCONNError])
        elif self.value.isa[ENETUNREACHError]():
            writer.write(self.value[ENETUNREACHError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct GetpeernameError(Movable, Stringable, Writable):
    """Typed error variant for getpeername() function."""

    comptime type = Variant[
        EBADFError,
        EFAULTError,
        EINVALError,
        ENOBUFSError,
        ENOTCONNError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct GetsocknameError(Movable, Stringable, Writable):
    """Typed error variant for getsockname() function."""

    comptime type = Variant[
        EBADFError,
        EFAULTError,
        EINVALError,
        ENOBUFSError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct GetsockoptError(Movable, Stringable, Writable):
    """Typed error variant for getsockopt() function."""

    comptime type = Variant[
        EBADFError,
        EFAULTError,
        EINVALError,
        ENOPROTOOPTError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOPROTOOPTError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ENOPROTOOPTError]():
            writer.write(self.value[ENOPROTOOPTError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct ListenError(Movable, Stringable, Writable):
    """Typed error variant for listen() function."""

    comptime type = Variant[
        EADDRINUSEError,
        EBADFError,
        ENOTSOCKError,
        EOPNOTSUPPError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: EOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EADDRINUSEError]():
            writer.write(self.value[EADDRINUSEError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[EOPNOTSUPPError]():
            writer.write(self.value[EOPNOTSUPPError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct RecvError(Movable, Stringable, Writable):
    """Typed error variant for recv() function."""

    comptime type = Variant[
        EAGAINError,
        EBADFError,
        ECONNREFUSEDError,
        EFAULTError,
        EINTRError,
        ENOTCONNError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EAGAINError]():
            writer.write(self.value[EAGAINError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNREFUSEDError]():
            writer.write(self.value[ECONNREFUSEDError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct RecvfromError(Movable, Stringable, Writable):
    """Typed error variant for recvfrom() function."""

    comptime type = Variant[
        EAGAINError,
        EBADFError,
        ECONNRESETError,
        EINTRError,
        EINVALError,
        EIOError,
        ENOBUFSError,
        ENOMEMError,
        ENOTCONNError,
        ENOTSOCKError,
        EOPNOTSUPPError,
        ETIMEDOUTError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: EIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: EOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, value: ETIMEDOUTError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EAGAINError]():
            writer.write(self.value[EAGAINError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNRESETError]():
            writer.write(self.value[ECONNRESETError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[EIOError]():
            writer.write(self.value[EIOError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOMEMError]():
            writer.write(self.value[ENOMEMError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[EOPNOTSUPPError]():
            writer.write(self.value[EOPNOTSUPPError])
        elif self.value.isa[ETIMEDOUTError]():
            writer.write(self.value[ETIMEDOUTError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct SendError(Movable, Stringable, Writable):
    """Typed error variant for send() function."""

    comptime type = Variant[
        EAGAINError,
        EBADFError,
        ECONNREFUSEDError,
        ECONNRESETError,
        EDESTADDRREQError,
        EFAULTError,
        EINTRError,
        EINVALError,
        EISCONNError,
        ENOBUFSError,
        ENOMEMError,
        ENOTCONNError,
        ENOTSOCKError,
        EOPNOTSUPPError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: EDESTADDRREQError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: EISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: EOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EAGAINError]():
            writer.write(self.value[EAGAINError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNREFUSEDError]():
            writer.write(self.value[ECONNREFUSEDError])
        elif self.value.isa[ECONNRESETError]():
            writer.write(self.value[ECONNRESETError])
        elif self.value.isa[EDESTADDRREQError]():
            writer.write(self.value[EDESTADDRREQError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[EISCONNError]():
            writer.write(self.value[EISCONNError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOMEMError]():
            writer.write(self.value[ENOMEMError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[EOPNOTSUPPError]():
            writer.write(self.value[EOPNOTSUPPError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct SendtoError(Movable, Stringable, Writable):
    """Typed error variant for sendto() function."""

    comptime type = Variant[
        EACCESError,
        EAFNOSUPPORTError,
        EAGAINError,
        EBADFError,
        ECONNRESETError,
        EDESTADDRREQError,
        EHOSTUNREACHError,
        EINTRError,
        EINVALError,
        EIOError,
        EISCONNError,
        ELOOPError,
        EMSGSIZEError,
        ENAMETOOLONGError,
        ENETDOWNError,
        ENETUNREACHError,
        ENOBUFSError,
        ENOMEMError,
        ENOTCONNError,
        ENOTSOCKError,
        EPIPEError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: EAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: EDESTADDRREQError):
        self.value = value

    @implicit
    fn __init__(out self, value: EHOSTUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: EIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: EISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ELOOPError):
        self.value = value

    @implicit
    fn __init__(out self, value: EMSGSIZEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENAMETOOLONGError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENETDOWNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENETUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: EPIPEError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EACCESError]():
            writer.write(self.value[EACCESError])
        elif self.value.isa[EAFNOSUPPORTError]():
            writer.write(self.value[EAFNOSUPPORTError])
        elif self.value.isa[EAGAINError]():
            writer.write(self.value[EAGAINError])
        elif self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[ECONNRESETError]():
            writer.write(self.value[ECONNRESETError])
        elif self.value.isa[EDESTADDRREQError]():
            writer.write(self.value[EDESTADDRREQError])
        elif self.value.isa[EHOSTUNREACHError]():
            writer.write(self.value[EHOSTUNREACHError])
        elif self.value.isa[EINTRError]():
            writer.write(self.value[EINTRError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[EIOError]():
            writer.write(self.value[EIOError])
        elif self.value.isa[EISCONNError]():
            writer.write(self.value[EISCONNError])
        elif self.value.isa[ELOOPError]():
            writer.write(self.value[ELOOPError])
        elif self.value.isa[EMSGSIZEError]():
            writer.write(self.value[EMSGSIZEError])
        elif self.value.isa[ENAMETOOLONGError]():
            writer.write(self.value[ENAMETOOLONGError])
        elif self.value.isa[ENETDOWNError]():
            writer.write(self.value[ENETDOWNError])
        elif self.value.isa[ENETUNREACHError]():
            writer.write(self.value[ENETUNREACHError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[ENOMEMError]():
            writer.write(self.value[ENOMEMError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[EPIPEError]():
            writer.write(self.value[EPIPEError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct SetsockoptError(Movable, Stringable, Writable):
    """Typed error variant for setsockopt() function."""

    comptime type = Variant[
        EBADFError,
        EFAULTError,
        EINVALError,
        ENOPROTOOPTError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOPROTOOPTError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EFAULTError]():
            writer.write(self.value[EFAULTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ENOPROTOOPTError]():
            writer.write(self.value[ENOPROTOOPTError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct ShutdownError(Movable, Stringable, Writable):
    """Typed error variant for shutdown() function."""

    comptime type = Variant[
        EBADFError,
        EINVALError,
        ENOTCONNError,
        ENOTSOCKError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EBADFError]():
            writer.write(self.value[EBADFError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[ENOTCONNError]():
            writer.write(self.value[ENOTCONNError])
        elif self.value.isa[ENOTSOCKError]():
            writer.write(self.value[ENOTSOCKError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

@fieldwise_init
struct SocketError(Movable, Stringable, Writable):
    """Typed error variant for socket() function."""

    comptime type = Variant[
        EACCESError,
        EAFNOSUPPORTError,
        EINVALError,
        EMFILEError,
        ENFILEError,
        ENOBUFSError,
        EPROTONOSUPPORTError,
        Error
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: EACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: EAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: EINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: EMFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: EPROTONOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[EACCESError]():
            writer.write(self.value[EACCESError])
        elif self.value.isa[EAFNOSUPPORTError]():
            writer.write(self.value[EAFNOSUPPORTError])
        elif self.value.isa[EINVALError]():
            writer.write(self.value[EINVALError])
        elif self.value.isa[EMFILEError]():
            writer.write(self.value[EMFILEError])
        elif self.value.isa[ENFILEError]():
            writer.write(self.value[ENFILEError])
        elif self.value.isa[ENOBUFSError]():
            writer.write(self.value[ENOBUFSError])
        elif self.value.isa[EPROTONOSUPPORTError]():
            writer.write(self.value[EPROTONOSUPPORTError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)

