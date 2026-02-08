"""
Auto-generated typed errors for socket operations.
Generated from socket.mojo error handling patterns.
Follows the pattern from typed_errors.mojo.
"""

from sys.ffi import c_int, external_call, get_errno

from lightbug_http.utils.error import CustomError
from utils import Variant


# Accept errors
@fieldwise_init
@register_passable("trivial")
struct AcceptEBADFError(CustomError):
    comptime message = "accept (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEINTRError(CustomError):
    comptime message = "accept (EINTR): The system call was interrupted by a signal that was caught before a valid connection arrived."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEAGAINError(CustomError):
    comptime message = "accept (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and no connections are present to be accepted."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptECONNABORTEDError(CustomError):
    comptime message = "accept (ECONNABORTED): A connection has been aborted."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEFAULTError(CustomError):
    comptime message = "accept (EFAULT): The address argument is not in a writable part of the user address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEINVALError(CustomError):
    comptime message = "accept (EINVAL): Socket is not listening for connections, or address_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEMFILEError(CustomError):
    comptime message = "accept (EMFILE): The per-process limit of open file descriptors has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptENFILEError(CustomError):
    comptime message = "accept (ENFILE): The system limit on the total number of open files has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptENOBUFSError(CustomError):
    comptime message = "accept (ENOBUFS): Not enough free memory."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptENOTSOCKError(CustomError):
    comptime message = "accept (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEOPNOTSUPPError(CustomError):
    comptime message = "accept (EOPNOTSUPP): The referenced socket is not of type SOCK_STREAM."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEPERMError(CustomError):
    comptime message = "accept (EPERM): Firewall rules forbid connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct AcceptEPROTOError(CustomError):
    comptime message = "accept (EPROTO): Protocol error."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Bind errors
@fieldwise_init
@register_passable("trivial")
struct BindEACCESError(CustomError):
    comptime message = "bind (EACCES): The address is protected, and the user is not the superuser."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindEADDRINUSEError(CustomError):
    comptime message = "bind (EADDRINUSE): The given address is already in use."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindEBADFError(CustomError):
    comptime message = "bind (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindEFAULTError(CustomError):
    comptime message = "bind (EFAULT): address points outside the user's accessible address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindEINVALError(CustomError):
    comptime message = "bind (EINVAL): The socket is already bound to an address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindELOOPError(CustomError):
    comptime message = "bind (ELOOP): Too many symbolic links were encountered in resolving address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindENAMETOOLONGError(CustomError):
    comptime message = "bind (ENAMETOOLONG): address is too long."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindENOMEMError(CustomError):
    comptime message = "bind (ENOMEM): Insufficient kernel memory was available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct BindENOTSOCKError(CustomError):
    comptime message = "bind (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Close errors
@fieldwise_init
@register_passable("trivial")
struct CloseEBADFError(CustomError):
    comptime message = "close (EBADF): The file_descriptor argument is not a valid open file descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct CloseEINTRError(CustomError):
    comptime message = "close (EINTR): The close() function was interrupted by a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct CloseEIOError(CustomError):
    comptime message = "close (EIO): An I/O error occurred while reading from or writing to the file system."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct CloseENOSPCError(CustomError):
    comptime message = "close (ENOSPC or EDQUOT): On NFS, these errors are not normally reported against the first write which exceeds the available storage space, but instead against a subsequent write, fsync, or close."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Connect errors
@fieldwise_init
@register_passable("trivial")
struct ConnectEACCESError(CustomError):
    comptime message = "connect (EACCES): Write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEADDRINUSEError(CustomError):
    comptime message = "connect (EADDRINUSE): Local address is already in use."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEAFNOSUPPORTError(CustomError):
    comptime message = "connect (EAFNOSUPPORT): The passed address didn't have the correct address family in its sa_family field."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEAGAINError(CustomError):
    comptime message = "connect (EAGAIN): No more free local ports or insufficient entries in the routing cache."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEALREADYError(CustomError):
    comptime message = "connect (EALREADY): The socket is nonblocking and a previous connection attempt has not yet been completed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEBADFError(CustomError):
    comptime message = "connect (EBADF): The file descriptor is not a valid index in the descriptor table."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectECONNREFUSEDError(CustomError):
    comptime message = "connect (ECONNREFUSED): No-one listening on the remote address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEFAULTError(CustomError):
    comptime message = "connect (EFAULT): The socket structure address is outside the user's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEINPROGRESSError(CustomError):
    comptime message = "connect (EINPROGRESS): The socket is nonblocking and the connection cannot be completed immediately. It is possible to select(2) or poll(2) for completion by selecting the socket for writing. After select(2) indicates writability, use getsockopt(2) to read the SO_ERROR option at level SOL_SOCKET to determine whether connect() completed successfully (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error codes listed here, explaining the reason for the failure)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEINTRError(CustomError):
    comptime message = "connect (EINTR): The system call was interrupted by a signal that was caught."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectEISCONNError(CustomError):
    comptime message = "connect (EISCONN): The socket is already connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectENETUNREACHError(CustomError):
    comptime message = "connect (ENETUNREACH): Network is unreachable."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectENOTSOCKError(CustomError):
    comptime message = "connect (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ConnectETIMEDOUTError(CustomError):
    comptime message = "connect (ETIMEDOUT): Timeout while attempting connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getpeername errors
@fieldwise_init
@register_passable("trivial")
struct GetpeernameEBADFError(CustomError):
    comptime message = "getpeername (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetpeernameEFAULTError(CustomError):
    comptime message = "getpeername (EFAULT): The address argument points to memory not in a valid part of the process address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetpeernameEINVALError(CustomError):
    comptime message = "getpeername (EINVAL): address_len is invalid (e.g., is negative)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetpeernameENOBUFSError(CustomError):
    comptime message = "getpeername (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetpeernameENOTCONNError(CustomError):
    comptime message = "getpeername (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetpeernameENOTSOCKError(CustomError):
    comptime message = "getpeername (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getsockname errors
@fieldwise_init
@register_passable("trivial")
struct GetsocknameEBADFError(CustomError):
    comptime message = "getsockname (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsocknameEFAULTError(CustomError):
    comptime message = "getsockname (EFAULT): The address argument points to memory not in a valid part of the process address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsocknameEINVALError(CustomError):
    comptime message = "getsockname (EINVAL): address_len is invalid (e.g., is negative)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsocknameENOBUFSError(CustomError):
    comptime message = "getsockname (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsocknameENOTSOCKError(CustomError):
    comptime message = "getsockname (ENOTSOCK): The argument socket is a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getsockopt errors
@fieldwise_init
@register_passable("trivial")
struct GetsockoptEBADFError(CustomError):
    comptime message = "getsockopt (EBADF): The argument socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsockoptEFAULTError(CustomError):
    comptime message = "getsockopt (EFAULT): The argument option_value points outside the process's allocated address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsockoptEINVALError(CustomError):
    comptime message = "getsockopt (EINVAL): The argument option_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsockoptENOPROTOOPTError(CustomError):
    comptime message = "getsockopt (ENOPROTOOPT): The option is unknown at the level indicated."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct GetsockoptENOTSOCKError(CustomError):
    comptime message = "getsockopt (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Listen errors
@fieldwise_init
@register_passable("trivial")
struct ListenEADDRINUSEError(CustomError):
    comptime message = "listen (EADDRINUSE): Another socket is already listening on the same port."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ListenEBADFError(CustomError):
    comptime message = "listen (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ListenENOTSOCKError(CustomError):
    comptime message = "listen (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ListenEOPNOTSUPPError(CustomError):
    comptime message = "listen (EOPNOTSUPP): The socket is not of a type that supports the listen() operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Recv errors
@fieldwise_init
@register_passable("trivial")
struct RecvEAGAINError(CustomError):
    comptime message = "recv (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the receive operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvEBADFError(CustomError):
    comptime message = "recv (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvECONNREFUSEDError(CustomError):
    comptime message = "recv (ECONNREFUSED): The remote host refused to allow the network connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvEFAULTError(CustomError):
    comptime message = "recv (EFAULT): buffer points outside the process's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvEINTRError(CustomError):
    comptime message = "recv (EINTR): The receive was interrupted by delivery of a signal before any data were available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvENOTCONNError(CustomError):
    comptime message = "recv (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvENOTSOCKError(CustomError):
    comptime message = "recv (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Recvfrom errors
@fieldwise_init
@register_passable("trivial")
struct RecvfromEAGAINError(CustomError):
    comptime message = "recvfrom (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the receive operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromEBADFError(CustomError):
    comptime message = "recvfrom (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromECONNRESETError(CustomError):
    comptime message = "recvfrom (ECONNRESET): A connection was forcibly closed by a peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromEINTRError(CustomError):
    comptime message = "recvfrom (EINTR): The receive was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromEINVALError(CustomError):
    comptime message = "recvfrom (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromEIOError(CustomError):
    comptime message = "recvfrom (EIO): An I/O error occurred."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromENOBUFSError(CustomError):
    comptime message = "recvfrom (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromENOMEMError(CustomError):
    comptime message = "recvfrom (ENOMEM): Insufficient memory was available to fulfill the request."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromENOTCONNError(CustomError):
    comptime message = "recvfrom (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromENOTSOCKError(CustomError):
    comptime message = "recvfrom (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromEOPNOTSUPPError(CustomError):
    comptime message = "recvfrom (EOPNOTSUPP): The specified flags are not supported for this socket type or protocol."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct RecvfromETIMEDOUTError(CustomError):
    comptime message = "recvfrom (ETIMEDOUT): The connection timed out."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Send errors
@fieldwise_init
@register_passable("trivial")
struct SendEAGAINError(CustomError):
    comptime message = "send (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the send operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEBADFError(CustomError):
    comptime message = "send (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendECONNREFUSEDError(CustomError):
    comptime message = "send (ECONNREFUSED): The remote host refused to allow the network connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendECONNRESETError(CustomError):
    comptime message = "send (ECONNRESET): Connection reset by peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEDESTADDRREQError(CustomError):
    comptime message = "send (EDESTADDRREQ): The socket is not connection-mode, and no peer address is set."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEFAULTError(CustomError):
    comptime message = "send (EFAULT): buffer points outside the process's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEINTRError(CustomError):
    comptime message = "send (EINTR): The send was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEINVALError(CustomError):
    comptime message = "send (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEISCONNError(CustomError):
    comptime message = "send (EISCONN): The connection-mode socket was connected already but a recipient was specified."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendENOBUFSError(CustomError):
    comptime message = "send (ENOBUFS): The output queue for a network interface was full."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendENOMEMError(CustomError):
    comptime message = "send (ENOMEM): No memory available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendENOTCONNError(CustomError):
    comptime message = "send (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendENOTSOCKError(CustomError):
    comptime message = "send (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendEOPNOTSUPPError(CustomError):
    comptime message = "send (EOPNOTSUPP): Some bit in the flags argument is inappropriate for the socket type."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Sendto errors
@fieldwise_init
@register_passable("trivial")
struct SendtoEACCESError(CustomError):
    comptime message = "sendto (EACCES): Write access to the named socket is denied."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEAFNOSUPPORTError(CustomError):
    comptime message = "sendto (EAFNOSUPPORT): Addresses in the specified address family cannot be used with this socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEAGAINError(CustomError):
    comptime message = "sendto (EAGAIN/EWOULDBLOCK): The socket's file descriptor is marked O_NONBLOCK and the requested operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEBADFError(CustomError):
    comptime message = "sendto (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoECONNRESETError(CustomError):
    comptime message = "sendto (ECONNRESET): A connection was forcibly closed by a peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEDESTADDRREQError(CustomError):
    comptime message = "sendto (EDESTADDRREQ): The socket is not connection-mode and does not have its peer address set, and no destination address was specified."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEHOSTUNREACHError(CustomError):
    comptime message = "sendto (EHOSTUNREACH): The destination host cannot be reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEINTRError(CustomError):
    comptime message = "sendto (EINTR): The send was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEINVALError(CustomError):
    comptime message = "sendto (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEIOError(CustomError):
    comptime message = "sendto (EIO): An I/O error occurred."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEISCONNError(CustomError):
    comptime message = "sendto (EISCONN): A destination address was specified and the socket is already connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoELOOPError(CustomError):
    comptime message = "sendto (ELOOP): More than SYMLOOP_MAX symbolic links were encountered during resolution of the pathname in the socket address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEMSGSIZEError(CustomError):
    comptime message = "sendto (EMSGSIZE): The message is too large to be sent all at once, as the socket requires."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENAMETOOLONGError(CustomError):
    comptime message = "sendto (ENAMETOOLONG): The length of a pathname exceeds PATH_MAX."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENETDOWNError(CustomError):
    comptime message = "sendto (ENETDOWN): The local network interface used to reach the destination is down."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENETUNREACHError(CustomError):
    comptime message = "sendto (ENETUNREACH): No route to the network is present."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENOBUFSError(CustomError):
    comptime message = "sendto (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENOMEMError(CustomError):
    comptime message = "sendto (ENOMEM): Insufficient memory was available to fulfill the request."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENOTCONNError(CustomError):
    comptime message = "sendto (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoENOTSOCKError(CustomError):
    comptime message = "sendto (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SendtoEPIPEError(CustomError):
    comptime message = "sendto (EPIPE): The socket is shut down for writing, or the socket is connection-mode and is no longer connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Setsockopt errors
@fieldwise_init
@register_passable("trivial")
struct SetsockoptEBADFError(CustomError):
    comptime message = "setsockopt (EBADF): The argument socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SetsockoptEFAULTError(CustomError):
    comptime message = "setsockopt (EFAULT): The argument option_value points outside the process's allocated address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SetsockoptEINVALError(CustomError):
    comptime message = "setsockopt (EINVAL): The argument option_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SetsockoptENOPROTOOPTError(CustomError):
    comptime message = "setsockopt (ENOPROTOOPT): The option is unknown at the level indicated."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SetsockoptENOTSOCKError(CustomError):
    comptime message = "setsockopt (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Shutdown errors
@fieldwise_init
@register_passable("trivial")
struct ShutdownEBADFError(CustomError):
    comptime message = "shutdown (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ShutdownEINVALError(CustomError):
    comptime message = "shutdown (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ShutdownENOTCONNError(CustomError):
    comptime message = "shutdown (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct ShutdownENOTSOCKError(CustomError):
    comptime message = "shutdown (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Socket errors
@fieldwise_init
@register_passable("trivial")
struct SocketEACCESError(CustomError):
    comptime message = "socket (EACCES): Permission to create a socket of the specified type and/or protocol is denied."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketEAFNOSUPPORTError(CustomError):
    comptime message = "socket (EAFNOSUPPORT): The implementation does not support the specified address family."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketEINVALError(CustomError):
    comptime message = "socket (EINVAL): Invalid flags in type, unknown protocol, or protocol family not available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketEMFILEError(CustomError):
    comptime message = "socket (EMFILE): The per-process limit on the number of open file descriptors has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketENFILEError(CustomError):
    comptime message = "socket (ENFILE): The system-wide limit on the total number of open files has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketENOBUFSError(CustomError):
    comptime message = "socket (ENOBUFS): Insufficient memory is available. The socket cannot be created until sufficient resources are freed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
@register_passable("trivial")
struct SocketEPROTONOSUPPORTError(CustomError):
    comptime message = "socket (EPROTONOSUPPORT): The protocol type or the specified protocol is not supported within this domain."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptError(Movable, Stringable, Writable):
    """Typed error variant for accept() function."""

    comptime type = Variant[
        AcceptEBADFError,
        AcceptEINTRError,
        AcceptEAGAINError,
        AcceptECONNABORTEDError,
        AcceptEFAULTError,
        AcceptEINVALError,
        AcceptEMFILEError,
        AcceptENFILEError,
        AcceptENOBUFSError,
        AcceptENOTSOCKError,
        AcceptEOPNOTSUPPError,
        AcceptEPERMError,
        AcceptEPROTOError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: AcceptEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptECONNABORTEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEMFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptENFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEPERMError):
        self.value = value

    @implicit
    fn __init__(out self, value: AcceptEPROTOError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[AcceptEBADFError]():
            writer.write(self.value[AcceptEBADFError])
        elif self.value.isa[AcceptEINTRError]():
            writer.write(self.value[AcceptEINTRError])
        elif self.value.isa[AcceptEAGAINError]():
            writer.write(self.value[AcceptEAGAINError])
        elif self.value.isa[AcceptECONNABORTEDError]():
            writer.write(self.value[AcceptECONNABORTEDError])
        elif self.value.isa[AcceptEFAULTError]():
            writer.write(self.value[AcceptEFAULTError])
        elif self.value.isa[AcceptEINVALError]():
            writer.write(self.value[AcceptEINVALError])
        elif self.value.isa[AcceptEMFILEError]():
            writer.write(self.value[AcceptEMFILEError])
        elif self.value.isa[AcceptENFILEError]():
            writer.write(self.value[AcceptENFILEError])
        elif self.value.isa[AcceptENOBUFSError]():
            writer.write(self.value[AcceptENOBUFSError])
        elif self.value.isa[AcceptENOTSOCKError]():
            writer.write(self.value[AcceptENOTSOCKError])
        elif self.value.isa[AcceptEOPNOTSUPPError]():
            writer.write(self.value[AcceptEOPNOTSUPPError])
        elif self.value.isa[AcceptEPERMError]():
            writer.write(self.value[AcceptEPERMError])
        elif self.value.isa[AcceptEPROTOError]():
            writer.write(self.value[AcceptEPROTOError])
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
        BindEACCESError,
        BindEADDRINUSEError,
        BindEBADFError,
        BindEFAULTError,
        BindEINVALError,
        BindELOOPError,
        BindENAMETOOLONGError,
        BindENOMEMError,
        BindENOTSOCKError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: BindEACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindEADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindELOOPError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindENAMETOOLONGError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: BindENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[BindEACCESError]():
            writer.write(self.value[BindEACCESError])
        elif self.value.isa[BindEADDRINUSEError]():
            writer.write(self.value[BindEADDRINUSEError])
        elif self.value.isa[BindEBADFError]():
            writer.write(self.value[BindEBADFError])
        elif self.value.isa[BindEFAULTError]():
            writer.write(self.value[BindEFAULTError])
        elif self.value.isa[BindEINVALError]():
            writer.write(self.value[BindEINVALError])
        elif self.value.isa[BindELOOPError]():
            writer.write(self.value[BindELOOPError])
        elif self.value.isa[BindENAMETOOLONGError]():
            writer.write(self.value[BindENAMETOOLONGError])
        elif self.value.isa[BindENOMEMError]():
            writer.write(self.value[BindENOMEMError])
        elif self.value.isa[BindENOTSOCKError]():
            writer.write(self.value[BindENOTSOCKError])
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

    comptime type = Variant[CloseEBADFError, CloseEINTRError, CloseEIOError, CloseENOSPCError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: CloseEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: CloseEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: CloseEIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: CloseENOSPCError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[CloseEBADFError]():
            writer.write(self.value[CloseEBADFError])
        elif self.value.isa[CloseEINTRError]():
            writer.write(self.value[CloseEINTRError])
        elif self.value.isa[CloseEIOError]():
            writer.write(self.value[CloseEIOError])
        elif self.value.isa[CloseENOSPCError]():
            writer.write(self.value[CloseENOSPCError])

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
        ConnectEACCESError,
        ConnectEADDRINUSEError,
        ConnectEAFNOSUPPORTError,
        ConnectEAGAINError,
        ConnectEALREADYError,
        ConnectEBADFError,
        ConnectECONNREFUSEDError,
        ConnectEFAULTError,
        ConnectEINPROGRESSError,
        ConnectEINTRError,
        ConnectEISCONNError,
        ConnectENETUNREACHError,
        ConnectENOTSOCKError,
        ConnectETIMEDOUTError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: ConnectEACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEALREADYError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEINPROGRESSError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectEISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectENETUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: ConnectETIMEDOUTError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[ConnectEACCESError]():
            writer.write(self.value[ConnectEACCESError])
        elif self.value.isa[ConnectEADDRINUSEError]():
            writer.write(self.value[ConnectEADDRINUSEError])
        elif self.value.isa[ConnectEAFNOSUPPORTError]():
            writer.write(self.value[ConnectEAFNOSUPPORTError])
        elif self.value.isa[ConnectEAGAINError]():
            writer.write(self.value[ConnectEAGAINError])
        elif self.value.isa[ConnectEALREADYError]():
            writer.write(self.value[ConnectEALREADYError])
        elif self.value.isa[ConnectEBADFError]():
            writer.write(self.value[ConnectEBADFError])
        elif self.value.isa[ConnectECONNREFUSEDError]():
            writer.write(self.value[ConnectECONNREFUSEDError])
        elif self.value.isa[ConnectEFAULTError]():
            writer.write(self.value[ConnectEFAULTError])
        elif self.value.isa[ConnectEINPROGRESSError]():
            writer.write(self.value[ConnectEINPROGRESSError])
        elif self.value.isa[ConnectEINTRError]():
            writer.write(self.value[ConnectEINTRError])
        elif self.value.isa[ConnectEISCONNError]():
            writer.write(self.value[ConnectEISCONNError])
        elif self.value.isa[ConnectENETUNREACHError]():
            writer.write(self.value[ConnectENETUNREACHError])
        elif self.value.isa[ConnectENOTSOCKError]():
            writer.write(self.value[ConnectENOTSOCKError])
        elif self.value.isa[ConnectETIMEDOUTError]():
            writer.write(self.value[ConnectETIMEDOUTError])
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
        GetpeernameEBADFError,
        GetpeernameEFAULTError,
        GetpeernameEINVALError,
        GetpeernameENOBUFSError,
        GetpeernameENOTCONNError,
        GetpeernameENOTSOCKError,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: GetpeernameEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetpeernameEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetpeernameEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetpeernameENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetpeernameENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetpeernameENOTSOCKError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[GetpeernameEBADFError]():
            writer.write(self.value[GetpeernameEBADFError])
        elif self.value.isa[GetpeernameEFAULTError]():
            writer.write(self.value[GetpeernameEFAULTError])
        elif self.value.isa[GetpeernameEINVALError]():
            writer.write(self.value[GetpeernameEINVALError])
        elif self.value.isa[GetpeernameENOBUFSError]():
            writer.write(self.value[GetpeernameENOBUFSError])
        elif self.value.isa[GetpeernameENOTCONNError]():
            writer.write(self.value[GetpeernameENOTCONNError])
        elif self.value.isa[GetpeernameENOTSOCKError]():
            writer.write(self.value[GetpeernameENOTSOCKError])

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
        GetsocknameEBADFError,
        GetsocknameEFAULTError,
        GetsocknameEINVALError,
        GetsocknameENOBUFSError,
        GetsocknameENOTSOCKError,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: GetsocknameEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsocknameEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsocknameEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsocknameENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsocknameENOTSOCKError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[GetsocknameEBADFError]():
            writer.write(self.value[GetsocknameEBADFError])
        elif self.value.isa[GetsocknameEFAULTError]():
            writer.write(self.value[GetsocknameEFAULTError])
        elif self.value.isa[GetsocknameEINVALError]():
            writer.write(self.value[GetsocknameEINVALError])
        elif self.value.isa[GetsocknameENOBUFSError]():
            writer.write(self.value[GetsocknameENOBUFSError])
        elif self.value.isa[GetsocknameENOTSOCKError]():
            writer.write(self.value[GetsocknameENOTSOCKError])

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
        GetsockoptEBADFError,
        GetsockoptEFAULTError,
        GetsockoptEINVALError,
        GetsockoptENOPROTOOPTError,
        GetsockoptENOTSOCKError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: GetsockoptEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsockoptEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsockoptEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsockoptENOPROTOOPTError):
        self.value = value

    @implicit
    fn __init__(out self, value: GetsockoptENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[GetsockoptEBADFError]():
            writer.write(self.value[GetsockoptEBADFError])
        elif self.value.isa[GetsockoptEFAULTError]():
            writer.write(self.value[GetsockoptEFAULTError])
        elif self.value.isa[GetsockoptEINVALError]():
            writer.write(self.value[GetsockoptEINVALError])
        elif self.value.isa[GetsockoptENOPROTOOPTError]():
            writer.write(self.value[GetsockoptENOPROTOOPTError])
        elif self.value.isa[GetsockoptENOTSOCKError]():
            writer.write(self.value[GetsockoptENOTSOCKError])
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

    comptime type = Variant[ListenEADDRINUSEError, ListenEBADFError, ListenENOTSOCKError, ListenEOPNOTSUPPError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: ListenEADDRINUSEError):
        self.value = value

    @implicit
    fn __init__(out self, value: ListenEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ListenENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: ListenEOPNOTSUPPError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[ListenEADDRINUSEError]():
            writer.write(self.value[ListenEADDRINUSEError])
        elif self.value.isa[ListenEBADFError]():
            writer.write(self.value[ListenEBADFError])
        elif self.value.isa[ListenENOTSOCKError]():
            writer.write(self.value[ListenENOTSOCKError])
        elif self.value.isa[ListenEOPNOTSUPPError]():
            writer.write(self.value[ListenEOPNOTSUPPError])

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
        RecvEAGAINError,
        RecvEBADFError,
        RecvECONNREFUSEDError,
        RecvEFAULTError,
        RecvEINTRError,
        RecvENOTCONNError,
        RecvENOTSOCKError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: RecvEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[RecvEAGAINError]():
            writer.write(self.value[RecvEAGAINError])
        elif self.value.isa[RecvEBADFError]():
            writer.write(self.value[RecvEBADFError])
        elif self.value.isa[RecvECONNREFUSEDError]():
            writer.write(self.value[RecvECONNREFUSEDError])
        elif self.value.isa[RecvEFAULTError]():
            writer.write(self.value[RecvEFAULTError])
        elif self.value.isa[RecvEINTRError]():
            writer.write(self.value[RecvEINTRError])
        elif self.value.isa[RecvENOTCONNError]():
            writer.write(self.value[RecvENOTCONNError])
        elif self.value.isa[RecvENOTSOCKError]():
            writer.write(self.value[RecvENOTSOCKError])
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
        RecvfromEAGAINError,
        RecvfromEBADFError,
        RecvfromECONNRESETError,
        RecvfromEINTRError,
        RecvfromEINVALError,
        RecvfromEIOError,
        RecvfromENOBUFSError,
        RecvfromENOMEMError,
        RecvfromENOTCONNError,
        RecvfromENOTSOCKError,
        RecvfromEOPNOTSUPPError,
        RecvfromETIMEDOUTError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: RecvfromEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromEIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromEOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, value: RecvfromETIMEDOUTError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[RecvfromEAGAINError]():
            writer.write(self.value[RecvfromEAGAINError])
        elif self.value.isa[RecvfromEBADFError]():
            writer.write(self.value[RecvfromEBADFError])
        elif self.value.isa[RecvfromECONNRESETError]():
            writer.write(self.value[RecvfromECONNRESETError])
        elif self.value.isa[RecvfromEINTRError]():
            writer.write(self.value[RecvfromEINTRError])
        elif self.value.isa[RecvfromEINVALError]():
            writer.write(self.value[RecvfromEINVALError])
        elif self.value.isa[RecvfromEIOError]():
            writer.write(self.value[RecvfromEIOError])
        elif self.value.isa[RecvfromENOBUFSError]():
            writer.write(self.value[RecvfromENOBUFSError])
        elif self.value.isa[RecvfromENOMEMError]():
            writer.write(self.value[RecvfromENOMEMError])
        elif self.value.isa[RecvfromENOTCONNError]():
            writer.write(self.value[RecvfromENOTCONNError])
        elif self.value.isa[RecvfromENOTSOCKError]():
            writer.write(self.value[RecvfromENOTSOCKError])
        elif self.value.isa[RecvfromEOPNOTSUPPError]():
            writer.write(self.value[RecvfromEOPNOTSUPPError])
        elif self.value.isa[RecvfromETIMEDOUTError]():
            writer.write(self.value[RecvfromETIMEDOUTError])
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
        SendEAGAINError,
        SendEBADFError,
        SendECONNREFUSEDError,
        SendECONNRESETError,
        SendEDESTADDRREQError,
        SendEFAULTError,
        SendEINTRError,
        SendEINVALError,
        SendEISCONNError,
        SendENOBUFSError,
        SendENOMEMError,
        SendENOTCONNError,
        SendENOTSOCKError,
        SendEOPNOTSUPPError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SendEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendECONNREFUSEDError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEDESTADDRREQError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendEOPNOTSUPPError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SendEAGAINError]():
            writer.write(self.value[SendEAGAINError])
        elif self.value.isa[SendEBADFError]():
            writer.write(self.value[SendEBADFError])
        elif self.value.isa[SendECONNREFUSEDError]():
            writer.write(self.value[SendECONNREFUSEDError])
        elif self.value.isa[SendECONNRESETError]():
            writer.write(self.value[SendECONNRESETError])
        elif self.value.isa[SendEDESTADDRREQError]():
            writer.write(self.value[SendEDESTADDRREQError])
        elif self.value.isa[SendEFAULTError]():
            writer.write(self.value[SendEFAULTError])
        elif self.value.isa[SendEINTRError]():
            writer.write(self.value[SendEINTRError])
        elif self.value.isa[SendEINVALError]():
            writer.write(self.value[SendEINVALError])
        elif self.value.isa[SendEISCONNError]():
            writer.write(self.value[SendEISCONNError])
        elif self.value.isa[SendENOBUFSError]():
            writer.write(self.value[SendENOBUFSError])
        elif self.value.isa[SendENOMEMError]():
            writer.write(self.value[SendENOMEMError])
        elif self.value.isa[SendENOTCONNError]():
            writer.write(self.value[SendENOTCONNError])
        elif self.value.isa[SendENOTSOCKError]():
            writer.write(self.value[SendENOTSOCKError])
        elif self.value.isa[SendEOPNOTSUPPError]():
            writer.write(self.value[SendEOPNOTSUPPError])
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
        SendtoEACCESError,
        SendtoEAFNOSUPPORTError,
        SendtoEAGAINError,
        SendtoEBADFError,
        SendtoECONNRESETError,
        SendtoEDESTADDRREQError,
        SendtoEHOSTUNREACHError,
        SendtoEINTRError,
        SendtoEINVALError,
        SendtoEIOError,
        SendtoEISCONNError,
        SendtoELOOPError,
        SendtoEMSGSIZEError,
        SendtoENAMETOOLONGError,
        SendtoENETDOWNError,
        SendtoENETUNREACHError,
        SendtoENOBUFSError,
        SendtoENOMEMError,
        SendtoENOTCONNError,
        SendtoENOTSOCKError,
        SendtoEPIPEError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SendtoEACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEAGAINError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoECONNRESETError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEDESTADDRREQError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEHOSTUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEINTRError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEIOError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEISCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoELOOPError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEMSGSIZEError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENAMETOOLONGError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENETDOWNError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENETUNREACHError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENOMEMError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, value: SendtoEPIPEError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SendtoEACCESError]():
            writer.write(self.value[SendtoEACCESError])
        elif self.value.isa[SendtoEAFNOSUPPORTError]():
            writer.write(self.value[SendtoEAFNOSUPPORTError])
        elif self.value.isa[SendtoEAGAINError]():
            writer.write(self.value[SendtoEAGAINError])
        elif self.value.isa[SendtoEBADFError]():
            writer.write(self.value[SendtoEBADFError])
        elif self.value.isa[SendtoECONNRESETError]():
            writer.write(self.value[SendtoECONNRESETError])
        elif self.value.isa[SendtoEDESTADDRREQError]():
            writer.write(self.value[SendtoEDESTADDRREQError])
        elif self.value.isa[SendtoEHOSTUNREACHError]():
            writer.write(self.value[SendtoEHOSTUNREACHError])
        elif self.value.isa[SendtoEINTRError]():
            writer.write(self.value[SendtoEINTRError])
        elif self.value.isa[SendtoEINVALError]():
            writer.write(self.value[SendtoEINVALError])
        elif self.value.isa[SendtoEIOError]():
            writer.write(self.value[SendtoEIOError])
        elif self.value.isa[SendtoEISCONNError]():
            writer.write(self.value[SendtoEISCONNError])
        elif self.value.isa[SendtoELOOPError]():
            writer.write(self.value[SendtoELOOPError])
        elif self.value.isa[SendtoEMSGSIZEError]():
            writer.write(self.value[SendtoEMSGSIZEError])
        elif self.value.isa[SendtoENAMETOOLONGError]():
            writer.write(self.value[SendtoENAMETOOLONGError])
        elif self.value.isa[SendtoENETDOWNError]():
            writer.write(self.value[SendtoENETDOWNError])
        elif self.value.isa[SendtoENETUNREACHError]():
            writer.write(self.value[SendtoENETUNREACHError])
        elif self.value.isa[SendtoENOBUFSError]():
            writer.write(self.value[SendtoENOBUFSError])
        elif self.value.isa[SendtoENOMEMError]():
            writer.write(self.value[SendtoENOMEMError])
        elif self.value.isa[SendtoENOTCONNError]():
            writer.write(self.value[SendtoENOTCONNError])
        elif self.value.isa[SendtoENOTSOCKError]():
            writer.write(self.value[SendtoENOTSOCKError])
        elif self.value.isa[SendtoEPIPEError]():
            writer.write(self.value[SendtoEPIPEError])
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
        SetsockoptEBADFError,
        SetsockoptEFAULTError,
        SetsockoptEINVALError,
        SetsockoptENOPROTOOPTError,
        SetsockoptENOTSOCKError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SetsockoptEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: SetsockoptEFAULTError):
        self.value = value

    @implicit
    fn __init__(out self, value: SetsockoptEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: SetsockoptENOPROTOOPTError):
        self.value = value

    @implicit
    fn __init__(out self, value: SetsockoptENOTSOCKError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SetsockoptEBADFError]():
            writer.write(self.value[SetsockoptEBADFError])
        elif self.value.isa[SetsockoptEFAULTError]():
            writer.write(self.value[SetsockoptEFAULTError])
        elif self.value.isa[SetsockoptEINVALError]():
            writer.write(self.value[SetsockoptEINVALError])
        elif self.value.isa[SetsockoptENOPROTOOPTError]():
            writer.write(self.value[SetsockoptENOPROTOOPTError])
        elif self.value.isa[SetsockoptENOTSOCKError]():
            writer.write(self.value[SetsockoptENOTSOCKError])
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

    comptime type = Variant[ShutdownEBADFError, ShutdownEINVALError, ShutdownENOTCONNError, ShutdownENOTSOCKError]
    var value: Self.type

    @implicit
    fn __init__(out self, value: ShutdownEBADFError):
        self.value = value

    @implicit
    fn __init__(out self, value: ShutdownEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: ShutdownENOTCONNError):
        self.value = value

    @implicit
    fn __init__(out self, value: ShutdownENOTSOCKError):
        self.value = value

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[ShutdownEBADFError]():
            writer.write(self.value[ShutdownEBADFError])
        elif self.value.isa[ShutdownEINVALError]():
            writer.write(self.value[ShutdownEINVALError])
        elif self.value.isa[ShutdownENOTCONNError]():
            writer.write(self.value[ShutdownENOTCONNError])
        elif self.value.isa[ShutdownENOTSOCKError]():
            writer.write(self.value[ShutdownENOTSOCKError])

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
        SocketEACCESError,
        SocketEAFNOSUPPORTError,
        SocketEINVALError,
        SocketEMFILEError,
        SocketENFILEError,
        SocketENOBUFSError,
        SocketEPROTONOSUPPORTError,
        Error,
    ]
    var value: Self.type

    @implicit
    fn __init__(out self, value: SocketEACCESError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketEAFNOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketEINVALError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketEMFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketENFILEError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketENOBUFSError):
        self.value = value

    @implicit
    fn __init__(out self, value: SocketEPROTONOSUPPORTError):
        self.value = value

    @implicit
    fn __init__(out self, var value: Error):
        self.value = value^

    fn write_to[W: Writer, //](self, mut writer: W):
        if self.value.isa[SocketEACCESError]():
            writer.write(self.value[SocketEACCESError])
        elif self.value.isa[SocketEAFNOSUPPORTError]():
            writer.write(self.value[SocketEAFNOSUPPORTError])
        elif self.value.isa[SocketEINVALError]():
            writer.write(self.value[SocketEINVALError])
        elif self.value.isa[SocketEMFILEError]():
            writer.write(self.value[SocketEMFILEError])
        elif self.value.isa[SocketENFILEError]():
            writer.write(self.value[SocketENFILEError])
        elif self.value.isa[SocketENOBUFSError]():
            writer.write(self.value[SocketENOBUFSError])
        elif self.value.isa[SocketEPROTONOSUPPORTError]():
            writer.write(self.value[SocketEPROTONOSUPPORTError])
        elif self.value.isa[Error]():
            writer.write(self.value[Error])

    fn isa[T: AnyType](self) -> Bool:
        return self.value.isa[T]()

    fn __getitem__[T: AnyType](self) -> ref [self.value] T:
        return self.value[T]

    fn __str__(self) -> String:
        return String.write(self)
