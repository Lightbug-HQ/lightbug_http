"""
Auto-generated typed errors for socket operations.
Generated from socket.mojo error handling patterns.
Follows the pattern from typed_errors.mojo.
"""

from lightbug_http.utils.error import CustomError
from utils import Variant


# Accept errors
@fieldwise_init
struct AcceptEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EINTR): The system call was interrupted by a signal that was caught before a valid connection arrived."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and no connections are present to be accepted."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptECONNABORTEDError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (ECONNABORTED): A connection has been aborted."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EFAULT): The address argument is not in a writable part of the user address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EINVAL): Socket is not listening for connections, or address_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEMFILEError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EMFILE): The per-process limit of open file descriptors has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptENFILEError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (ENFILE): The system limit on the total number of open files has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (ENOBUFS): Not enough free memory."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEOPNOTSUPPError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EOPNOTSUPP): The referenced socket is not of type SOCK_STREAM."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEPERMError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EPERM): Firewall rules forbid connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct AcceptEPROTOError(CustomError, TrivialRegisterPassable):
    comptime message = "accept (EPROTO): Protocol error."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Bind errors
@fieldwise_init
struct BindEACCESError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (EACCES): The address is protected, and the user is not the superuser."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindEADDRINUSEError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (EADDRINUSE): The given address is already in use."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (EFAULT): address points outside the user's accessible address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (EINVAL): The socket is already bound to an address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindELOOPError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (ELOOP): Too many symbolic links were encountered in resolving address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindENAMETOOLONGError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (ENAMETOOLONG): address is too long."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindENOMEMError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (ENOMEM): Insufficient kernel memory was available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct BindENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "bind (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Close errors
@fieldwise_init
struct CloseEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "close (EBADF): The file_descriptor argument is not a valid open file descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct CloseEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "close (EINTR): The close() function was interrupted by a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct CloseEIOError(CustomError, TrivialRegisterPassable):
    comptime message = "close (EIO): An I/O error occurred while reading from or writing to the file system."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct CloseENOSPCError(CustomError, TrivialRegisterPassable):
    comptime message = "close (ENOSPC or EDQUOT): On NFS, these errors are not normally reported against the first write which exceeds the available storage space, but instead against a subsequent write, fsync, or close."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Connect errors
@fieldwise_init
struct ConnectEACCESError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EACCES): Write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEADDRINUSEError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EADDRINUSE): Local address is already in use."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEAFNOSUPPORTError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EAFNOSUPPORT): The passed address didn't have the correct address family in its sa_family field."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EAGAIN): No more free local ports or insufficient entries in the routing cache."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEALREADYError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EALREADY): The socket is nonblocking and a previous connection attempt has not yet been completed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EBADF): The file descriptor is not a valid index in the descriptor table."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectECONNREFUSEDError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (ECONNREFUSED): No-one listening on the remote address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EFAULT): The socket structure address is outside the user's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEINPROGRESSError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EINPROGRESS): The socket is nonblocking and the connection cannot be completed immediately. It is possible to select(2) or poll(2) for completion by selecting the socket for writing. After select(2) indicates writability, use getsockopt(2) to read the SO_ERROR option at level SOL_SOCKET to determine whether connect() completed successfully (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error codes listed here, explaining the reason for the failure)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EINTR): The system call was interrupted by a signal that was caught."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectEISCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (EISCONN): The socket is already connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectENETUNREACHError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (ENETUNREACH): Network is unreachable."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ConnectETIMEDOUTError(CustomError, TrivialRegisterPassable):
    comptime message = "connect (ETIMEDOUT): Timeout while attempting connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getpeername errors
@fieldwise_init
struct GetpeernameEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetpeernameEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (EFAULT): The address argument points to memory not in a valid part of the process address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetpeernameEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (EINVAL): address_len is invalid (e.g., is negative)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetpeernameENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetpeernameENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetpeernameENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "getpeername (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getsockname errors
@fieldwise_init
struct GetsocknameEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockname (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsocknameEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockname (EFAULT): The address argument points to memory not in a valid part of the process address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsocknameEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockname (EINVAL): address_len is invalid (e.g., is negative)."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsocknameENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockname (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsocknameENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockname (ENOTSOCK): The argument socket is a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Getsockopt errors
@fieldwise_init
struct GetsockoptEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockopt (EBADF): The argument socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsockoptEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockopt (EFAULT): The argument option_value points outside the process's allocated address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsockoptEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockopt (EINVAL): The argument option_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsockoptENOPROTOOPTError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockopt (ENOPROTOOPT): The option is unknown at the level indicated."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct GetsockoptENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "getsockopt (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Listen errors
@fieldwise_init
struct ListenEADDRINUSEError(CustomError, TrivialRegisterPassable):
    comptime message = "listen (EADDRINUSE): Another socket is already listening on the same port."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ListenEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "listen (EBADF): socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ListenENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "listen (ENOTSOCK): socket is a descriptor for a file, not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ListenEOPNOTSUPPError(CustomError, TrivialRegisterPassable):
    comptime message = "listen (EOPNOTSUPP): The socket is not of a type that supports the listen() operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Recv errors
@fieldwise_init
struct RecvEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the receive operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvECONNREFUSEDError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (ECONNREFUSED): The remote host refused to allow the network connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (EFAULT): buffer points outside the process's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (EINTR): The receive was interrupted by delivery of a signal before any data were available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "recv (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Recvfrom errors
@fieldwise_init
struct RecvfromEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the receive operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromECONNRESETError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ECONNRESET): A connection was forcibly closed by a peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EINTR): The receive was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromEIOError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EIO): An I/O error occurred."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromENOMEMError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ENOMEM): Insufficient memory was available to fulfill the request."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromEOPNOTSUPPError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (EOPNOTSUPP): The specified flags are not supported for this socket type or protocol."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct RecvfromETIMEDOUTError(CustomError, TrivialRegisterPassable):
    comptime message = "recvfrom (ETIMEDOUT): The connection timed out."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Send errors
@fieldwise_init
struct SendEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EAGAIN/EWOULDBLOCK): The socket is marked nonblocking and the send operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendECONNREFUSEDError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ECONNREFUSED): The remote host refused to allow the network connection."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendECONNRESETError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ECONNRESET): Connection reset by peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEDESTADDRREQError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EDESTADDRREQ): The socket is not connection-mode, and no peer address is set."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EFAULT): buffer points outside the process's address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EINTR): The send was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEISCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EISCONN): The connection-mode socket was connected already but a recipient was specified."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ENOBUFS): The output queue for a network interface was full."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendENOMEMError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ENOMEM): No memory available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "send (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendEOPNOTSUPPError(CustomError, TrivialRegisterPassable):
    comptime message = "send (EOPNOTSUPP): Some bit in the flags argument is inappropriate for the socket type."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Sendto errors
@fieldwise_init
struct SendtoEACCESError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EACCES): Write access to the named socket is denied."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEAFNOSUPPORTError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EAFNOSUPPORT): Addresses in the specified address family cannot be used with this socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEAGAINError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EAGAIN/EWOULDBLOCK): The socket's file descriptor is marked O_NONBLOCK and the requested operation would block."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoECONNRESETError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ECONNRESET): A connection was forcibly closed by a peer."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEDESTADDRREQError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EDESTADDRREQ): The socket is not connection-mode and does not have its peer address set, and no destination address was specified."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEHOSTUNREACHError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EHOSTUNREACH): The destination host cannot be reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEINTRError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EINTR): The send was interrupted by delivery of a signal."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEIOError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EIO): An I/O error occurred."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEISCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EISCONN): A destination address was specified and the socket is already connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoELOOPError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ELOOP): More than SYMLOOP_MAX symbolic links were encountered during resolution of the pathname in the socket address."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEMSGSIZEError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EMSGSIZE): The message is too large to be sent all at once, as the socket requires."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENAMETOOLONGError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENAMETOOLONG): The length of a pathname exceeds PATH_MAX."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENETDOWNError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENETDOWN): The local network interface used to reach the destination is down."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENETUNREACHError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENETUNREACH): No route to the network is present."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENOBUFS): Insufficient resources were available in the system to perform the operation."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENOMEMError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENOMEM): Insufficient memory was available to fulfill the request."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SendtoEPIPEError(CustomError, TrivialRegisterPassable):
    comptime message = "sendto (EPIPE): The socket is shut down for writing, or the socket is connection-mode and is no longer connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Setsockopt errors
@fieldwise_init
struct SetsockoptEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "setsockopt (EBADF): The argument socket is not a valid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SetsockoptEFAULTError(CustomError, TrivialRegisterPassable):
    comptime message = "setsockopt (EFAULT): The argument option_value points outside the process's allocated address space."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SetsockoptEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "setsockopt (EINVAL): The argument option_len is invalid."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SetsockoptENOPROTOOPTError(CustomError, TrivialRegisterPassable):
    comptime message = "setsockopt (ENOPROTOOPT): The option is unknown at the level indicated."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SetsockoptENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "setsockopt (ENOTSOCK): The argument socket is not a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Shutdown errors
@fieldwise_init
struct ShutdownEBADFError(CustomError, TrivialRegisterPassable):
    comptime message = "shutdown (EBADF): The argument socket is an invalid descriptor."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ShutdownEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "shutdown (EINVAL): Invalid argument passed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ShutdownENOTCONNError(CustomError, TrivialRegisterPassable):
    comptime message = "shutdown (ENOTCONN): The socket is not connected."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct ShutdownENOTSOCKError(CustomError, TrivialRegisterPassable):
    comptime message = "shutdown (ENOTSOCK): The file descriptor is not associated with a socket."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


# Socket errors
@fieldwise_init
struct SocketEACCESError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (EACCES): Permission to create a socket of the specified type and/or protocol is denied."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketEAFNOSUPPORTError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (EAFNOSUPPORT): The implementation does not support the specified address family."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketEINVALError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (EINVAL): Invalid flags in type, unknown protocol, or protocol family not available."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketEMFILEError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (EMFILE): The per-process limit on the number of open file descriptors has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketENFILEError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (ENFILE): The system-wide limit on the total number of open files has been reached."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketENOBUFSError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (ENOBUFS): Insufficient memory is available. The socket cannot be created until sufficient resources are freed."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


@fieldwise_init
struct SocketEPROTONOSUPPORTError(CustomError, TrivialRegisterPassable):
    comptime message = "socket (EPROTONOSUPPORT): The protocol type or the specified protocol is not supported within this domain."

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(Self.message)

    fn __str__(self) -> String:
        return Self.message


comptime AcceptError = Variant[
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


comptime BindError = Variant[
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


comptime CloseError = Variant[CloseEBADFError, CloseEINTRError, CloseEIOError, CloseENOSPCError]


comptime ConnectError = Variant[
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


comptime GetpeernameError = Variant[
    GetpeernameEBADFError,
    GetpeernameEFAULTError,
    GetpeernameEINVALError,
    GetpeernameENOBUFSError,
    GetpeernameENOTCONNError,
    GetpeernameENOTSOCKError,
]


comptime GetsocknameError = Variant[
    GetsocknameEBADFError,
    GetsocknameEFAULTError,
    GetsocknameEINVALError,
    GetsocknameENOBUFSError,
    GetsocknameENOTSOCKError,
]


comptime GetsockoptError = Variant[
    GetsockoptEBADFError,
    GetsockoptEFAULTError,
    GetsockoptEINVALError,
    GetsockoptENOPROTOOPTError,
    GetsockoptENOTSOCKError,
    Error,
]


comptime ListenError = Variant[ListenEADDRINUSEError, ListenEBADFError, ListenENOTSOCKError, ListenEOPNOTSUPPError]


comptime RecvError = Variant[
    RecvEAGAINError,
    RecvEBADFError,
    RecvECONNREFUSEDError,
    RecvEFAULTError,
    RecvEINTRError,
    RecvENOTCONNError,
    RecvENOTSOCKError,
    Error,
]


comptime RecvfromError = Variant[
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


comptime SendError = Variant[
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


comptime SendtoError = Variant[
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


comptime SetsockoptError = Variant[
    SetsockoptEBADFError,
    SetsockoptEFAULTError,
    SetsockoptEINVALError,
    SetsockoptENOPROTOOPTError,
    SetsockoptENOTSOCKError,
    Error,
]


comptime ShutdownError = Variant[ShutdownEBADFError, ShutdownEINVALError, ShutdownENOTCONNError, ShutdownENOTSOCKError]


comptime SocketError = Variant[
    SocketEACCESError,
    SocketEAFNOSUPPORTError,
    SocketEINVALError,
    SocketEMFILEError,
    SocketENFILEError,
    SocketENOBUFSError,
    SocketEPROTONOSUPPORTError,
    Error,
]
