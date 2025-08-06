from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call
from sys.ffi import external_call, c_int, c_long, c_size_t, c_uchar
from sys.info import sizeof, os_is_linux, os_is_macos, num_logical_cores
from memory import memcmp, UnsafePointer, stack_allocation
from sys.info import sizeof
from time import sleep
from lightbug_http.external.small_time import now
from algorithm import parallelize
from memory import memset_zero, memcpy
from lightbug_http._libc import get_errno, sockaddr, socklen_t, c_ssize_t
from sys.ffi import external_call, c_int, c_uint, c_ushort, c_size_t
from sys.info import sizeof, is_big_endian, is_little_endian
from memory import UnsafePointer, memset_zero
from utils import StaticTuple

# Below is a straightforward translation of the Rust FAF (Fast As Fuck) code: 
# Courtesy of the original author @errantmind
# https://github.com/errantmind/faf/blob/master/src/epoll.rs

# ===----------------------------------------------------------------------=== #
# Epoll Constants
# ===----------------------------------------------------------------------=== #

# (dummy values - should match actual system constants)
alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUF_SIZE = 1024
alias RES_BUF_SIZE = 35
alias MAX_CONN = 1024

alias EPOLL_TIMEOUT_BLOCKING = -1
alias EPOLL_TIMEOUT_IMMEDIATE_RETURN = 0
alias EAGAIN = 11
alias EINTR = 4
alias EACCES = 13
alias EINVAL = 22
alias EBADF = 9
alias EEXIST = 17
alias ENFILE = 23
alias EMFILE = 24
alias ENOMEM = 12
alias ENOSYS = 38
alias EPERM = 1
alias EWOULDBLOCK = 11
alias ECONNABORTED = 103
alias ENOTCONN = 107
alias ENOTSOCK = 88
alias EOPNOTSUPP = 45
alias ECONNREFUSED = 111
alias ECONNRESET = 104
alias EFAULT = 14
alias EPIPE = 32
alias ESRCH = 3
alias ENOENT = 2
alias ENOSPC = 28

# Epoll events
alias EPOLLIN = 0x001
alias EPOLLPRI = 0x002
alias EPOLLOUT = 0x004
alias EPOLLRDNORM = 0x040
alias EPOLLRDBAND = 0x080
alias EPOLLWRNORM = 0x100
alias EPOLLWRBAND = 0x200
alias EPOLLMSG = 0x400
alias EPOLLERR = 0x008
alias EPOLLHUP = 0x010
alias EPOLLRDHUP = 0x2000
alias EPOLLEXCLUSIVE = 1 << 28
alias EPOLLWAKEUP = 1 << 29
alias EPOLLONESHOT = 1 << 30
alias EPOLLET = 1 << 31

# Epoll operations
alias EPOLL_CTL_ADD = 1
alias EPOLL_CTL_DEL = 2
alias EPOLL_CTL_MOD = 3

# Priority constants
alias PRIO_PROCESS = 0
alias PRIO_PGRP = 1
alias PRIO_USER = 2

# Clone flags
alias CLONE_FILES = 0x00000400

# Syscall numbers (Linux x86_64)
alias SYS_SETPRIORITY = 141
alias SYS_UNSHARE = 272
alias SYS_NANOSLEEP = 35
alias SYS_EPOLL_CREATE1 = 291
alias SYS_EPOLL_CTL = 233
alias SYS_EPOLL_WAIT = 232
alias SYS_ACCEPT = 43
alias SYS_RECVFROM = 45
alias SYS_SENDTO = 44

# ===----------------------------------------------------------------------=== #
# Time structures
# ===----------------------------------------------------------------------=== #

@fieldwise_init
@register_passable("trivial")
struct timespec:
    var tv_sec: Int64   # seconds
    var tv_nsec: Int64  # nanoseconds

# ===----------------------------------------------------------------------=== #
# Epoll structures
# ===----------------------------------------------------------------------=== #

@fieldwise_init
@register_passable("trivial") 
struct epoll_data:
    var u64: UInt64  # We'll use this as our union - can cast to/from fd, ptr, etc.

@fieldwise_init
@register_passable("trivial")
struct epoll_event:
    var events: UInt32
    var data: epoll_data

@fieldwise_init
@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]

alias AlignedEpollEventsTuple = StaticTuple[epoll_event, MAX_EPOLL_EVENTS_RETURNED]

@fieldwise_init
@register_passable("trivial")
struct AlignedEpollEvents:
    var data: AlignedEpollEventsTuple

@fieldwise_init
struct AlignedEpollEvent:
    var data: epoll_event

alias ReqBufAlignedTuple = StaticTuple[UInt8, REQ_BUF_SIZE * MAX_CONN]

@fieldwise_init
@register_passable("trivial")
struct ReqBufAligned:
    var data: ReqBufAlignedTuple

alias ResBufAlignedTuple = StaticTuple[UInt8, RES_BUF_SIZE]

@fieldwise_init
@register_passable("trivial")
struct ResBufAligned:
    var data: ResBufAlignedTuple

# ===----------------------------------------------------------------------=== #
# Syscall implementations
# ===----------------------------------------------------------------------=== #

fn sys_call_setpriority(which: Int, who: Int, priority: Int) -> Int:
    """Set process priority using setpriority syscall."""
    return Int(external_call["syscall", c_int, Int, Int, Int, Int](
        SYS_SETPRIORITY, which, who, priority
    ))

fn sys_call_unshare(flags: Int) -> Int:
    """Unshare system resources using unshare syscall."""
    return Int(external_call["syscall", c_int, Int, Int](
        SYS_UNSHARE, flags
    ))

fn sys_call_nanosleep(req: UnsafePointer[timespec], rem: UnsafePointer[timespec]) -> Int:
    """Sleep for specified time using nanosleep syscall."""
    return Int(external_call["syscall", c_int, Int, UnsafePointer[timespec], UnsafePointer[timespec]](
        SYS_NANOSLEEP, req, rem
    ))

fn sys_call_epoll_create1(flags: Int) -> Int:
    """Create epoll instance using epoll_create1 syscall."""
    return Int(external_call["syscall", c_int, Int, Int](
        SYS_EPOLL_CREATE1, flags
    ))

fn sys_call_epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) -> Int:
    """Control epoll instance using epoll_ctl syscall."""
    return Int(external_call["syscall", c_int, Int, Int, Int, Int, UnsafePointer[epoll_event]](
        SYS_EPOLL_CTL, epfd, op, fd, event
    ))

fn sys_call_epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) -> Int:
    """Wait for epoll events using epoll_wait syscall."""
    return Int(external_call["syscall", c_int, Int, Int, UnsafePointer[epoll_event], Int, Int](
        SYS_EPOLL_WAIT, epfd, events, maxevents, timeout
    ))

fn sys_call_accept(sockfd: Int, addr: UnsafePointer[sockaddr], addrlen: UnsafePointer[socklen_t]) -> Int:
    """Accept connection using accept syscall."""
    return Int(external_call["syscall", c_int, Int, Int, UnsafePointer[sockaddr], UnsafePointer[socklen_t]](
        SYS_ACCEPT, sockfd, addr, addrlen
    ))

fn sys_call_recvfrom(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, src_addr: UnsafePointer[sockaddr], addrlen: UnsafePointer[socklen_t]) -> Int:
    """Receive data using recvfrom syscall."""
    return Int(external_call["syscall", c_ssize_t, Int, Int, UnsafePointer[UInt8], Int, Int, UnsafePointer[sockaddr], UnsafePointer[socklen_t]](
        SYS_RECVFROM, sockfd, buf, len, flags, src_addr, addrlen
    ))

fn sys_call_sendto(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, dest_addr: UnsafePointer[sockaddr], addrlen: socklen_t) -> Int:
    """Send data using sendto syscall."""
    return Int(external_call["syscall", c_ssize_t, Int, Int, UnsafePointer[UInt8], Int, Int, UnsafePointer[sockaddr], socklen_t](
        SYS_SENDTO, sockfd, buf, len, flags, dest_addr, addrlen
    ))

# ===----------------------------------------------------------------------=== #
# Higher-level wrapper functions with error handling
# ===----------------------------------------------------------------------=== #

fn setpriority(which: Int, who: Int, priority: Int) raises:
    """Set process priority with error handling."""
    var result = sys_call_setpriority(which, who, priority)
    if result == -1:
        var errno = get_errno()
        if errno == EACCES:
            raise Error("setpriority: Permission denied")
        elif errno == EINVAL:
            raise Error("setpriority: Invalid argument")
        elif errno == EPERM:
            raise Error("setpriority: Operation not permitted")
        elif errno == ESRCH:
            raise Error("setpriority: No such process")
        else:
            raise Error("setpriority failed with errno: " + String(errno))

fn unshare(flags: Int) raises:
    """Unshare system resources with error handling."""
    var result = sys_call_unshare(flags)
    if result == -1:
        var errno = get_errno()
        if errno == EINVAL:
            raise Error("unshare: Invalid flags")
        elif errno == ENOMEM:
            raise Error("unshare: Out of memory")
        elif errno == ENOSYS:
            raise Error("unshare: Function not implemented")
        elif errno == EPERM:
            raise Error("unshare: Operation not permitted")
        else:
            raise Error("unshare failed with errno: " + String(errno))

fn nanosleep(seconds: Float64) raises:
    """Sleep for specified seconds using nanosleep."""
    var req = timespec(Int64(seconds), Int64((seconds - Float64(Int64(seconds))) * 1_000_000_000))
    var rem = timespec(0, 0)
    
    var result = sys_call_nanosleep(UnsafePointer(to=req), UnsafePointer(to=rem))
    if result == -1:
        var errno = get_errno()
        if errno == EINTR:
            raise Error("nanosleep: Interrupted by signal")
        elif errno == EINVAL:
            raise Error("nanosleep: Invalid time specification")
        else:
            raise Error("nanosleep failed with errno: " + String(errno))

fn epoll_create1(flags: Int) raises -> Int:
    """Create epoll instance with error handling."""
    var result = sys_call_epoll_create1(flags)
    if result == -1:
        var errno = get_errno()
        if errno == EINVAL:
            raise Error("epoll_create1: Invalid flags")
        elif errno == EMFILE:
            raise Error("epoll_create1: Too many file descriptors")
        elif errno == ENFILE:
            raise Error("epoll_create1: System file table overflow")
        elif errno == ENOMEM:
            raise Error("epoll_create1: Out of memory")
        else:
            raise Error("epoll_create1 failed with errno: " + String(errno))
    return result

fn epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) raises:
    """Control epoll instance with error handling."""
    var result = sys_call_epoll_ctl(epfd, op, fd, event)
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("epoll_ctl: Bad file descriptor")
        elif errno == EEXIST:
            raise Error("epoll_ctl: File descriptor already exists")
        elif errno == EINVAL:
            raise Error("epoll_ctl: Invalid parameters")
        elif errno == ENOENT:
            raise Error("epoll_ctl: File descriptor not found")
        elif errno == ENOMEM:
            raise Error("epoll_ctl: Out of memory")
        elif errno == ENOSPC:
            raise Error("epoll_ctl: No space for new descriptor")
        elif errno == EPERM:
            raise Error("epoll_ctl: Operation not permitted")
        else:
            raise Error("epoll_ctl failed with errno: " + String(errno))

fn epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) raises -> Int:
    """Wait for epoll events with error handling."""
    var result = sys_call_epoll_wait(epfd, events, maxevents, timeout)
    if result == -1:
        var errno = get_errno()
        if errno == EBADF:
            raise Error("epoll_wait: Bad file descriptor")
        elif errno == EFAULT:
            raise Error("epoll_wait: Invalid memory address")
        elif errno == EINTR:
            raise Error("epoll_wait: Interrupted by signal")
        elif errno == EINVAL:
            raise Error("epoll_wait: Invalid parameters")
        else:
            raise Error("epoll_wait failed with errno: " + String(errno))
    return result

fn accept_connection(sockfd: Int) raises -> Int:
    """Accept connection with error handling (no address info)."""
    var result = sys_call_accept(sockfd, UnsafePointer[sockaddr](), UnsafePointer[socklen_t]())
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error("accept: Would block")
        elif errno == EBADF:
            raise Error("accept: Bad file descriptor")
        elif errno == ECONNABORTED:
            raise Error("accept: Connection aborted")
        elif errno == EINTR:
            raise Error("accept: Interrupted by signal")
        elif errno == EINVAL:
            raise Error("accept: Invalid socket state")
        elif errno == EMFILE:
            raise Error("accept: Too many open files")
        elif errno == ENFILE:
            raise Error("accept: System file table full")
        elif errno == ENOTSOCK:
            raise Error("accept: Not a socket")
        elif errno == EOPNOTSUPP:
            raise Error("accept: Operation not supported")
        else:
            raise Error("accept failed with errno: " + String(errno))
    return result

fn recv_from(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int = 0) raises -> Int:
    """Receive data from socket with error handling."""
    var result = sys_call_recvfrom(sockfd, buf, len, flags, UnsafePointer[sockaddr](), UnsafePointer[socklen_t]())
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error("recvfrom: Would block")
        elif errno == EBADF:
            raise Error("recvfrom: Bad file descriptor")
        elif errno == ECONNREFUSED:
            raise Error("recvfrom: Connection refused")
        elif errno == ENOTCONN:
            raise Error("recvfrom: Socket not connected")
        elif errno == ENOTSOCK:
            raise Error("recvfrom: Not a socket")
        elif errno == EINTR:
            raise Error("recvfrom: Interrupted by signal")
        elif errno == EINVAL:
            raise Error("recvfrom: Invalid argument")
        else:
            raise Error("recvfrom failed with errno: " + String(errno))
    return result

fn send_to(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int = 0) raises -> Int:
    """Send data to socket with error handling."""
    var result = sys_call_sendto(sockfd, buf, len, flags, UnsafePointer[sockaddr](), 0)
    if result == -1:
        var errno = get_errno()
        if Int(errno) in [EAGAIN, EWOULDBLOCK]:
            raise Error("sendto: Would block")
        elif errno == EBADF:
            raise Error("sendto: Bad file descriptor")
        elif errno == ECONNRESET:
            raise Error("sendto: Connection reset")
        elif errno == ENOTCONN:
            raise Error("sendto: Socket not connected")
        elif errno == ENOTSOCK:
            raise Error("sendto: Not a socket")
        elif errno == EPIPE:
            raise Error("sendto: Broken pipe")
        elif errno == EINTR:
            raise Error("sendto: Interrupted by signal")
        elif errno == EINVAL:
            raise Error("sendto: Invalid argument")
        else:
            raise Error("sendto failed with errno: " + String(errno))
    return result

# ===----------------------------------------------------------------------=== #
# HTTP date update loop
# ===----------------------------------------------------------------------=== #

fn get_http_date(http_date: UnsafePointer[StaticTuple[UInt8, 35]], HTTP_DATE: AlignedHttpDate) raises:
    """Get the current HTTP date."""
    var current_time = now()
    var http_date_str = current_time.format("ddd, DD MMM YYYY HH:mm:ss [GMT]")
    var http_date_len = len(http_date_str)
    memcpy(UnsafePointer(to=HTTP_DATE.data[0]), http_date_str.unsafe_ptr(), http_date_len)



# ===----------------------------------------------------------------------=== #
# Constants
# ===----------------------------------------------------------------------=== #

alias _SC_NPROCESSORS_ONLN: c_int = 84
alias POINTER_WIDTH_IN_BITS = sizeof[UnsafePointer[UInt8]]() * 8
alias CPU_SET_LEN = 1024 // POINTER_WIDTH_IN_BITS
alias CURRENT_THREAD_CONTROL_PID: c_int = 0

# ===----------------------------------------------------------------------=== #
# CPU Set Structure
# ===----------------------------------------------------------------------=== #

@fieldwise_init
@register_passable("trivial")
struct cpu_set_t:
    """CPU affinity set structure."""
    var data: StaticTuple[UInt64, CPU_SET_LEN]

# ===----------------------------------------------------------------------=== #
# External C Functions
# ===----------------------------------------------------------------------=== #

fn _sysconf(name: c_int) -> c_long:
    """Get system configuration information."""
    return external_call["sysconf", c_long, c_int](name)

fn _sched_getaffinity(pid: c_int, cpusetsize: c_size_t, cpuset: UnsafePointer[cpu_set_t]) -> c_int:
    """Get CPU affinity for a process/thread."""
    return external_call["sched_getaffinity", c_int, c_int, c_size_t, UnsafePointer[cpu_set_t]](
        pid, cpusetsize, cpuset
    )

fn _sched_setaffinity(pid: c_int, cpusetsize: c_size_t, cpuset: UnsafePointer[cpu_set_t]) -> c_int:
    """Set CPU affinity for a process/thread."""
    return external_call["sched_setaffinity", c_int, c_int, c_size_t, UnsafePointer[cpu_set_t]](
        pid, cpusetsize, cpuset
    )

fn _memcmp(s1: UnsafePointer[UInt8], s2: UnsafePointer[UInt8], n: c_size_t) -> c_int:
    """Compare memory regions."""
    return external_call["memcmp", c_int, UnsafePointer[UInt8], UnsafePointer[UInt8], c_size_t](
        s1, s2, n
    )

# ===----------------------------------------------------------------------=== #
# CPU Set Helper Functions
# ===----------------------------------------------------------------------=== #

@always_inline
fn cpu_isset(cpu_num: Int, cpuset: cpu_set_t) -> Bool:
    """Check if a CPU is set in the CPU set."""
    var chunk_index = cpu_num // 64  # 64 bits per UInt64
    var chunk_offset = cpu_num % 64
    
    if chunk_index >= CPU_SET_LEN:
        return False
    
    var mask = UInt64(1) << chunk_offset
    return (cpuset.data[chunk_index] & mask) != 0

@always_inline
fn cpu_set(cpu_num: Int, mut cpuset: cpu_set_t) -> cpu_set_t:
    """Set a CPU in the CPU set."""
    var chunk_index = cpu_num // 64  # 64 bits per UInt64
    var chunk_offset = cpu_num % 64
    
    if chunk_index < CPU_SET_LEN:
        var mask = UInt64(1) << chunk_offset
        var new_data = cpuset.data
        new_data[chunk_index] |= mask
        cpuset = cpu_set_t(new_data)
    
    return cpuset

@always_inline
fn cpu_zero(mut cpuset: cpu_set_t) -> cpu_set_t:
    """Clear all CPUs in the CPU set."""
    var new_data = StaticTuple[UInt64, CPU_SET_LEN]()
    for i in range(CPU_SET_LEN):
        new_data[i] = 0
    cpuset = cpu_set_t(new_data)
    return cpuset

# ===----------------------------------------------------------------------=== #
# Public API Functions
# ===----------------------------------------------------------------------=== #

fn set_current_thread_cpu_affinity_to(cpu_num: Int):
    """Set the current thread's CPU affinity to a specific CPU core.
    
    Args:
        cpu_num: The CPU core number to bind the thread to.
    """
    # Get current CPU affinity
    var current_set = cpu_set_t(StaticTuple[UInt64, CPU_SET_LEN]())
    var current_set_ptr = UnsafePointer(to=current_set)
    
    var result = _sched_getaffinity(
        CURRENT_THREAD_CONTROL_PID, 
        sizeof[cpu_set_t](), 
        current_set_ptr
    )
    
    if result != 0:
        print("Warning: Failed to get current CPU affinity")
        return
    
    # Check if the requested CPU is available
    if not cpu_isset(cpu_num, current_set):
        print("Cannot set affinity for cpu", cpu_num)
        return
    
    # Create a new CPU set with only the requested CPU
    var new_set_mut = cpu_set_t(StaticTuple[UInt64, CPU_SET_LEN]())
    var new_set = cpu_zero(new_set_mut)
    new_set = cpu_set(cpu_num, new_set)
    var new_set_ptr = UnsafePointer(to=new_set)
    
    # Set the new affinity
    result = _sched_setaffinity(
        CURRENT_THREAD_CONTROL_PID, 
        sizeof[cpu_set_t](), 
        new_set_ptr
    )
    
    if result != 0:
        print("Warning: Failed to set CPU affinity for cpu", cpu_num)

fn get_num_logical_cpus() -> Int:
    """Get the number of logical CPU cores available.
    
    Returns:
        The number of logical CPU cores, or 1 if unable to determine.
    """
    # First try Mojo's built-in function
    try:
        var cores = num_logical_cores()
        if cores > 0:
            return cores
    except:
        pass
    
    # Fallback to sysconf
    var cpus = _sysconf(_SC_NPROCESSORS_ONLN)
    if cpus <= 0:
        print("Cannot determine the number of logical cpus with sysconf, performance will be severely impacted")
        return 1
    else:
        return Int(cpus)


# ===----------------------------------------------------------------------=== #
# Socket Constants  
# ===----------------------------------------------------------------------=== #

# Socket families
alias AF_INET: c_int = 2
alias AF_INET6: c_int = 10

# Socket types
alias SOCK_STREAM: c_int = 1
alias SOCK_DGRAM: c_int = 2

# Protocol levels
alias SOL_SOCKET: c_int = 1
alias IPPROTO_TCP: c_int = 6
alias IPPROTO_UDP: c_int = 17

# Socket options
alias SO_REUSEADDR: c_int = 2
alias SO_REUSEPORT: c_int = 15
alias SO_LINGER: c_int = 13
alias SO_ZEROCOPY: c_int = 60
alias SO_BUSY_POLL: c_int = 46
alias SO_INCOMING_CPU: c_int = 49
alias SO_INCOMING_NAPI_ID: c_int = 56
alias SO_ATTACH_REUSEPORT_CBPF: c_int = 51

# TCP options
alias TCP_NODELAY: c_int = 1
alias TCP_QUICKACK: c_int = 12
alias TCP_FASTOPEN: c_int = 23
alias TCP_DEFER_ACCEPT: c_int = 9

# fcntl constants
alias F_SETFL: c_int = 4
alias O_NONBLOCK: c_int = 2048

# Special addresses
alias INADDR_ANY: c_uint = 0

# Syscall numbers (Linux x86_64)
alias SYS_SOCKET: c_int = 41
alias SYS_BIND: c_int = 49
alias SYS_LISTEN: c_int = 50
alias SYS_SETSOCKOPT: c_int = 54
alias SYS_GETSOCKOPT: c_int = 55
alias SYS_FCNTL: c_int = 72
alias SYS_CLOSE: c_int = 3

# BPF constants for packet filtering
alias BPF_LD: c_ushort = 0x00
alias BPF_RET: c_ushort = 0x06
alias BPF_W: c_ushort = 0x00
alias BPF_ABS: c_ushort = 0x20
alias BPF_A: c_ushort = 0x10

alias SKF_AD_OFF: c_int = -0x1000
alias SKF_AD_CPU: c_int = 36

# ===----------------------------------------------------------------------=== #
# Network Structures
# ===----------------------------------------------------------------------=== #

@fieldwise_init
@register_passable("trivial")
struct in_addr:
    """IPv4 address structure."""
    var s_addr: c_uint

@fieldwise_init
@register_passable("trivial")
struct sockaddr_in:
    """IPv4 socket address structure."""
    var sin_family: c_ushort
    var sin_port: c_ushort
    var sin_addr: in_addr
    var sin_zero: StaticTuple[UInt8, 8]

@fieldwise_init
@register_passable("trivial")
struct linger:
    """Socket linger structure for SO_LINGER option."""
    var l_onoff: c_int
    var l_linger: c_int

@fieldwise_init
@register_passable("trivial")
struct sock_filter:
    """Berkeley Packet Filter instruction."""
    var code: c_ushort
    var jt: UInt8
    var jf: UInt8
    var k: c_uint

@fieldwise_init
@register_passable("trivial")
struct sock_fprog:
    """Berkeley Packet Filter program."""
    var len: c_ushort
    var filter: UnsafePointer[sock_filter]

# ===----------------------------------------------------------------------=== #
# Byte Order Functions
# ===----------------------------------------------------------------------=== #

@always_inline
fn htons(host_val: c_ushort) -> c_ushort:
    """Convert 16-bit host byte order to network byte order (big-endian).
    
    Args:
        host_val: Value in host byte order.
    
    Returns:
        Value in network byte order.
    """
    @parameter
    if is_little_endian():
        # Swap bytes for little-endian systems
        return ((host_val & 0x00FF) << 8) | ((host_val & 0xFF00) >> 8)
    else:
        # Already big-endian
        return host_val

@always_inline
fn htonl(host_val: c_uint) -> c_uint:
    """Convert 32-bit host byte order to network byte order (big-endian).
    
    Args:
        host_val: Value in host byte order.
    
    Returns:
        Value in network byte order.
    """
    @parameter
    if is_little_endian():
        # Swap bytes for little-endian systems
        return ((host_val & 0x000000FF) << 24) | \
               ((host_val & 0x0000FF00) << 8) | \
               ((host_val & 0x00FF0000) >> 8) | \
               ((host_val & 0xFF000000) >> 24)
    else:
        # Already big-endian
        return host_val

@always_inline
fn ntohs(net_val: c_ushort) -> c_ushort:
    """Convert 16-bit network byte order to host byte order.
    
    Args:
        net_val: Value in network byte order.
    
    Returns:
        Value in host byte order.
    """
    return htons(net_val)  # Same operation for 16-bit

@always_inline
fn ntohl(net_val: c_uint) -> c_uint:
    """Convert 32-bit network byte order to host byte order.
    
    Args:
        net_val: Value in network byte order.
    
    Returns:
        Value in host byte order.
    """
    return htonl(net_val)  # Same operation for 32-bit

# ===----------------------------------------------------------------------=== #
# Syscall Wrappers
# ===----------------------------------------------------------------------=== #

fn sys_socket(domain: c_int, type: c_int, protocol: c_int) -> Int:
    """Create a socket."""
    return Int(external_call["syscall", c_int, c_int, c_int, c_int, c_int](
        SYS_SOCKET, domain, type, protocol
    ))

fn sys_bind(sockfd: Int, addr: UnsafePointer[sockaddr_in], addrlen: c_size_t) -> Int:
    """Bind socket to address."""
    return Int(external_call["syscall", c_int, c_int, Int, UnsafePointer[sockaddr_in], c_size_t](
        SYS_BIND, sockfd, addr, addrlen
    ))

fn sys_listen(sockfd: Int, backlog: c_int) -> Int:
    """Listen for connections."""
    return Int(external_call["syscall", c_int, c_int, Int, c_int](
        SYS_LISTEN, sockfd, backlog
    ))

fn sys_setsockopt(sockfd: Int, level: c_int, optname: c_int, optval: UnsafePointer[NoneType], optlen: c_size_t) -> Int:
    """Set socket options."""
    return Int(external_call["syscall", c_int, c_int, Int, c_int, c_int, UnsafePointer[NoneType], c_size_t](
        SYS_SETSOCKOPT, sockfd, level, optname, optval, optlen
    ))

fn sys_getsockopt(sockfd: Int, level: c_int, optname: c_int, optval: UnsafePointer[NoneType], optlen: UnsafePointer[c_size_t]) -> Int:
    """Get socket options."""
    return Int(external_call["syscall", c_int, c_int, Int, c_int, c_int, UnsafePointer[NoneType], UnsafePointer[c_size_t]](
        SYS_GETSOCKOPT, sockfd, level, optname, optval, optlen
    ))

fn sys_fcntl(fd: Int, cmd: c_int, arg: c_int) -> Int:
    """File control operations."""
    return Int(external_call["syscall", c_int, c_int, Int, c_int, c_int](
        SYS_FCNTL, fd, cmd, arg
    ))

fn sys_close(fd: Int) -> Int:
    """Close file descriptor."""
    return Int(external_call["syscall", c_int, c_int, Int](
        SYS_CLOSE, fd
    ))

fn sys_epoll_ctl(epfd: Int, op: c_int, fd: Int, event: UnsafePointer[NoneType]) -> Int:
    """Control epoll instance."""
    return Int(external_call["syscall", c_int, c_int, Int, c_int, Int, UnsafePointer[NoneType]](
        SYS_EPOLL_CTL, epfd, op, fd, event
    ))

# ===----------------------------------------------------------------------=== #
# Main Networking Functions
# ===----------------------------------------------------------------------=== #

fn get_listener_fd(port: c_ushort) -> Tuple[Int, sockaddr_in, c_uint]:
    """Create and configure a listening socket.
    
    Args:
        port: Port number to bind to.
    
    Returns:
        Tuple containing (file_descriptor, socket_address, address_length).
    """
    alias OPTVAL: Int = 1
    alias OPTVAL_TCPFASTOPEN_QUEUE_LEN: Int = MAX_CONN
    
    # Create socket
    var fd_listener = sys_socket(AF_INET, SOCK_STREAM, 0)
    var size_of_optval = sizeof[Int]()
    
    # Set SO_REUSEPORT
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    var _ = sys_setsockopt(
        fd_listener,
        SOL_SOCKET,
        SO_REUSEPORT,
        optval_ptr,
        size_of_optval
    )
    
    # Create address structure
    var zero_array = StaticTuple[UInt8, 8]()
    for i in range(8):
        zero_array[i] = 0
    
    var addr = sockaddr_in(
        sin_family=c_ushort(AF_INET),
        sin_port=htons(port),
        sin_addr=in_addr(s_addr=htonl(INADDR_ANY)),
        sin_zero=zero_array
    )
    
    # Bind socket
    var _ = sys_bind(fd_listener, UnsafePointer(to=addr), sizeof[sockaddr_in]())
    
    # Listen
    var _ = sys_listen(fd_listener, OPTVAL_TCPFASTOPEN_QUEUE_LEN)
    
    var sock_len = c_uint(sizeof[sockaddr_in]())
    return (fd_listener, addr, sock_len)

@always_inline
fn setup_connection(fd: Int):
    """Configure a socket connection for optimal performance.
    
    Args:
        fd: Socket file descriptor to configure.
    """
    alias OPTVAL: Int = 1
    var size_of_optval = sizeof[Int]()
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    
    # Set TCP_NODELAY for reduced latency
    var _ = sys_setsockopt(
        fd,
        IPPROTO_TCP,
        TCP_NODELAY,
        optval_ptr,
        size_of_optval
    )
    
    # Set non-blocking mode
    var _ = sys_fcntl(fd, F_SETFL, O_NONBLOCK)

@always_inline
fn close_connection(epfd: Int, fd: Int):
    """Close a socket connection cleanly.
    
    Args:
        epfd: Epoll file descriptor.
        fd: Socket file descriptor to close.
    """
    # Set SO_LINGER to force immediate close
    var linger_opt = linger(l_onoff=1, l_linger=0)
    var linger_ptr = UnsafePointer(to=linger_opt).bitcast[NoneType]()
    
    var _ = sys_setsockopt(
        fd,
        SOL_SOCKET,
        SO_LINGER,
        linger_ptr,
        sizeof[linger]()
    )
    
    # Remove from epoll
    var _ = sys_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, UnsafePointer[NoneType]())
    
    # Close socket
    var _ = sys_close(fd)

@always_inline
fn attach_reuseport_cbpf(fd: Int):
    """Attach Classic BPF program for SO_REUSEPORT CPU distribution.
    
    This sets up a Berkeley Packet Filter program that distributes incoming
    connections based on CPU core to improve performance with SO_REUSEPORT.
    
    Args:
        fd: Socket file descriptor.
    """
    # BPF program to return CPU core number for load balancing
    var code = StaticTuple[sock_filter, 2](
        sock_filter(
            code=BPF_LD | BPF_W | BPF_ABS,
            jt=0,
            jf=0,
            k=c_uint(SKF_AD_OFF + SKF_AD_CPU)
        ),
        sock_filter(
            code=BPF_RET | BPF_A,
            jt=0,
            jf=0,
            k=0
        )
    )
    
    var prog = sock_fprog(
        len=2,
        filter=UnsafePointer(to=code[0])
    )
    
    var prog_ptr = UnsafePointer(to=prog).bitcast[NoneType]()
    var ret = sys_setsockopt(
        fd,
        SOL_SOCKET,
        SO_ATTACH_REUSEPORT_CBPF,
        prog_ptr,
        sizeof[sock_fprog]()
    )
    
    # Uncomment for debugging:
    # print("SO_ATTACH_REUSEPORT_CBPF ret:", ret, "size =", sizeof[sock_fprog]())

@always_inline
fn debug_incoming_cpu(incoming_fd: Int, listener_fd: Int, cpu_core: c_int):
    """Debug function to print CPU affinity information for sockets.
    
    Args:
        incoming_fd: Incoming connection file descriptor.
        listener_fd: Listener socket file descriptor.
        cpu_core: Expected CPU core number.
    """
    var incoming_cpu: c_int = -1
    var listener_cpu: c_int = -1
    var incoming_napi_id: c_int = -1
    var optlen = c_size_t(sizeof[c_int]())
    
    var incoming_cpu_ptr = UnsafePointer(to=incoming_cpu).bitcast[NoneType]()
    var listener_cpu_ptr = UnsafePointer(to=listener_cpu).bitcast[NoneType]()
    var incoming_napi_id_ptr = UnsafePointer(to=incoming_napi_id).bitcast[NoneType]()
    var optlen_ptr = UnsafePointer(to=optlen)
    
    var incoming_ret = sys_getsockopt(
        incoming_fd,
        SOL_SOCKET,
        SO_INCOMING_CPU,
        incoming_cpu_ptr,
        optlen_ptr
    )
    
    var listener_ret = sys_getsockopt(
        listener_fd,
        SOL_SOCKET,
        SO_INCOMING_CPU,
        listener_cpu_ptr,
        optlen_ptr
    )
    
    var incoming_napi_id_ret = sys_getsockopt(
        incoming_fd,
        SOL_SOCKET,
        SO_INCOMING_NAPI_ID,
        incoming_napi_id_ptr,
        optlen_ptr
    )
    
    print(
        "fd:", incoming_fd,
        "received request on core", incoming_cpu,
        "with ret value", incoming_ret,
        "should be core", cpu_core,
        "listener_fd is on core", listener_cpu,
        "with ret value", listener_ret,
        "with napi id", incoming_napi_id,
        "with ret", incoming_napi_id_ret
    )

# ===----------------------------------------------------------------------=== #
# Utility Functions for Socket Configuration
# ===----------------------------------------------------------------------=== #

fn set_socket_reuseaddr(fd: Int) raises:
    """Enable SO_REUSEADDR on socket."""
    alias OPTVAL: Int = 1
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    var result = sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set SO_REUSEADDR")

fn set_socket_reuseport(fd: Int) raises:
    """Enable SO_REUSEPORT on socket."""
    alias OPTVAL: Int = 1
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    var result = sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set SO_REUSEPORT")

fn set_tcp_nodelay(fd: Int) raises:
    """Enable TCP_NODELAY on socket."""
    alias OPTVAL: Int = 1
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    var result = sys_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set TCP_NODELAY")

fn set_nonblocking(fd: Int) raises:
    """Set socket to non-blocking mode."""
    var result = sys_fcntl(fd, F_SETFL, O_NONBLOCK)
    if result != 0:
        raise Error("Failed to set non-blocking mode")

# ===----------------------------------------------------------------------=== #
# Advanced Socket Options (Commented equivalents from Rust code)
# ===----------------------------------------------------------------------=== #

fn set_tcp_fastopen(fd: Int, queue_len: Int) raises:
    """Enable TCP Fast Open (TFO) on socket.
    
    Args:
        fd: Socket file descriptor.
        queue_len: Size of the TFO queue.
    """
    var optval_ptr = UnsafePointer(to=queue_len).bitcast[NoneType]()
    var result = sys_setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set TCP_FASTOPEN")

fn set_tcp_defer_accept(fd: Int, timeout: Int) raises:
    """Enable TCP_DEFER_ACCEPT on socket.
    
    Args:
        fd: Socket file descriptor.
        timeout: Defer accept timeout.
    """
    var optval_ptr = UnsafePointer(to=timeout).bitcast[NoneType]()
    var result = sys_setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set TCP_DEFER_ACCEPT")

fn set_so_zerocopy(fd: Int) raises:
    """Enable SO_ZEROCOPY on socket for zero-copy networking."""
    alias OPTVAL: Int = 1
    var optval_ptr = UnsafePointer(to=OPTVAL).bitcast[NoneType]()
    var result = sys_setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set SO_ZEROCOPY")

fn set_so_busy_poll(fd: Int, timeout_us: Int) raises:
    """Enable SO_BUSY_POLL on socket.
    
    Args:
        fd: Socket file descriptor.
        timeout_us: Busy poll timeout in microseconds.
    """
    var optval_ptr = UnsafePointer(to=timeout_us).bitcast[NoneType]()
    var result = sys_setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, optval_ptr, sizeof[Int]())
    if result != 0:
        raise Error("Failed to set SO_BUSY_POLL")

# ===----------------------------------------------------------------------=== #
# Updated web server implementation using real syscalls
# ===----------------------------------------------------------------------=== #

@no_inline
fn go(port: UInt16, cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int, mut NUM_WORKERS_INITED: Int, HTTP_DATE: AlignedHttpDate):
    # Set higher process priority (requires root on most systems)
    try:
        setpriority(PRIO_PROCESS, 0, -19)
    except e:
        print("Warning: Could not set priority:", e)
    
    # Initialize HTTP date
    try:
        get_http_date(UnsafePointer(to=HTTP_DATE.data), HTTP_DATE)
    except e:
        print("Warning: Could not initialize HTTP date:", e)
    
    var num_cpu_cores = num_logical_cores()
    print("Starting", num_cpu_cores, "worker threads")
    
    # In Mojo, we use parallelize instead of manual thread creation
    @parameter
    fn worker_task(core: Int):
        try:
            # Unshare file descriptor table
            unshare(CLONE_FILES)
            set_current_thread_cpu_affinity_to(core)
            threaded_worker(port, cb, core, num_cpu_cores, NUM_WORKERS_INITED)
        except e:
            print("Worker", core, "error:", e)
    
    # Start worker tasks
    parallelize[worker_task](num_cpu_cores)
    
    # Main date update loop
    while True:
        try:
            get_http_date(UnsafePointer(to=HTTP_DATE.data), HTTP_DATE)
        except e:
            print("Warning: Could not update HTTP date:", e)
        try:
            nanosleep(1.0)  # Sleep for 1 second
        except:
            pass

fn threaded_worker(
    port: UInt16,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    cpu_core: Int,
    num_cpu_cores: Int,
    mut NUM_WORKERS_INITED: Int
):
    """Worker thread function using real syscalls."""
    
    try:
        var listener_fd_tuple = get_listener_fd(port)
        var listener_fd = listener_fd_tuple[0]
        setup_connection(listener_fd)
        
        # Synchronization for REUSEPORT_CBPF attachment
        NUM_WORKERS_INITED += 1
        if cpu_core == 0:
            while NUM_WORKERS_INITED < num_cpu_cores:
                nanosleep(0.000001)  # 1 microsecond
            attach_reuseport_cbpf(listener_fd)
        
        var epfd = epoll_create1(0)
        
        # Add listener fd to epoll
        var epoll_event_listener = epoll_event(EPOLLIN, epoll_data(UInt64(listener_fd)))
        epoll_ctl(epfd, EPOLL_CTL_ADD, listener_fd, UnsafePointer(to=epoll_event_listener))
        
        # Initialize buffers and state
        var epoll_events = AlignedEpollEvents(AlignedEpollEventsTuple())
        memset_zero(rebind[UnsafePointer[UInt8]](UnsafePointer(to=epoll_events)), sizeof[AlignedEpollEvents]())
        
        var saved_event = epoll_event(EPOLLIN, epoll_data(0))
        
        var reqbuf = ReqBufAligned(ReqBufAlignedTuple())
        memset_zero(rebind[UnsafePointer[UInt8]](UnsafePointer(to=reqbuf)), sizeof[ReqBufAligned]())
        
        # Request buffer position tracking arrays
        var reqbuf_cur_addr = StaticTuple[Int, MAX_CONN]()
        var reqbuf_start_address = Int(UnsafePointer(to=reqbuf.data).bitcast[Int]())
        for i in range(MAX_CONN):
            reqbuf_cur_addr[i] = reqbuf_start_address + i * REQ_BUF_SIZE
        
        var reqbuf_residual = StaticTuple[Int, MAX_CONN]()
        for i in range(MAX_CONN):
            reqbuf_residual[i] = 0
        
        var resbuf = ResBufAligned(ResBufAlignedTuple())
        memset_zero(rebind[UnsafePointer[UInt8]](UnsafePointer(to=resbuf)), sizeof[ResBufAligned]())
        var resbuf_start_address = UnsafePointer(to=resbuf.data)
        
        var epoll_wait_type = -1  # EPOLL_TIMEOUT_BLOCKING
        
        # Main event loop
        while True:
            var num_incoming_events = epoll_wait(
                epfd, 
                UnsafePointer(to=epoll_events.data[0]),
                MAX_EPOLL_EVENTS_RETURNED, 
                epoll_wait_type
            )
            
            if num_incoming_events <= 0:
                epoll_wait_type = -1  # EPOLL_TIMEOUT_BLOCKING
                continue
            
            epoll_wait_type = 0  # EPOLL_TIMEOUT_IMMEDIATE_RETURN
            
            for index in range(num_incoming_events):
                var event = epoll_events.data[index]
                var cur_fd = Int(event.data.u64)
                
                if cur_fd == listener_fd:
                    # Handle new connection
                    var incoming_fd = accept_connection(listener_fd)
                    
                    if incoming_fd >= 0 and incoming_fd < MAX_CONN:
                        var req_buf_start_address = reqbuf_start_address + incoming_fd * REQ_BUF_SIZE
                        reqbuf_cur_addr[incoming_fd] = req_buf_start_address
                        reqbuf_residual[incoming_fd] = 0
                        setup_connection(incoming_fd)
                        saved_event.data.u64 = UInt64(incoming_fd)
                        epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd, UnsafePointer(to=saved_event))
                    else:
                        close_connection(epfd, cur_fd)
                else:
                    # Handle existing connection data
                    var req_buf_start_address = reqbuf_start_address + cur_fd * REQ_BUF_SIZE
                    var req_buf_cur_position = reqbuf_cur_addr[cur_fd]
                    var residual = reqbuf_residual[cur_fd]
                    
                    var buffer_remaining = REQ_BUF_SIZE - (req_buf_cur_position - req_buf_start_address)
                    var read = recv_from(cur_fd, rebind[UnsafePointer[UInt8]](UnsafePointer(to=req_buf_cur_position)), buffer_remaining)
                    
                    if read > 0:
                        # Process the received data (simplified)
                        var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                        var response_len = len(response)
                        
                        # Copy response to buffer
                        var response_ptr = response.unsafe_ptr()
                        var dest_ptr = rebind[UnsafePointer[UInt8]](resbuf_start_address)
                        memcpy(dest_ptr, response_ptr, response_len)
                        
                        var wrote = send_to(cur_fd, dest_ptr, response_len)
                        
                        # Reset buffer state
                        reqbuf_cur_addr[cur_fd] = req_buf_start_address
                        reqbuf_residual[cur_fd] = 0
                        
                        if wrote != response_len:
                            close_connection(epfd, cur_fd)
                    else:
                        # Connection closed or error
                        reqbuf_cur_addr[cur_fd] = req_buf_start_address
                        reqbuf_residual[cur_fd] = 0
                        close_connection(epfd, cur_fd)
    
    except e:
        print("Worker thread error:", e)

# Example usage function
fn example_callback(
    method: UnsafePointer[UInt8], 
    method_len: Int, 
    path: UnsafePointer[UInt8], 
    path_len: Int, 
    response_buf: UnsafePointer[UInt8], 
    http_date: UnsafePointer[UInt8]
) -> Int:
    """Example HTTP request callback function."""
    print("Processing request: method_len=", method_len, "path_len=", path_len)
    # Write a simple HTTP response
    var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
    var response_len = len(response)
    # Copy response to buffer (dummy implementation)
    return response_len
