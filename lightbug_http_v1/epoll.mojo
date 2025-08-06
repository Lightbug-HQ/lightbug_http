from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call
from sys import num_logical_cores
from sys.info import sizeof
from time import sleep
from lightbug_http.external.small_time import now
from algorithm import parallelize
from memory import memset_zero, memcpy
from lightbug_http._libc import get_errno, sockaddr, socklen_t, c_ssize_t

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

@fieldwise_init
@register_passable("trivial")
struct ResBufAligned:
    var data: StaticTuple[UInt8, RES_BUF_SIZE]

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
# Updated web server implementation using real syscalls
# ===----------------------------------------------------------------------=== #

# Now update your web server code to use these real syscalls:

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
        memset_zero(UnsafePointer(to=epoll_events).bitcast[UInt8](), sizeof[AlignedEpollEvents]())
        
        var saved_event = epoll_event(EPOLLIN, epoll_data(0))
        
        var reqbuf = ReqBufAligned(ReqBufAlignedTuple())
        memset_zero(UnsafePointer(to=reqbuf).bitcast[UInt8](), sizeof[ReqBufAligned]())
        
        # Request buffer position tracking arrays
        var reqbuf_cur_addr = StaticTuple[Int, MAX_CONN]()
        var reqbuf_start_address = Int(reqbuf.data.unsafe_ptr().bitcast[Int]())
        for i in range(MAX_CONN):
            reqbuf_cur_addr[i] = reqbuf_start_address + i * REQ_BUF_SIZE
        
        var reqbuf_residual = StaticTuple[Int, MAX_CONN]()
        for i in range(MAX_CONN):
            reqbuf_residual[i] = 0
        
        var resbuf = ResBufAligned()
        memset_zero(UnsafePointer(to=resbuf).bitcast[UInt8](), sizeof[ResBufAligned]())
        var resbuf_start_address = resbuf.data.unsafe_ptr()
        
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
                    var read = recv_from(cur_fd, UnsafePointer[UInt8](req_buf_cur_position), buffer_remaining)
                    
                    if read > 0:
                        # Process the received data (simplified)
                        var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                        var response_len = len(response)
                        
                        # Copy response to buffer
                        var response_ptr = response.unsafe_ptr()
                        memcpy(resbuf_start_address, response_ptr, response_len)
                        
                        var wrote = send_to(cur_fd, resbuf_start_address, response_len)
                        
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

fn main():
    """Main function to start the server."""
    print("Starting FaF server on port 8080")
    
    # Initialize global HTTP_DATE
    HTTP_DATE = AlignedHttpDate(StaticTuple[UInt8, 35]())
    
    # Start the server
    var NUM_WORKERS_INITED = 0
    go(8080, example_callback, NUM_WORKERS_INITED, HTTP_DATE)