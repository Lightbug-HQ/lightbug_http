from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call, c_long, c_size_t, c_uchar, c_ushort, c_char
from sys.info import sizeof, CompilationTarget, num_logical_cores
from sys.intrinsics import likely, unlikely
from memory import memcmp, UnsafePointer, stack_allocation, memset_zero, memcpy
from time import sleep
from lightbug_http_v1.runtime import AsyncRuntime, TaskHandle, TaskResult, default_callback
from os.atomic import Atomic

# Using existing working socket infrastructure from your codebase
from lightbug_http._libc import (
    sockaddr_in, 
    socket,
    setsockopt,
    bind,
    listen,
    accept,
    recv,
    send,
    close,
    c_void,
    AddressFamily,
    SOCK_STREAM,
    get_errno,
    EAGAIN,
    EWOULDBLOCK
)

# ===----------------------------------------------------------------------=== #
# FaF Constants (matching Rust version)
# ===----------------------------------------------------------------------=== #

alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUFF_SIZE = 1024
alias RES_BUFF_SIZE = 1024
alias MAX_CONN = 1024

alias EPOLL_TIMEOUT_BLOCKING = -1
alias EPOLL_TIMEOUT_IMMEDIATE_RETURN = 0

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

# Socket options - Linux specific values
# Your libc code has macOS/BSD values, but we need Linux values for Ubuntu
alias SO_REUSEADDR_LINUX = 2       # Linux value
alias SO_REUSEPORT_LINUX = 15      # Linux value  
alias SOL_SOCKET_LINUX = 1         # Linux value (not 0xFFFF which is BSD)

# Check if SO_REUSEPORT is supported by testing with a temporary socket
fn test_so_reuseport_support() -> Bool:
    """Test if SO_REUSEPORT is supported on this system."""
    try:
        var test_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
        if test_fd < 0:
            return False
        # Try setting SO_REUSEPORT with direct external_call
        var value = c_int(1)
        var result = external_call["setsockopt", c_int, c_int, c_int, c_int, UnsafePointer[c_int], c_uint](
            c_int(test_fd),
            c_int(SOL_SOCKET_LINUX),
            c_int(SO_REUSEPORT_LINUX),
            UnsafePointer(to=value),
            c_uint(sizeof[c_int]())
        )
        
        var _ = close(test_fd)
        return result == 0
    except:
        print("no")
    return False
    
    

# TODO: Add TCP_NODELAY and other socket options
# alias TCP_NODELAY = 1

# System call constants
alias SYS_SETPRIORITY = 141
alias SYS_NANOSLEEP = 35
alias SYS_EPOLL_CREATE1 = 291
alias SYS_EPOLL_CTL = 233
alias SYS_EPOLL_WAIT = 232
alias SYS_ACCEPT = 43
alias SYS_RECVFROM = 45
alias SYS_SENDTO = 44
alias SYS_UNSHARE = 272
alias CLONE_FILES = 0x00000400

# Priority constants
alias PRIO_PROCESS = 0
alias PRIO_PGRP = 1
alias PRIO_USER = 2

# ===----------------------------------------------------------------------=== #
# FaF Structures (matching Rust alignment and layout)
# ===----------------------------------------------------------------------=== #

@register_passable("trivial")  
struct epoll_event:
    var events: UInt32
    var data: UInt64  # This represents the union epoll_data as a single 64-bit value
    
    fn __init__(out self):
        self.events = 0
        self.data = 0
        
    fn __init__(out self, events: UInt32, fd: Int):
        self.events = events
        self.data = UInt64(fd)  # Store fd in the data field

# TODO: Add proper 64-byte alignment like Rust #[repr(align(64))]
@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]
    
    fn __init__(out self):
        self.data = StaticTuple[UInt8, 35]()

# TODO: Add proper 64-byte alignment for all aligned structures
@register_passable("trivial")
struct AlignedEpollEvents:
    var events: StaticTuple[epoll_event, MAX_EPOLL_EVENTS_RETURNED]
    
    fn __init__(out self):
        self.events = StaticTuple[epoll_event, MAX_EPOLL_EVENTS_RETURNED]()

# ===----------------------------------------------------------------------=== #
# Simplified Global State Management (avoiding Atomic copyability issues)
# ===----------------------------------------------------------------------=== #

# TODO: Implement proper global state management when Mojo supports it
# For now, we'll use simpler per-worker approach without global synchronization

# ===----------------------------------------------------------------------=== #
# Enhanced Worker Data for FaF
# ===----------------------------------------------------------------------=== #

@register_passable("trivial")
struct FafWorkerData:
    """Enhanced worker data structure for FaF-style workers."""
    var worker_id: Int
    var cpu_core: Int
    var port: UInt16
    var num_cpu_cores: Int
    # TODO: Add global state management when Mojo supports it properly
    
    fn __init__(out self, worker_id: Int, cpu_core: Int, port: UInt16, num_cpu_cores: Int):
        self.worker_id = worker_id
        self.cpu_core = cpu_core
        self.port = port
        self.num_cpu_cores = num_cpu_cores

# ===----------------------------------------------------------------------=== #
# System call wrappers
# ===----------------------------------------------------------------------=== #

fn sys_setpriority(which: Int, who: Int, priority: Int) -> Int:
    """Set process priority."""
    return Int(external_call["setpriority", c_int, c_int, c_int, c_int](which, who, priority))

fn sys_epoll_create1(flags: Int) -> Int:
    """Create an epoll instance."""
    return Int(external_call["epoll_create1", c_int, c_int](flags))

fn sys_epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) -> Int:
    """Control epoll instance."""
    return Int(external_call["epoll_ctl", c_int, c_int, c_int, c_int, UnsafePointer[epoll_event]](epfd, op, fd, event))

fn sys_epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) -> Int:
    """Wait for epoll events."""
    return Int(external_call["epoll_wait", c_int, c_int, UnsafePointer[epoll_event], c_int, c_int](epfd, events, maxevents, timeout))

fn sys_accept(sockfd: Int, addr: Int, addrlen: Int) -> Int:
    """Accept a connection."""
    return Int(external_call["accept", c_int, c_int, c_int, c_int](sockfd, addr, addrlen))

fn sys_recvfrom(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, src_addr: Int, addrlen: Int) -> Int:
    """Receive data from socket."""
    return Int(external_call["recvfrom", c_int, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_int, c_int](sockfd, buf, len, flags, src_addr, addrlen))

fn sys_sendto(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, dest_addr: Int, addrlen: Int) -> Int:
    """Send data to socket."""
    return Int(external_call["sendto", c_int, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_int, c_int](sockfd, buf, len, flags, dest_addr, addrlen))

# Linux-specific socket option functions
fn set_so_reuseaddr_linux(fd: c_int) -> Bool:
    """Set SO_REUSEADDR using Linux constants."""
    var value = c_int(1)
    var result = external_call["setsockopt", c_int, c_int, c_int, c_int, UnsafePointer[c_int], c_uint](
        c_int(fd),
        c_int(SOL_SOCKET_LINUX),
        c_int(SO_REUSEADDR_LINUX),
        UnsafePointer(to=value),
        c_uint(sizeof[c_int]())
    )
    return result == 0

fn set_so_reuseport_linux(fd: c_int) -> Bool:
    """Set SO_REUSEPORT using Linux constants."""
    var value = c_int(1)
    var result = external_call["setsockopt", c_int, c_int, c_int, c_int, UnsafePointer[c_int], c_uint](
        c_int(fd),
        c_int(SOL_SOCKET_LINUX),
        c_int(SO_REUSEPORT_LINUX),
        UnsafePointer(to=value),
        c_uint(sizeof[c_int]())
    )
    return result == 0

# TODO: Add CPU affinity syscalls
fn sys_set_cpu_affinity(cpu_core: Int) -> Bool:
    """Set CPU affinity for current thread."""
    # TODO: Implement sched_setaffinity syscall
    # var cpu_set = UnsafePointer[UInt8].alloc(128)  # cpu_set_t 
    # _ = external_call["CPU_ZERO", NoneType](cpu_set)
    # _ = external_call["CPU_SET", NoneType](cpu_core, cpu_set)
    # var result = external_call["sched_setaffinity", Int32](0, 128, cpu_set)
    # cpu_set.free()
    # return result == 0
    print("TODO: CPU affinity not implemented - would set core", cpu_core)
    return True

# TODO: Add unshare syscall for FD table isolation
fn sys_unshare_fd_table() -> Bool:
    """Unshare file descriptor table between threads."""
    # TODO: Implement SYS_UNSHARE with CLONE_FILES
    # return external_call["syscall", Int](SYS_UNSHARE, CLONE_FILES) == 0
    print("TODO: FD table unsharing not implemented")
    return True

# TODO: Add thread naming
fn sys_set_thread_name(name: String) -> Bool:
    """Set thread name for debugging."""
    # TODO: Implement pthread_setname_np
    # var name_bytes = name.as_bytes()
    # var result = external_call["pthread_setname_np", Int32](
    #     external_call["pthread_self", UInt64](),
    #     name_bytes.unsafe_ptr()
    # )
    # return result == 0
    print("TODO: Thread naming not implemented - would set name:", name)
    return True

# ===----------------------------------------------------------------------=== #
# Socket setup functions (enhanced FaF version)
# ===----------------------------------------------------------------------=== #

fn get_listener_fd_with_reuseport(port: UInt16, worker_id: Int) raises -> (c_int, Bool, Bool):
    """Create a socket with SO_REUSEPORT for multiple workers."""
    print("Worker", worker_id, "creating socket with SO_REUSEPORT on port", port)
    
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    if listener_fd < 0:
        print("Worker", worker_id, "failed to create socket, errno:", get_errno())
        return (-1, False, False)
    
    print("Worker", worker_id, "socket created successfully, fd:", listener_fd)
    
    # Try to set SO_REUSEADDR using Linux-specific constants
    print("Worker", worker_id, "attempting to set SO_REUSEADDR with Linux constants...")
    if set_so_reuseaddr_linux(listener_fd):
        print("Worker", worker_id, "SO_REUSEADDR set successfully")
    else:
        print("Worker", worker_id, "failed to set SO_REUSEADDR, errno:", get_errno(), "- continuing anyway")
    
    # Try SO_REUSEPORT using Linux-specific constants
    print("Worker", worker_id, "attempting to set SO_REUSEPORT with Linux constants...")
    var reuseport_result = -1
    if set_so_reuseport_linux(listener_fd):
        print("Worker", worker_id, "SO_REUSEPORT set successfully")
        reuseport_result = 0
    else:
        print("Worker", worker_id, "failed to set SO_REUSEPORT, errno:", get_errno())
        reuseport_result = -1
        if worker_id > 0:
            print("Worker", worker_id, "SO_REUSEPORT failed and worker > 0, cannot bind to same port")
            var _ = close(listener_fd)
            return (-1, False, False)
        else:
            print("Worker", worker_id, "SO_REUSEPORT failed but worker 0, continuing without it")
    
    # Bind socket
    var addr = sockaddr_in(Int(AddressFamily.AF_INET.value), port, 0)  # INADDR_ANY = 0
    try:
        bind(listener_fd, addr)
        print("Worker", worker_id, "bound to port", port, "successfully")
    except e:
        print("Worker", worker_id, "failed to bind to port", port, ", error:", e)
        var _ = close(listener_fd)
        return (-1, False, False)
    
    # Listen
    try:
        listen(listener_fd, 128)
        print("Worker", worker_id, "listening on port", port, "successfully")
    except e:
        print("Worker", worker_id, "failed to listen, error:", e)
        var _ = close(listener_fd)
        return (-1, False, False)
    
    return (listener_fd, True, True)

fn get_listener_fd_simple(port: UInt16, worker_id: Int) raises -> (c_int, Bool, Bool):
    """Create a simple listener socket without advanced options (fallback)."""
    print("Worker", worker_id, "creating simple socket on port", port)
    
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    if listener_fd < 0:
        print("Worker", worker_id, "failed to create socket, errno:", get_errno())
        return (-1, False, False)
    
    print("Worker", worker_id, "socket created successfully, fd:", listener_fd)
    
    # Only worker 0 can bind without SO_REUSEPORT
    if worker_id > 0:
        print("Worker", worker_id, "cannot bind to same port without SO_REUSEPORT, exiting")
        var _ = close(listener_fd)
        return (-1, False, False)
    
    # Try to set SO_REUSEADDR using Linux-specific constants
    print("Worker", worker_id, "attempting to set SO_REUSEADDR with Linux constants...")
    if set_so_reuseaddr_linux(listener_fd):
        print("Worker", worker_id, "SO_REUSEADDR set successfully")
    else:
        print("Worker", worker_id, "failed to set SO_REUSEADDR, errno:", get_errno(), "- continuing anyway")
    
    print("Worker", worker_id, "skipping SO_REUSEPORT (simple mode)")
    
    # Bind socket
    var addr = sockaddr_in(Int(AddressFamily.AF_INET.value), port, 0)  # INADDR_ANY = 0
    try:
        bind(listener_fd, addr)
        print("Worker", worker_id, "bound to port", port, "successfully")
    except e:
        print("Worker", worker_id, "failed to bind to port", port, ", error:", e)
        var _ = close(listener_fd)
        return (-1, False, False)
    
    # Listen
    try:
        listen(listener_fd, 128)
        print("Worker", worker_id, "listening on port", port, "successfully")
    except e:
        print("Worker", worker_id, "failed to listen, error:", e)
        var _ = close(listener_fd)
        return (-1, False, False)
    
    return (listener_fd, True, True)

fn get_listener_fd_faf(port: UInt16, worker_id: Int) raises -> (c_int, Bool, Bool):
    """Create and configure listener socket with FaF options - try SO_REUSEPORT first."""
    # Try the SO_REUSEPORT version for multiple workers
    try:
        return get_listener_fd_with_reuseport(port, worker_id)
    except e:
        print("Worker", worker_id, "SO_REUSEPORT approach failed:", e)
        print("Worker", worker_id, "falling back to simple socket (worker 0 only)")
        return get_listener_fd_simple(port, worker_id)

fn setup_connection_faf(fd: Int):
    """Set up connection options (FaF version)."""
    # TODO: Implement TCP_NODELAY and other FaF socket options
    # var nodelay = c_int(1)
    # var _ = sys_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, UnsafePointer(to=nodelay), sizeof[c_int]())
    print("TODO: TCP_NODELAY and other socket options not implemented for fd", fd)

# TODO: Implement REUSEPORT CBPF attachment
fn attach_reuseport_cbpf_faf(listener_fd: Int):
    """Attach REUSEPORT CBPF for greater locality."""
    # TODO: Implement SO_ATTACH_REUSEPORT_CBPF
    print("TODO: REUSEPORT CBPF not implemented for fd", listener_fd)

fn close_connection_faf(epfd: Int, fd: Int):
    """Close connection and remove from epoll."""
    var _ = sys_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, UnsafePointer[epoll_event]())
    try:
        var _ = close(c_int(fd))
    except:
        pass

# ===----------------------------------------------------------------------=== #
# HTTP request parsing (simplified, TODO: SIMD version)
# ===----------------------------------------------------------------------=== #

fn parse_request_path_pipelined_simple(
    request_buffer: UnsafePointer[UInt8],
    buffer_len: Int,
    method: UnsafePointer[UnsafePointer[UInt8]],
    method_len: UnsafePointer[Int],
    path: UnsafePointer[UnsafePointer[UInt8]],
    path_len: UnsafePointer[Int]
) -> Int:
    """Simplified HTTP request parser - TODO: implement SIMD version like FaF."""
    if buffer_len < 4:
        return 0
    
    # Look for "GET " or "POST"
    var buf = request_buffer
    if buf[0] == ord("G") and buf[1] == ord("E") and buf[2] == ord("T") and buf[3] == ord(" "):
        method[] = buf
        method_len[] = 3
        
        # Find path start (after "GET ")
        var path_start = buf + 4
        path[] = path_start
        
        # Find end of path (space or newline)
        var i = 4
        while i < buffer_len and buf[i] != ord(" ") and buf[i] != ord("\r") and buf[i] != ord("\n"):
            i += 1
        
        path_len[] = i - 4
        
        # Find end of request (double CRLF)
        while i < buffer_len - 3:
            if buf[i] == ord("\r") and buf[i+1] == ord("\n") and buf[i+2] == ord("\r") and buf[i+3] == ord("\n"):
                return i + 4
            i += 1
        
        # Incomplete request
        return 0
    
    return 0  # Invalid request

# HTTP date function (simplified but proper format)
fn get_http_date(buf: UnsafePointer[UInt8]):
    """Get current HTTP date string - TODO: implement real date formatting."""
    # TODO: Implement proper HTTP date formatting like FaF
    var date_str = "Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    var date_bytes = date_str.as_bytes()
    memcpy(buf, date_bytes.unsafe_ptr(), min(len(date_bytes), 35))

# ===----------------------------------------------------------------------=== #
# FaF Worker Thread Function (main translation)
# ===----------------------------------------------------------------------=== #

fn faf_threaded_worker(arg: UnsafePointer[UInt8]) -> UnsafePointer[UInt8]:
    """FaF threaded worker - direct translation from Rust version."""
    var data_ptr = arg.bitcast[FafWorkerData]()
    var data = data_ptr[]
    
    print("FaF Worker", data.worker_id, "starting on CPU core", data.cpu_core)
    
    # TODO: Unshare file descriptor table (FaF optimization)
    var _ = sys_unshare_fd_table()
    
    # TODO: Set CPU affinity (FaF performance optimization)
    var _ = sys_set_cpu_affinity(data.cpu_core)
    
    # TODO: Set thread name for debugging
    var thread_name = "faf" + String(data.worker_id)
    var _ = sys_set_thread_name(thread_name)
    
    # Get listener socket (with SO_REUSEPORT)
    try:
        var (listener_fd, success1, success2) = get_listener_fd_faf(data.port, data.worker_id)
        if listener_fd < 0:
            print("FaF Worker", data.worker_id, "failed to create listener socket - exiting worker")
            return UnsafePointer[UInt8]()
        
        setup_connection_faf(Int(listener_fd))
        print("FaF Worker", data.worker_id, "listener socket created successfully on port", data.port)
        
        # TODO: Track worker initialization like FaF (needs proper global state)
        # For now, just use a simple delay for worker 0 to attach CBPF
        if data.worker_id == 0:
            sleep(0.05)  # 50ms delay to let other workers initialize
            attach_reuseport_cbpf_faf(Int(listener_fd))
        
        # Create epoll instance
        var epfd = sys_epoll_create1(0)
        if epfd < 0:
            print("FaF Worker", data.worker_id, "failed to create epoll")
            try:
                var _ = close(listener_fd)
            except:
                pass
            return UnsafePointer[UInt8]()
        
        # Add listener fd to epoll for monitoring
        var epoll_event_listener = epoll_event(EPOLLIN, Int(listener_fd))
        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, Int(listener_fd), UnsafePointer(to=epoll_event_listener))
        
        # Allocate aligned buffers like FaF (TODO: proper 64-byte alignment)
        var epoll_events = UnsafePointer[epoll_event].alloc(MAX_EPOLL_EVENTS_RETURNED)
        memset_zero(epoll_events, MAX_EPOLL_EVENTS_RETURNED * sizeof[epoll_event]())
        
        var saved_event = epoll_event(EPOLLIN, 0)
        
        # Request buffer management (like FaF)
        var reqbuf = UnsafePointer[UInt8].alloc(REQ_BUFF_SIZE * MAX_CONN)
        memset_zero(reqbuf, REQ_BUFF_SIZE * MAX_CONN)
        
        # Track buffer positions and residuals per connection
        var reqbuf_cur_addr = UnsafePointer[UInt64].alloc(MAX_CONN)
        var reqbuf_residual = UnsafePointer[Int].alloc(MAX_CONN)
        memset_zero(reqbuf_cur_addr, MAX_CONN * sizeof[UInt64]())
        memset_zero(reqbuf_residual, MAX_CONN * sizeof[Int]())
        
        # Initialize buffer addresses
        var reqbuf_start_address = Int(reqbuf)
        for i in range(MAX_CONN):
            reqbuf_cur_addr[i] = UInt64(reqbuf_start_address + i * REQ_BUFF_SIZE)
        
        # Response buffer
        var resbuf = UnsafePointer[UInt8].alloc(RES_BUFF_SIZE)
        var resbuf_start_address = Int(resbuf)
        
        var epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
        
        print("FaF Worker", data.worker_id, "starting epoll event loop")
        
        # Main epoll event loop (infinite like FaF)
        while True:
            var num_incoming_events = sys_epoll_wait(epfd, epoll_events, MAX_EPOLL_EVENTS_RETURNED, epoll_wait_type)
            
            if num_incoming_events <= 0:
                epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
                continue
            
            epoll_wait_type = EPOLL_TIMEOUT_IMMEDIATE_RETURN
            
            for index in range(num_incoming_events):
                var event = epoll_events[index]
                var cur_fd = Int(event.data)
                
                # Calculate buffer addresses for this connection
                var req_buf_start_address = reqbuf_start_address + cur_fd * REQ_BUFF_SIZE
                var req_buf_cur_position = reqbuf_cur_addr[cur_fd]
                var residual = reqbuf_residual[cur_fd]
                
                if cur_fd == Int(listener_fd):
                    # Accept new connection (FaF logic)
                    var incoming_fd = sys_accept(Int(listener_fd), 0, 0)
                    
                    if likely(incoming_fd >= 0 and incoming_fd < MAX_CONN):
                        # Reset buffer state for this connection
                        reqbuf_cur_addr[incoming_fd] = UInt64(reqbuf_start_address + incoming_fd * REQ_BUFF_SIZE)
                        reqbuf_residual[incoming_fd] = 0
                        
                        setup_connection_faf(incoming_fd)
                        saved_event.data = UInt64(incoming_fd)
                        
                        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd, UnsafePointer(to=saved_event))
                    else:
                        close_connection_faf(epfd, cur_fd)
                else:
                    # Handle client connection (FaF logic)
                    var buffer_remaining = REQ_BUFF_SIZE - Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    var buf_ptr = reqbuf + (cur_fd * REQ_BUFF_SIZE) + Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    var read_bytes = sys_recvfrom(cur_fd, buf_ptr, buffer_remaining, 0, 0, 0)
                    
                    if likely(read_bytes > 0):
                        var request_buffer_offset = 0
                        var response_buffer_filled_total = 0
                        
                        # Process potentially multiple pipelined requests (FaF logic)
                        while request_buffer_offset != (read_bytes + residual):
                            var method = UnsafePointer[UInt8]()
                            var method_len = 0
                            var path = UnsafePointer[UInt8]()
                            var path_len = 0
                            
                            var parse_buf_ptr = buf_ptr - residual + request_buffer_offset
                            # TODO: Use SIMD parsing like FaF's parse_request_path_pipelined_simd
                            var request_buffer_bytes_parsed = parse_request_path_pipelined_simple(
                                parse_buf_ptr,
                                read_bytes + residual - request_buffer_offset,
                                UnsafePointer(to=method),
                                UnsafePointer(to=method_len),
                                UnsafePointer(to=path),
                                UnsafePointer(to=path_len)
                            )
                            
                            if request_buffer_bytes_parsed > 0:
                                request_buffer_offset += request_buffer_bytes_parsed
                                
                                # Generate response using callback
                                # TODO: Use proper HTTP date from global state
                                var http_date_buffer = UnsafePointer[UInt8].alloc(35)
                                get_http_date(http_date_buffer)
                                
                                var response_buffer_filled = example_callback_faf(
                                    method, method_len,
                                    path, path_len,
                                    resbuf + response_buffer_filled_total,
                                    http_date_buffer
                                )
                                
                                http_date_buffer.free()
                                
                                response_buffer_filled_total += response_buffer_filled
                            else:
                                break
                        
                        # Handle buffer state updates (FaF logic)
                        if request_buffer_offset == 0 or response_buffer_filled_total == 0:
                            # Reset buffer and close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection_faf(epfd, cur_fd)
                            continue
                        elif request_buffer_offset == (read_bytes + residual):
                            # Complete request processed
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                        else:
                            # Partial request - update buffer position
                            reqbuf_cur_addr[cur_fd] += UInt64(read_bytes)
                            reqbuf_residual[cur_fd] += (read_bytes - request_buffer_offset)
                        
                        # Send response (FaF logic)
                        var wrote = sys_sendto(cur_fd, resbuf, response_buffer_filled_total, 0, 0, 0)
                        
                        if likely(wrote == response_buffer_filled_total):
                            # Successful write - continue
                            pass
                        elif unlikely(wrote < 0 and (-wrote == EAGAIN or -wrote == 11)):  # EINTR = 11
                            # Handle EAGAIN/EINTR
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection_faf(epfd, cur_fd)
                        else:
                            # Error or partial write - close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection_faf(epfd, cur_fd)
                        
                    elif read_bytes < 0:
                        var errno = -read_bytes
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                            # Would block - continue
                            pass
                        else:
                            # Error - close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection_faf(epfd, cur_fd)
                    else:
                        # Connection closed by client
                        reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                        reqbuf_residual[cur_fd] = 0
                        close_connection_faf(epfd, cur_fd)
        
        # Cleanup (this won't be reached in the infinite loop)
        epoll_events.free()
        reqbuf.free()
        reqbuf_cur_addr.free()
        reqbuf_residual.free()
        resbuf.free()
        try:
            var _ = close(c_int(epfd))
        except:
            pass
        try:
            var _ = close(listener_fd)
        except:
            pass
        
    except e:
        print("FaF Worker", data.worker_id, "error:", e)
    
    return UnsafePointer[UInt8]()

# ===----------------------------------------------------------------------=== #
# Enhanced AsyncRuntime for FaF
# ===----------------------------------------------------------------------=== #

struct FafAsyncRuntime:
    """Enhanced AsyncRuntime specifically designed for FaF-style HTTP server."""
    var num_workers: Int
    var threads: UnsafePointer[UInt64]
    var worker_data: UnsafePointer[FafWorkerData]
    var started: Bool
    var port: UInt16
    # TODO: Add proper global state when Mojo supports it
    
    fn __init__(out self, port: UInt16, num_workers: Int = 0):
        var actual_workers = num_workers if num_workers > 0 else num_logical_cores()
        # Allow multiple workers for debugging
        actual_workers = min(actual_workers, 4)  # Limit to 4 for debugging
        
        self.num_workers = actual_workers
        self.port = port
        self.threads = UnsafePointer[UInt64].alloc(actual_workers)
        self.worker_data = UnsafePointer[FafWorkerData].alloc(actual_workers)
        self.started = False
        
        print("Note: Testing", actual_workers, "worker(s) for multi-worker debugging")
        
        # Test SO_REUSEPORT support at startup
        print("Testing SO_REUSEPORT support on this system...")
        if test_so_reuseport_support():
            print("✅ SO_REUSEPORT is supported on this system")
        else:
            print("❌ SO_REUSEPORT is NOT supported on this system")
            print("Multi-worker mode will be limited to single worker")
        
        # Initialize worker data with CPU affinity
        for i in range(actual_workers):
            self.worker_data[i] = FafWorkerData(
                worker_id=i, 
                cpu_core=i, 
                port=port, 
                num_cpu_cores=actual_workers
            )
    
    fn start_faf_workers(mut self):
        """Start FaF worker threads using pthread."""
        if self.started:
            return
        
        print("Starting", self.num_workers, "FaF worker threads")
        
        for i in range(self.num_workers):
            var thread_ptr = (self.threads + i).bitcast[UInt8]()
            var data_ptr = (self.worker_data + i).bitcast[UInt8]()
            
            # TODO: Use enhanced pthread_create with custom stack size (8MB like FaF)
            var result = external_call["pthread_create", Int32](
                thread_ptr,
                UnsafePointer[UInt8](),  # TODO: Add pthread attributes for stack size
                faf_threaded_worker,
                data_ptr
            )
            
            if result != 0:
                print("Failed to create worker thread", i)
            
            # Small delay to ensure workers are initialized in sequence (like FaF)
            sleep(0.005)  # 5ms
        
        self.started = True
        
        # TODO: Update HTTP date before workers start processing (needs global state)
    
    fn wait_for_workers(self):
        """Wait for all worker threads to complete."""
        if not self.started:
            return
        
        print("Waiting for FaF workers to complete...")
        for i in range(self.num_workers):
            var result = external_call["pthread_join", Int32](
                self.threads[i],
                UnsafePointer[UInt8]()
            )
            if result != 0:
                print("Failed to join worker thread", i)
    
    fn run_date_update_loop(mut self):
        """Run the HTTP date update loop (like FaF main thread)."""
        print("Starting HTTP date update loop...")
        
        # TODO: Implement nanosleep for precise timing like FaF
        # TODO: Implement global HTTP date updating when global state is available
        # const SLEEP_TIME: timespec = timespec { tv_sec: 1, tv_nsec: 0 };
        while True:
            # TODO: update global HTTP date here
            sleep(1.0)  # 1 second - TODO: use nanosleep for precision
    
    fn shutdown(mut self):
        """Shutdown the FaF runtime."""
        if self.started:
            # TODO: Graceful shutdown by signaling workers
            # For now, workers run indefinitely
            print("TODO: Implement graceful shutdown")
            
        self.threads.free()
        self.worker_data.free()
        self.started = False

# ===----------------------------------------------------------------------=== #
# Callback function
# ===----------------------------------------------------------------------=== #

fn example_callback_faf(
    method: UnsafePointer[UInt8], method_len: Int,
    path: UnsafePointer[UInt8], path_len: Int, 
    response: UnsafePointer[UInt8],
    http_date: UnsafePointer[UInt8]
) -> Int:
    """Example HTTP callback function for FaF."""
    # TODO: Use the actual HTTP date from http_date parameter
    var response_str = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
    var response_bytes = response_str.as_bytes()
    memcpy(response, response_bytes.unsafe_ptr(), len(response_bytes))
    return len(response_bytes)

# ===----------------------------------------------------------------------=== #
# Main FaF server function
# ===----------------------------------------------------------------------=== #

fn faf_go(port: UInt16, num_workers: Int = 0):
    """Main FaF server function - direct translation from Rust go() function."""
    print("Starting FaF HTTP server on port", port)
    
    # Attempt to set higher process priority (like FaF)
    var priority_result = sys_setpriority(PRIO_PROCESS, 0, -19)
    if priority_result != 0:
        print("Warning: Could not set priority: setpriority: Permission denied")
    
    # Create FaF runtime
    var faf_runtime = FafAsyncRuntime(port, num_workers)
    
    # Start worker threads
    faf_runtime.start_faf_workers()
    
    print("All FaF workers started and listening on port", port)
    print("Try: curl http://localhost:" + String(port))
    print("Press Ctrl+C to stop the server")
    
    # Give workers a moment to start their epoll loops
    sleep(0.1)
    
    # Run the HTTP date update loop (blocking, like FaF main thread)
    # TODO: For proof of concept, we'll run a limited version
    print("HTTP date update loop started...")
    var loop_count = 0
    while loop_count < 1000:  # Limit for demonstration
        sleep(1.0)
        loop_count += 1
        if loop_count % 10 == 0:
            print("Server running... handled", loop_count, "date updates")

# ===--------------------------------------- -------------------------------=== #
# Proof of Concept Demo
# ===----------------------------------------------------------------------=== #

fn main():
    """Proof of concept demo."""
    print("FaF HTTP Server Proof of Concept")
    print("Features implemented:")
    print("✅ pthread-based worker threads")
    print("✅ Epoll event loop per worker")  
    print("✅ FaF-style buffer management")
    print("✅ HTTP request parsing")
    print("✅ Socket setup with error handling")
    print()
    print("Features limited for proof of concept:")
    print("⚠️  Single worker only (SO_REUSEPORT issues)")
    print("⚠️  Simplified global state management")
    print()
    print("TODO Features needed for full FaF compatibility:")
    print("❌ Multiple workers with SO_REUSEPORT")
    print("❌ CPU affinity binding (sys_set_cpu_affinity)")
    print("❌ FD table unsharing (sys_unshare_fd_table)")
    print("❌ Thread naming (sys_set_thread_name)")
    print("❌ Custom pthread stack sizes")
    print("❌ TCP_NODELAY and socket options")
    print("❌ REUSEPORT CBPF attachment")
    print("❌ SIMD HTTP parsing")
    print("❌ Precise HTTP date formatting")
    print("❌ 64-byte memory alignment")
    print("❌ Nanosleep for precise timing")
    print("❌ Global state synchronization")
    print()
    
    # Start the server (this will run indefinitely)
    print("Testing with 2 workers to debug SO_REUSEPORT...")
    faf_go(8080, 2)  # Test with 2 workers
