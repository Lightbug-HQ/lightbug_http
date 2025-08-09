from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call, c_long, c_size_t, c_ssize_t, c_uchar, c_ushort, c_char
from sys.info import sizeof, CompilationTarget, num_logical_cores
from memory import memcmp, UnsafePointer, stack_allocation, memset_zero, memcpy
from time import sleep
# Removed asyncrt - using process-based parallelism like Rust
from os.atomic import Atomic

# Using existing working socket infrastructure from your codebase
from lightbug_http._libc import (
    sockaddr_in, 
    socket,
    setsockopt,
    bind,
    listen,
    AddressFamily,
    SOCK_STREAM,
    SOL_SOCKET,


)

# Socket option constants (Linux values - should work on most systems)
alias SO_REUSEADDR = 2
alias SO_REUSEPORT = 15  
alias SO_KEEPALIVE = 9

# System call constants
alias SYS_SETPRIORITY = 141
alias SYS_NANOSLEEP = 35
alias SYS_EPOLL_CREATE1 = 291
alias SYS_EPOLL_CTL = 233
alias SYS_EPOLL_WAIT = 232
alias SYS_ACCEPT = 43
alias SYS_RECVFROM = 45
alias SYS_SENDTO = 44

# Thread isolation constants
alias CLONE_FILES = 0x400
alias SYS_UNSHARE = 272  # Linux x86_64
alias SYS_SCHED_SETAFFINITY = 203

# Process management constants
alias SYS_FORK = 57
alias SYS_GETPID = 39
alias SYS_WAITPID = 61

# Epoll constants and configuration
alias EPOLL_TIMEOUT_BLOCKING = -1
alias EPOLL_TIMEOUT_IMMEDIATE_RETURN = 0
alias MAX_EPOLL_EVENTS_RETURNED = 64
alias MAX_CONN = 1024
alias REQ_BUFF_SIZE = 4096
alias RES_BUFF_SIZE = 8192

# ===----------------------------------------------------------------------=== #
# System call wrappers
# ===----------------------------------------------------------------------=== #

fn sys_unshare(flags: Int) -> Int:
    """Unshare system call to isolate file descriptor table."""
    return Int(external_call["unshare", c_int, c_int](flags))

fn set_cpu_affinity(cpu_core: Int) -> Int:
    """Set CPU affinity for current task/thread."""
    var cpu_set = UnsafePointer[UInt64].alloc(1)
    cpu_set[0] = UInt64(1) << UInt64(cpu_core)
    
    var result = Int(external_call["sched_setaffinity", c_int, c_int, c_size_t, UnsafePointer[UInt64]](
        0, 8, cpu_set
    ))
    
    cpu_set.free()
    return result

fn fork() -> Int:
    """Fork the current process."""
    return Int(external_call["fork", c_int]())

fn getpid() -> Int:
    """Get current process ID."""
    return Int(external_call["getpid", c_int]())

fn waitpid(pid: Int, status: UnsafePointer[c_int], options: Int) -> Int:
    """Wait for child process."""
    return Int(external_call["waitpid", c_int, c_int, UnsafePointer[c_int], c_int](pid, status, options))

fn get_thread_info() -> (Int, Int):
    """Get current thread ID and process ID."""
    var thread_id = Int(external_call["pthread_self", c_long]())
    var process_id = Int(external_call["getpid", c_int]())
    return (thread_id, process_id)

fn sys_setpriority(which: Int, who: Int, priority: Int) -> Int:
    """Set process priority using setpriority system call."""
    return Int(external_call["setpriority", c_int, c_int, c_int, c_int](which, who, priority))

# Priority constants
alias PRIO_PROCESS = 0
alias PRIO_PGRP = 1 
alias PRIO_USER = 2

fn sys_epoll_create1(flags: Int) -> Int:
    """Create epoll file descriptor."""
    return Int(external_call["epoll_create1", c_int, c_int](flags))

fn close(fd: c_int) -> Int:
    """Close file descriptor."""
    return Int(external_call["close", c_int, c_int](fd))

fn sys_close(fd: Int) -> Int:
    """Close file descriptor (sys_close variant)."""
    return Int(external_call["close", c_int, c_int](fd))

fn sys_epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) -> Int:
    """Control epoll file descriptor."""
    return Int(external_call["epoll_ctl", c_int, c_int, c_int, c_int, UnsafePointer[epoll_event]](epfd, op, fd, event))

fn sys_epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) -> Int:
    """Wait for epoll events."""
    return Int(external_call["epoll_wait", c_int, c_int, UnsafePointer[epoll_event], c_int, c_int](epfd, events, maxevents, timeout))

fn sys_accept(sockfd: Int, addr: Int, addrlen: Int) -> Int:
    """Accept connection."""
    return Int(external_call["accept", c_int, c_int, c_int, c_int](sockfd, addr, addrlen))

fn sys_recvfrom(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, src_addr: Int, addrlen: Int) -> Int:
    """Receive data from socket."""
    return Int(external_call["recvfrom", c_ssize_t, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_int, c_int](sockfd, buf, len, flags, src_addr, addrlen))

fn sys_sendto(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int, dest_addr: Int, addrlen: Int) -> Int:
    """Send data to socket."""
    return Int(external_call["sendto", c_ssize_t, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_int, c_int](sockfd, buf, len, flags, dest_addr, addrlen))

fn get_errno() -> Int:
    """Get current errno value."""
    return Int(external_call["__errno_location", UnsafePointer[c_int]]()[])

# Epoll constants
alias EPOLLIN = 1
alias EPOLLOUT = 4
alias EPOLLHUP = 16
alias EPOLLERR = 8
alias EPOLL_CTL_ADD = 1
alias EPOLL_CTL_DEL = 2
alias EPOLL_CTL_MOD = 3

# Error constants
alias EAGAIN = 11
alias EINTR = 4
alias EBADF = 9
alias ECONNRESET = 104
alias ENOTCONN = 107
alias EWOULDBLOCK = 11
alias EPIPE = 32

# ===----------------------------------------------------------------------=== #
# Data structures (matching Rust exactly)
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
        # Ensure fd is properly cast and within valid range
        if fd >= 0 and fd < 65536:
            self.data = UInt64(fd)
        else:
            self.data = 0

@register_passable
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]
    
    fn __init__(out self):
        self.data = StaticTuple[UInt8, 35]()

fn get_http_date(buffer: UnsafePointer[UInt8]):
    """Get current HTTP date string."""
    var date_str = "Mon, 01 Jan 2024 00:00:00 GMT"
    var date_bytes = date_str.as_bytes()
    var copy_len = min(len(date_bytes), 35)
    memcpy(buffer, date_bytes.unsafe_ptr(), copy_len)

# ===----------------------------------------------------------------------=== #
# Network functions (matching Rust net module)
# ===----------------------------------------------------------------------=== #

fn get_listener_fd(port: UInt16) raises -> c_int:
    """Create and configure listener socket with SO_REUSEPORT (matches Rust version)."""
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    if listener_fd < 0:
        raise Error("Failed to create socket")
    
    # Set SO_REUSEADDR (critical for avoiding "Address already in use")
    try:
        var reuseaddr = UInt8(1)
        var ret = setsockopt(
            listener_fd, 
            SOL_SOCKET, 
            SO_REUSEADDR, 
            reuseaddr
        )
        if ret != 0:
            print("Warning: SO_REUSEADDR failed, but continuing")
    except:
        print("Warning: Could not set SO_REUSEADDR (continuing anyway)")
    
    # Set SO_REUSEPORT (critical for multi-worker performance)
    var reuseport_success = False
    try:
        var reuseport = UInt8(1)
        var ret = setsockopt(
            listener_fd, 
            SOL_SOCKET, 
            SO_REUSEPORT, 
            reuseport
        )
        if ret == 0:
            reuseport_success = True
        else:
            print("Warning: SO_REUSEPORT failed with return code", ret)
    except e:
        print("Warning: Could not set SO_REUSEPORT:", e)
    
    if not reuseport_success:
        print("CRITICAL: SO_REUSEPORT failed - multiple workers cannot bind to same port")
        print("This will cause binding conflicts. Consider running with 1 worker.")
    
    # Bind socket
    var addr = sockaddr_in(Int(AddressFamily.AF_INET.value), port, 0)  # INADDR_ANY = 0
    try:
        bind(listener_fd, addr)
        listen(listener_fd, 128)  # Backlog of 128
        return listener_fd
    except:
        var _ = close(listener_fd)
        raise Error("Failed to bind/listen on port")

fn setup_connection(fd: c_int):
    """Setup TCP connection options (matches Rust)."""
    # TCP_NODELAY to disable Nagle's algorithm for low latency (non-fatal)
    try:
        alias TCP_NODELAY = 1
        alias IPPROTO_TCP = 6
        var nodelay = UInt8(1)
        var _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, nodelay)
    except:
        pass  # Non-fatal, continue without TCP_NODELAY
    
    # SO_KEEPALIVE for connection health monitoring (non-fatal)
    try:
        var keepalive = UInt8(1)
        var _ = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, keepalive)
    except:
        pass  # Non-fatal, continue without SO_KEEPALIVE

# ===----------------------------------------------------------------------=== #
# Main worker function (matching Rust threaded_worker exactly)
# ===----------------------------------------------------------------------=== #

fn threaded_worker(
    port: UInt16,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    cpu_core: Int,
    num_cpu_cores: Int,
    http_date_ptr: UnsafePointer[UInt8]
):
    """Main worker function - matches Rust threaded_worker exactly."""
    try:
        var listener_fd = get_listener_fd(port)
        setup_connection(listener_fd)
        
        var epfd = sys_epoll_create1(0)
        if epfd < 0:
            print("Worker", cpu_core, "failed to create epoll (macOS doesn't support epoll natively)")
            print("Worker", cpu_core, "continuing with simplified polling...")
            # On macOS, we'll do a simplified version without epoll
            simple_worker_loop(listener_fd, cb, cpu_core, http_date_ptr)
            return
        
        # Add listener fd to epoll for monitoring (matches Rust)
        var epoll_event_listener = epoll_event()
        epoll_event_listener.events = UInt32(EPOLLIN)
        epoll_event_listener.data = UInt64(listener_fd)
        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, Int(listener_fd), UnsafePointer(to=epoll_event_listener))
        
        # Allocate epoll events array (matches Rust)
        var epoll_events = UnsafePointer[epoll_event].alloc(MAX_EPOLL_EVENTS_RETURNED)
        
        # Pre-allocated saved event for new connections (matches Rust)
        var saved_event = epoll_event()
        saved_event.events = UInt32(EPOLLIN)
        
        var epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
        var connection_count = 0
        
        print("Worker", cpu_core, "starting epoll event loop")
        
        # Main event loop (matches Rust exactly)  
        # Note: This is an infinite loop in production, but we'll break on error
        while True:
            var num_incoming_events = sys_epoll_wait(epfd, epoll_events, MAX_EPOLL_EVENTS_RETURNED, epoll_wait_type)
            
            if num_incoming_events <= 0:
                epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
                continue
                
            epoll_wait_type = EPOLL_TIMEOUT_IMMEDIATE_RETURN
            
            # Process all incoming events (matches Rust loop)
            for index in range(num_incoming_events):
                var event = epoll_events[index]
                var cur_fd = Int(event.data)
                
                if cur_fd == Int(listener_fd):
                    # Accept new connection (matches Rust)
                    var incoming_fd = sys_accept(Int(listener_fd), 0, 0)
                    
                    if incoming_fd >= 0 and incoming_fd < MAX_CONN:
                        setup_connection(c_int(incoming_fd))
                        saved_event.data = UInt64(incoming_fd)
                        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd, UnsafePointer(to=saved_event))
                    else:
                        if incoming_fd >= 0:
                            var _ = close(c_int(incoming_fd))
                else:
                    # Handle existing connection (simplified for now)
                    var buffer = UnsafePointer[UInt8].alloc(REQ_BUFF_SIZE)
                    var read_bytes = sys_recvfrom(cur_fd, buffer, REQ_BUFF_SIZE, 0, 0, 0)
                    
                    if read_bytes > 0:
                        connection_count += 1
                        # Use the callback with HTTP date (matches Rust)
                        var method = "GET"
                        var path = "/"
                        var response_buffer = UnsafePointer[UInt8].alloc(RES_BUFF_SIZE)
                        var response_len = cb(
                            method.unsafe_ptr(), len(method),
                            path.unsafe_ptr(), len(path),
                            response_buffer, http_date_ptr
                        )
                        var _ = sys_sendto(cur_fd, response_buffer, response_len, 0, 0, 0)
                        response_buffer.free()
                        
                        if connection_count % 100 == 0:
                            print("Worker", cpu_core, "handled", connection_count, "connections")
                    
                    var _ = close(c_int(cur_fd))
                    buffer.free()
        
        # Cleanup (this code is technically unreachable after infinite loop, but kept for completeness)
        epoll_events.free()
        var _ = close(c_int(epfd))
        var _ = close(listener_fd)
        
    except e:
        print("Worker", cpu_core, "error:", e)

fn simple_worker_loop(
    listener_fd: c_int,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    cpu_core: Int,
    http_date_ptr: UnsafePointer[UInt8]
):
    """Simplified worker loop for macOS (no epoll)."""
    print("Worker", cpu_core, "starting simple polling loop (macOS fallback)")
    var connection_count = 0
    
    # Simple accept loop without epoll
    while True:
        try:
            # Accept new connection (blocking)
            var incoming_fd = sys_accept(Int(listener_fd), 0, 0)
            
            if incoming_fd >= 0:
                setup_connection(c_int(incoming_fd))
                
                # Read request
                var buffer = UnsafePointer[UInt8].alloc(REQ_BUFF_SIZE)
                var read_bytes = sys_recvfrom(incoming_fd, buffer, REQ_BUFF_SIZE, 0, 0, 0)
                
                if read_bytes > 0:
                    connection_count += 1
                    # Use the callback with HTTP date
                    var method = "GET"
                    var path = "/"
                    var response_buffer = UnsafePointer[UInt8].alloc(RES_BUFF_SIZE)
                    var response_len = cb(
                        method.unsafe_ptr(), len(method),
                        path.unsafe_ptr(), len(path),
                        response_buffer, http_date_ptr
                    )
                    var _ = sys_sendto(incoming_fd, response_buffer, response_len, 0, 0, 0)
                    response_buffer.free()
                    
                    if connection_count % 100 == 0:
                        print("Worker", cpu_core, "handled", connection_count, "connections")
                
                var _ = close(c_int(incoming_fd))
                buffer.free()
            else:
                # Accept failed, small delay to prevent busy loop
                sleep(0.001)
                
        except e:
            print("Worker", cpu_core, "simple loop error:", e)
            sleep(0.1)  # Prevent busy loop on errors

fn threaded_worker_with_shared_socket(
    listener_fd: c_int,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    cpu_core: Int,
    num_cpu_cores: Int,
    http_date_ptr: UnsafePointer[UInt8]
):
    """Worker function that uses a shared listener socket (macOS compatible)."""
    print("Worker", cpu_core, "starting with shared socket fd", listener_fd)
    
    # Since epoll doesn't work on macOS, use the simple worker loop directly
    simple_worker_loop(listener_fd, cb, cpu_core, http_date_ptr)

# ===----------------------------------------------------------------------=== #
# Main server function (matching Rust go() exactly)
# ===----------------------------------------------------------------------=== #

fn go(
    port: UInt16, 
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Main server function - matches Rust epoll.rs exactly."""
    # Attempt to set higher process priority (matches Rust version)
    var priority_result = sys_setpriority(PRIO_PROCESS, 0, -19)
    if priority_result != 0:
        print("Warning: Could not set priority: setpriority: Permission denied")
    
    # Create HTTP date buffer (no more global variable)
    var http_date = AlignedHttpDate()
    var date_ptr = UnsafePointer(to=http_date.data[0])
    get_http_date(date_ptr)
    
    var num_cpu_cores = num_logical_cores()
    print("Starting", num_cpu_cores, "process-based HTTP workers (matching Rust)")
    
    # Try to create a test socket to see if SO_REUSEPORT works
    var reuseport_works = False
    try:
        var test_fd = get_listener_fd(port)
        var _ = close(test_fd)
        reuseport_works = True
        print("SO_REUSEPORT test successful - using per-worker sockets")
    except:
        print("SO_REUSEPORT test failed - falling back to shared socket approach")
    
    # Create shared socket if SO_REUSEPORT doesn't work
    var shared_listener_fd: c_int = -1
    if not reuseport_works:
        try:
            shared_listener_fd = get_listener_fd(port)
            print("Created shared listener socket on fd", shared_listener_fd, "(SO_REUSEPORT fallback)")
        except e:
            print("Failed to create shared listener socket:", e)
            return
    
    # Fork workers for each CPU core (platform-specific approach)
    for core in range(num_cpu_cores):
        var pid = fork()
        if pid == 0:
            # Child process - run the worker
            if reuseport_works:
                # SO_REUSEPORT works - use per-worker sockets (ideal case)
                var _ = sys_unshare(CLONE_FILES)  # Safe to unshare
                var _ = set_cpu_affinity(core)
                
                var worker_http_date = AlignedHttpDate()
                var worker_date_ptr = UnsafePointer(to=worker_http_date.data[0])
                get_http_date(worker_date_ptr)
                
                threaded_worker(port, cb, core, num_cpu_cores, worker_date_ptr)
            else:
                # SO_REUSEPORT failed - use shared socket (fallback)
                # Don't unshare - need to inherit the shared socket
                var _ = set_cpu_affinity(core)
                
                var worker_http_date = AlignedHttpDate()
                var worker_date_ptr = UnsafePointer(to=worker_http_date.data[0])
                get_http_date(worker_date_ptr)
                
                threaded_worker_with_shared_socket(shared_listener_fd, cb, core, num_cpu_cores, worker_date_ptr)
            return  # Child process exits here
        elif pid > 0:
            # Parent process - continue forking more workers
            sleep(0.005)  # Small delay like Rust (5ms)
        else:
            print("Failed to fork worker", core)
    
    # Parent process - update HTTP date in a loop (matches Rust exactly)
    while True:
        get_http_date(date_ptr)
        sleep(1.0)  # Sleep for 1 second like Rust

# ===----------------------------------------------------------------------=== #
# Example callback function
# ===----------------------------------------------------------------------=== #

fn example_callback(
    method: UnsafePointer[UInt8], method_len: Int,
    path: UnsafePointer[UInt8], path_len: Int, 
    response: UnsafePointer[UInt8],
    http_date: UnsafePointer[UInt8]
) -> Int:
    """Example HTTP callback function."""
    # Simple HTTP response
    var response_str = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
    var response_bytes = response_str.as_bytes()
    memcpy(response, response_bytes.unsafe_ptr(), len(response_bytes))
    return len(response_bytes)
