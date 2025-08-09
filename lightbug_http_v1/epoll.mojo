from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call, c_long, c_size_t, c_uchar, c_ushort, c_char
from sys.info import sizeof, CompilationTarget, num_logical_cores
from memory import memcmp, UnsafePointer, stack_allocation, memset_zero, memcpy
from time import sleep
from runtime import asyncrt
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
    SOL_SOCKET,
    get_errno,
    EAGAIN,
    EWOULDBLOCK
)

# Correct socket option constants for Ubuntu/Linux
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

# Epoll-based HTTP server using Mojo's async runtime
# This translates the Rust threading approach to async tasks

# ===----------------------------------------------------------------------=== #
# Epoll Constants
# ===----------------------------------------------------------------------=== #

alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUFF_SIZE = 1024  # Match Rust naming
alias RES_BUFF_SIZE = 1024  # Match Rust naming
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

# Priority constants
alias PRIO_PROCESS = 0
alias PRIO_PGRP = 1
alias PRIO_USER = 2

# ===----------------------------------------------------------------------=== #
# Epoll structures and system call wrappers
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
        if fd >= 0 and fd < 65536:  # Reasonable FD limit
            self.data = UInt64(fd)
        else:
            self.data = 0

@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]  # Match Rust size
    
    fn __init__(out self):
        self.data = StaticTuple[UInt8, 35]()

# Note: Mojo doesn't support global variables, so we'll pass these as parameters

# Direct system call wrappers using external_call
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

fn sys_setsockopt(sockfd: Int, level: Int, optname: Int, optval: UnsafePointer[c_int], optlen: Int) -> Int:
    """Set socket options."""
    return Int(external_call["setsockopt", c_int, c_int, c_int, c_int, UnsafePointer[c_int], c_uint](sockfd, level, optname, optval, optlen))

# ===----------------------------------------------------------------------=== #
# Thread isolation functions
# ===----------------------------------------------------------------------=== #

fn sys_unshare(flags: Int) -> Int:
    """Unshare parts of the execution context."""
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

# HTTP date function (simplified but proper format)
fn get_http_date(buf: UnsafePointer[UInt8]):
    """Get current HTTP date string."""
    # Simplified - real implementation would get actual current date
    var date_str = "Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    var date_bytes = date_str.as_bytes()
    memcpy(buf, date_bytes.unsafe_ptr(), min(len(date_bytes), 35))

# ===----------------------------------------------------------------------=== #
# Socket setup functions matching Rust net::get_listener_fd
# ===----------------------------------------------------------------------=== #

fn get_listener_fd(port: UInt16) raises -> (c_int, Bool, Bool):
    """Create and configure listener socket with SO_REUSEPORT (matches Rust version)."""
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    if listener_fd < 0:
        return (-1, False, False)
    
    # Set SO_REUSEADDR
    var reuseaddr = c_int(1)
    var ret = sys_setsockopt(
        Int(listener_fd), 
        SOL_SOCKET, 
        SO_REUSEADDR, 
        UnsafePointer(to=reuseaddr), 
        sizeof[c_int]()
    )
    
    # Set SO_REUSEPORT (critical for multi-worker performance)
    var reuseport = c_int(1)
    var _ = sys_setsockopt(
        Int(listener_fd), 
        SOL_SOCKET, 
        SO_REUSEPORT, 
        UnsafePointer(to=reuseport), 
        sizeof[c_int]()
    )
    
    # Bind socket
    var addr = sockaddr_in(Int(AddressFamily.AF_INET.value), port, 0)  # INADDR_ANY = 0
    try:
        bind(listener_fd, addr)
    except:
        var _ = close(listener_fd)
        return (-1, False, False)
    
    # Listen
    try:
        listen(listener_fd, 128)
    except:
        var _ = close(listener_fd)
        return (-1, False, False)
    
    return (listener_fd, True, True)

fn setup_connection(fd: Int):
    """Set up connection options with TCP optimizations."""
    # TCP_NODELAY to disable Nagle's algorithm for low latency
    alias TCP_NODELAY = 1
    alias IPPROTO_TCP = 6
    
    var nodelay = c_int(1)
    var _ = sys_setsockopt(
        fd,
        IPPROTO_TCP,
        TCP_NODELAY,
        UnsafePointer(to=nodelay),
        sizeof[c_int]()
    )
    
    # SO_KEEPALIVE for connection health monitoring
    var keepalive = c_int(1)
    var _ = sys_setsockopt(
        fd,
        SOL_SOCKET,
        SO_KEEPALIVE,
        UnsafePointer(to=keepalive),
        sizeof[c_int]()
    )

fn close_connection(epfd: Int, fd: Int):
    """Close connection and remove from epoll (matches Rust net::close_connection)."""
    var _ = sys_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, UnsafePointer[epoll_event]())
    try:
        var _ = close(c_int(fd))
    except:
        pass

# ===----------------------------------------------------------------------=== #
# HTTP request parsing (simplified version)
# ===----------------------------------------------------------------------=== #

fn parse_request_path_simple(
    request_buffer: UnsafePointer[UInt8],
    buffer_len: Int,
    method: UnsafePointer[UnsafePointer[UInt8]],
    method_len: UnsafePointer[Int],
    path: UnsafePointer[UnsafePointer[UInt8]],
    path_len: UnsafePointer[Int]
) -> Int:
    """Simple HTTP request parser - returns bytes parsed or 0 if incomplete."""
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

# ===----------------------------------------------------------------------=== #
# Simplified async worker function (following async_demo.mojo pattern)
# ===----------------------------------------------------------------------=== #

async fn epoll_worker(worker_id: Int):
    """Async epoll-based HTTP worker with thread isolation experiments."""
    print("Worker", worker_id, "ASYNC TASK STARTED!")
    
    # EXPERIMENT 1: Check what thread we're actually running on
    var (thread_id, process_id) = get_thread_info()
    print("Worker", worker_id, "running on thread:", thread_id, "process:", process_id)
    
    # EXPERIMENT 2: Try to unshare file descriptor table
    print("Worker", worker_id, "attempting unshare(CLONE_FILES)")
    var unshare_result = sys_unshare(CLONE_FILES)
    if unshare_result == 0:
        print("Worker", worker_id, "SUCCESS: Unshared FD table!")
    else:
        var errno = get_errno()
        print("Worker", worker_id, "FAILED unshare")
    
    # EXPERIMENT 3: Try to set CPU affinity
    print("Worker", worker_id, "attempting CPU affinity")
    var affinity_result = set_cpu_affinity(worker_id % num_logical_cores())
    if affinity_result == 0:
        print("Worker", worker_id, "SUCCESS: Set CPU affinity to core", worker_id % num_logical_cores())
    else:
        var errno = get_errno()
        print("Worker", worker_id, "FAILED CPU affinity")
    
    print("Worker", worker_id, "isolation experiments completed - starting socket operations")
    
    try:
        # Create listener socket for this worker (with SO_REUSEPORT) - all workers use same port
        print("Worker", worker_id, "calling get_listener_fd...")
        var (listener_fd, success1, success2) = get_listener_fd(UInt16(8080))  # Same port for all workers
        if listener_fd < 0:
            print("Worker", worker_id, "failed to create listener socket")
            return
        
        print("Worker", worker_id, "got listener_fd:", listener_fd)
        setup_connection(Int(listener_fd))
        print("Worker", worker_id, "listener socket created, sharing port 8080")
        
        # Create epoll instance
        var epfd = sys_epoll_create1(0)
        if epfd < 0:
            print("Worker", worker_id, "failed to create epoll")
            try:
                var _ = close(listener_fd)
            except:
                pass
            return
        
        # Add listener fd to epoll for monitoring
        var epoll_event_listener = epoll_event(EPOLLIN, Int(listener_fd))
        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, Int(listener_fd), UnsafePointer(to=epoll_event_listener))
        
        # Allocate event array and buffers
        var epoll_events = UnsafePointer[epoll_event].alloc(MAX_EPOLL_EVENTS_RETURNED)
        memset_zero(epoll_events, MAX_EPOLL_EVENTS_RETURNED * sizeof[epoll_event]())
        
        print("Worker", worker_id, "allocated epoll events array, size per event:", sizeof[epoll_event]())
        
        var saved_event = epoll_event(EPOLLIN, 0)
        
        # Request buffer management (matches Rust version)
        var reqbuf = UnsafePointer[UInt8].alloc(REQ_BUFF_SIZE * MAX_CONN)
        memset_zero(reqbuf, REQ_BUFF_SIZE * MAX_CONN)
        
        # Track buffer positions and residuals per connection (matches Rust)
        var reqbuf_cur_addr = UnsafePointer[UInt64].alloc(MAX_CONN)
        var reqbuf_residual = UnsafePointer[Int].alloc(MAX_CONN)
        memset_zero(reqbuf_cur_addr, MAX_CONN * sizeof[UInt64]())
        memset_zero(reqbuf_residual, MAX_CONN * sizeof[Int]())
        
        # Initialize buffer addresses (matches Rust initialization)
        var reqbuf_start_address = Int(reqbuf)
        for i in range(MAX_CONN):
            reqbuf_cur_addr[i] = UInt64(reqbuf_start_address + i * REQ_BUFF_SIZE)
        
        # Response buffer
        var resbuf = UnsafePointer[UInt8].alloc(RES_BUFF_SIZE)
        var resbuf_start_address = Int(resbuf)
        
        # Use shorter timeout to allow cooperative multitasking
        var epoll_wait_type = 10  # 10ms timeout instead of blocking
        var connections_handled = 0
        var max_connections = 10000  # Increased for stress testing
        
        print("Worker", worker_id, "starting epoll event loop")
        
        # Main epoll event loop (matches Rust version exactly)
        while connections_handled < max_connections:
            # Add cooperative yielding for single-threaded async runtime
            if connections_handled % 10 == 0:
                sleep(0.001)  # Yield control briefly to allow other workers
            
            var num_incoming_events = sys_epoll_wait(epfd, epoll_events, MAX_EPOLL_EVENTS_RETURNED, epoll_wait_type)
            
            if num_incoming_events <= 0:
                epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
                continue
            
            if num_incoming_events > 0:
                print("Worker", worker_id, "got", num_incoming_events, "epoll events")
            
            epoll_wait_type = EPOLL_TIMEOUT_IMMEDIATE_RETURN
            
            for index in range(num_incoming_events):
                var event = epoll_events[index]
                var cur_fd_raw = event.data
                
                # Validate and extract file descriptor safely
                if cur_fd_raw > UInt64(MAX_CONN) or cur_fd_raw > UInt64(65535):
                    print("Worker", worker_id, "corrupted fd data:", cur_fd_raw, "- skipping")
                    continue
                
                var cur_fd = Int(cur_fd_raw)
                
                # Additional bounds checking for file descriptor
                if cur_fd < 0 or cur_fd >= MAX_CONN:
                    print("Worker", worker_id, "invalid fd:", cur_fd, "- closing")
                    close_connection(epfd, cur_fd)
                    continue
                
                var req_buf_start_address = reqbuf_start_address + cur_fd * REQ_BUFF_SIZE
                var req_buf_cur_position = reqbuf_cur_addr[cur_fd]
                var residual = reqbuf_residual[cur_fd]
                
                if cur_fd == Int(listener_fd):
                    # Accept new connection (matches Rust)
                    var incoming_fd = sys_accept(Int(listener_fd), 0, 0)
                    
                    if incoming_fd < 0:
                        # Accept failed - could be EAGAIN/EWOULDBLOCK
                        var errno = get_errno()
                        if errno != EAGAIN and errno != EWOULDBLOCK:
                            print("Worker", worker_id, "accept failed with errno", errno)
                        continue
                    
                    if incoming_fd >= MAX_CONN:
                        print("Worker", worker_id, "fd", incoming_fd, "exceeds MAX_CONN, closing")
                        var _ = close(c_int(incoming_fd))
                        continue
                    
                    if incoming_fd >= 0 and incoming_fd < MAX_CONN:
                        # Reset buffer state for this connection (matches Rust)
                        reqbuf_cur_addr[incoming_fd] = UInt64(reqbuf_start_address + incoming_fd * REQ_BUFF_SIZE)
                        reqbuf_residual[incoming_fd] = 0
                        
                        setup_connection(incoming_fd)
                        saved_event.data = UInt64(incoming_fd)
                        
                        print("Worker", worker_id, "adding fd", incoming_fd, "to epoll with data", saved_event.data)
                        var epoll_result = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd, UnsafePointer(to=saved_event))
                        if epoll_result != 0:
                            var errno = get_errno()
                            print("Worker", worker_id, "epoll_ctl ADD failed for fd", incoming_fd, "errno", errno)
                            # Close the connection since we can't monitor it
                            var _ = close(c_int(incoming_fd))
                            continue
                    else:
                        close_connection(epfd, cur_fd)
                else:
                    # Handle client connection (matches Rust buffer management)
                    # Add bounds checking to prevent buffer overflows
                    if cur_fd >= MAX_CONN:
                        close_connection(epfd, cur_fd)
                        continue
                    
                    var buffer_remaining = REQ_BUFF_SIZE - Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    if buffer_remaining <= 0:
                        # Buffer full, reset and close connection
                        reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                        reqbuf_residual[cur_fd] = 0
                        close_connection(epfd, cur_fd)
                        continue
                    
                    var buf_ptr = reqbuf + (cur_fd * REQ_BUFF_SIZE) + Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    var read_bytes = sys_recvfrom(cur_fd, buf_ptr, buffer_remaining, 0, 0, 0)
                    
                    if read_bytes > 0:
                        var request_buffer_offset = 0
                        var response_buffer_filled_total = 0
                        
                        # Process potentially multiple pipelined requests (matches Rust)
                        while request_buffer_offset != (read_bytes + residual):
                            var method = UnsafePointer[UInt8]()
                            var method_len = 0
                            var path = UnsafePointer[UInt8]()
                            var path_len = 0
                            
                            var parse_buf_ptr = buf_ptr - residual + request_buffer_offset
                            var request_buffer_bytes_parsed = parse_request_path_simple(
                                parse_buf_ptr,
                                read_bytes + residual - request_buffer_offset,
                                UnsafePointer(to=method),
                                UnsafePointer(to=method_len),
                                UnsafePointer(to=path),
                                UnsafePointer(to=path_len)
                            )
                            
                            if request_buffer_bytes_parsed > 0:
                                request_buffer_offset += request_buffer_bytes_parsed
                                
                                # Generate response with bounds checking
                                var remaining_response_space = RES_BUFF_SIZE - response_buffer_filled_total
                                if remaining_response_space > 100:  # Ensure we have space for response
                                    var response_buffer_filled = example_callback(
                                        method, method_len,
                                        path, path_len,
                                        resbuf + response_buffer_filled_total,
                                        UnsafePointer[UInt8]()  # HTTP date - simplified
                                    )
                                    response_buffer_filled_total += response_buffer_filled
                                else:
                                    # Response buffer full, break out of loop
                                    break
                            else:
                                break
                        
                        # Handle buffer state updates (matches Rust logic)
                        if request_buffer_offset == 0 or response_buffer_filled_total == 0:
                            # Reset buffer and close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection(epfd, cur_fd)
                            continue
                        elif request_buffer_offset == (read_bytes + residual):
                            # Complete request processed
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                        else:
                            # Partial request - update buffer position
                            reqbuf_cur_addr[cur_fd] += UInt64(read_bytes)
                            reqbuf_residual[cur_fd] += (read_bytes - request_buffer_offset)
                        
                        # Send response (matches Rust)
                        var wrote = sys_sendto(cur_fd, resbuf, response_buffer_filled_total, 0, 0, 0)
                        
                        if wrote == response_buffer_filled_total:
                            # Successful write - continue
                            pass
                        elif wrote < 0 and (-wrote == EAGAIN or -wrote == 11):  # EINTR = 11
                            # Handle EAGAIN/EINTR (matches Rust)
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection(epfd, cur_fd)
                        else:
                            # Error or partial write - close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection(epfd, cur_fd)
                        
                        connections_handled += 1
                        
                    elif read_bytes < 0:
                        var errno = -read_bytes
                        if errno == EAGAIN or errno == EWOULDBLOCK:
                            # Would block - continue (matches Rust)
                            pass
                        else:
                            # Error - close connection
                            reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                            reqbuf_residual[cur_fd] = 0
                            close_connection(epfd, cur_fd)
                    else:
                        # Connection closed by client
                        reqbuf_cur_addr[cur_fd] = UInt64(req_buf_start_address)
                        reqbuf_residual[cur_fd] = 0
                        close_connection(epfd, cur_fd)
        
        print("Worker", worker_id, "handled", connections_handled, "connections, shutting down")
        
        # Add some debug output
        if connections_handled == 0:
            print("Worker", worker_id, "WARNING: No connections were handled - check if worker started properly")
        
        # Cleanup (matches Rust)
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
        print("Worker", worker_id, "error:", e)

# ===----------------------------------------------------------------------=== #
# Main server function matching Rust go() function
# ===----------------------------------------------------------------------=== #

fn epoll_worker_sync(
    worker_id: Int, 
    port: UInt16,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Synchronous version of epoll worker for process-based architecture."""
    print("Sync worker", worker_id, "starting (PID:", getpid(), ")")
    
    # Unshare file descriptor table (like Rust)
    var unshare_result = sys_unshare(CLONE_FILES)
    if unshare_result == 0:
        print("Process worker", worker_id, "SUCCESS: Unshared FD table!")
    
    # Run the actual worker logic synchronously
    try:
        var listener_result = get_listener_fd(port)
        var listener_fd = Int(listener_result[0])
        print("Process worker", worker_id, "got listener_fd")
        
        # Run epoll loop (simplified synchronous version)
        var epfd = sys_epoll_create1(0)
        if epfd < 0:
            print("Process worker", worker_id, "failed to create epoll")
            return
            
        # Add listener to epoll
        var saved_event = epoll_event()
        saved_event.events = UInt32(EPOLLIN)
        saved_event.data = UInt64(listener_fd)
        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, listener_fd, UnsafePointer(to=saved_event))
        
        print("Process worker", worker_id, "starting epoll event loop")
        
        var connection_count = 0
        # Infinite event loop - handle connections continuously
        while True:
            var events = UnsafePointer[epoll_event].alloc(1)
            var num_events = sys_epoll_wait(epfd, events, 1, 1000)  # 1 second timeout
            
            if num_events > 0:
                # Accept and handle connection
                var incoming_fd = sys_accept(listener_fd, 0, 0)
                if incoming_fd >= 0:
                    connection_count += 1
                    # Send simple response
                    var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
                    var _ = sys_sendto(incoming_fd, response.unsafe_ptr(), len(response), 0, 0, 0)
                    var _ = close(c_int(incoming_fd))
                    
                    # Print progress every 100 connections
                    if connection_count % 100 == 0:
                        print("Process worker", worker_id, "handled", connection_count, "connections")
            
            events.free()
            
        print("Process worker", worker_id, "shutting down")
        var _ = close(c_int(epfd))
        var _ = close(listener_fd)
        
    except e:
        print("Process worker", worker_id, "error:", e)

fn process_based_workers(
    port: UInt16, 
    num_workers: Int,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Create process-based workers like the Rust version."""
    print("🚀 Creating", num_workers, "process-based HTTP workers (like Rust)")
    
    # Fork multiple processes
    for worker_id in range(num_workers):
        var pid = fork()
        if pid == 0:
            # Child process - run the worker
            print("Process worker", worker_id, "starting (PID:", getpid(), ")")
            
            # Set CPU affinity for this process
            var affinity_result = set_cpu_affinity(worker_id % num_logical_cores())
            if affinity_result == 0:
                print("Process worker", worker_id, "pinned to CPU core", worker_id % num_logical_cores())
            
            # Run a single worker synchronously in this process
            # Since we can't run async in a forked process, run a sync version
            epoll_worker_sync(worker_id, port, cb)
            return  # Exit child process
        elif pid > 0:
            # Parent process - continue to fork more workers
            print("Forked process worker", worker_id, "with PID:", pid)
        else:
            print("Failed to fork worker", worker_id)
    
    # Parent process waits for all children
    print("Parent process waiting for", num_workers, "worker processes...")
    for i in range(num_workers):
        var status = c_int(0)
        var _ = waitpid(-1, UnsafePointer(to=status), 0)
        print("Worker process", i, "completed")

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

fn go(
    port: UInt16, 
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Main server function with thread isolation testing."""
    print("Starting server on port", port)
    var parallelism = asyncrt.parallelism_level()
    print("Available parallelism level:", parallelism)
    
    # Suggest environment variables if parallelism is low
    if parallelism == 1:
        print("💡 TIP: Try setting environment variables to increase parallelism:")
        print("   MOJO_ASYNC_THREADS=4 mojo test.mojo")
        print("   MOJO_PARALLELISM=4 mojo test.mojo") 
        print("   KGEN_PARALLELISM=4 mojo test.mojo")
        print("   or: taskset -c 0-3 mojo test.mojo")
    
    # Attempt to set higher process priority (matches Rust version)
    var priority_result = sys_setpriority(PRIO_PROCESS, 0, -19)
    if priority_result != 0:
        print("Warning: Could not set priority: setpriority: Permission denied")
    
    # Create local variables to replace globals
    var http_date = AlignedHttpDate()
    var workers_inited = Atomic[DType.index](0)
    
    # Initialize HTTP date before launching workers
    var date_ptr = UnsafePointer(to=http_date.data[0])
    get_http_date(date_ptr)
    
    var available_parallelism = asyncrt.parallelism_level()
    var num_cpu_cores = min(4, num_logical_cores())  # Force more workers for testing
    print("Starting", num_cpu_cores, "epoll-based HTTP workers via asyncrt")
    print("Available parallelism:", available_parallelism)
    if available_parallelism == 1:
        print("WARNING: Only 1 async worker thread available!")
        print("SOLUTION: Using process-based workers instead of async tasks")
        process_based_workers(port, num_cpu_cores, cb)
        return
    print("This will test if Mojo async tasks achieve thread-level isolation like Rust")
    
    # Create task group for all workers (following async_demo.mojo pattern)
    var task_group = asyncrt.TaskGroup()
    
    # Launch epoll worker tasks (equivalent to spawning threads in Rust)
    for core in range(num_cpu_cores):
        print("Creating worker", core, "- testing thread isolation...")
        
        var worker_coro = epoll_worker(core)
        # Use TaskGroup.create_task following the working pattern from async_demo.mojo
        task_group.create_task(worker_coro^)
        print("Worker", core, "task created and submitted to task group")
        
        # Small delay to ensure workers are initialized in sequence
        sleep(0.01)  # 10ms delay for better separation
    
    print("All epoll workers launched")
    print("Waiting for workers to initialize their sockets...")
    
    # Give workers time to actually start and bind their sockets
    sleep(0.1)  # 100ms to let async workers start
    
    print("All workers should be listening on port 8080 (shared via SO_REUSEPORT)")
    print("Check the output above to see if thread isolation worked:")
    print("  - Different thread IDs = Mojo uses real OS threads")  
    print("  - Successful unshare() = FD table isolation achieved")
    print("  - Successful CPU affinity = Thread pinning works")
    print("Try: curl http://localhost:8080")
    
    # For now, let's wait for the workers to complete their demo runs
    # In the real Rust version, this would be an infinite loop updating HTTP date
    print("Waiting for workers to complete their connection handling...")
    task_group.wait()
    print("All workers completed their demo runs")
    print("Thread isolation experiment completed - check results above!")
    print("Server shutting down")