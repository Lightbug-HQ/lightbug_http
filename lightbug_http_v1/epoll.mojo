from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call, c_long, c_size_t, c_uchar, c_ushort, c_char
from sys.info import sizeof, CompilationTarget, num_logical_cores
from sys.intrinsics import likely, unlikely
from memory import memcmp, UnsafePointer, stack_allocation, memset_zero, memcpy
from time import sleep, now
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

# System call constants
alias SYS_SETPRIORITY = 141
alias SYS_NANOSLEEP = 35
alias SYS_EPOLL_CREATE1 = 291
alias SYS_EPOLL_CTL = 233
alias SYS_EPOLL_WAIT = 232
alias SYS_ACCEPT = 43
alias SYS_RECVFROM = 45
alias SYS_SENDTO = 44

# Epoll-based HTTP server using Mojo's async runtime
# This translates the Rust threading approach to async tasks

# ===----------------------------------------------------------------------=== #
# Epoll Constants
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
        self.data = UInt64(fd)  # Store fd in the data field

@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]
    
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

# HTTP date function (simplified but proper format)
fn get_http_date(buf: UnsafePointer[UInt8]):
    """Get current HTTP date string."""
    # Simplified - real implementation would get actual current date
    var date_str = "Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    var date_bytes = date_str.as_bytes()
    memcpy(buf, date_bytes.unsafe_ptr(), min(len(date_bytes), 35))

# ===----------------------------------------------------------------------=== #
# Socket setup functions
# ===----------------------------------------------------------------------=== #

fn get_listener_fd(port: UInt16) raises -> (c_int, Bool, Bool):
    """Create and configure listener socket with SO_REUSEPORT."""
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
    """Set up connection options."""
    # todo: In the Rust version this sets TCP_NODELAY and other options, need to make the same
    pass

fn close_connection(epfd: Int, fd: Int):
    """Close connection and remove from epoll."""
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
    """Async epoll-based HTTP worker matching Rust threaded_worker."""
    try:
        # Create listener socket for this worker (with SO_REUSEPORT) - all workers use same port
        print("Worker", worker_id, "calling get_listener_fd...")
        var (listener_fd, success1, success2) = get_listener_fd(UInt16(8080))  # todo: make port configurable
        if listener_fd < 0:
            print("Worker", worker_id, "failed to create listener socket")
            return
        
        print("Worker", worker_id, "got listener_fd:", listener_fd)
        setup_connection(Int(listener_fd))
        print("Worker", worker_id, "listener socket created, sharing port 8080")
        # todo: add atach_reuseport_cbpf
        
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
        
        var saved_event = epoll_event(EPOLLIN, 0)
        
        # Request buffer management
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
        var connections_handled = 0
        var max_connections = 100 # todo: make configurable
        
        print("Worker", worker_id, "starting epoll event loop")
        
        # Main epoll event loop
        while connections_handled < max_connections:
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
                    # Accept new connection
                    var incoming_fd = sys_accept(Int(listener_fd), 0, 0)
                    
                    if likely(incoming_fd >= 0 and incoming_fd < MAX_CONN):
                        # Reset buffer state for this connection
                        reqbuf_cur_addr[incoming_fd] = UInt64(reqbuf_start_address + incoming_fd * REQ_BUFF_SIZE)
                        reqbuf_residual[incoming_fd] = 0
                        
                        setup_connection(incoming_fd)
                        saved_event.data = UInt64(incoming_fd)
                        
                        var _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd, UnsafePointer(to=saved_event))
                    else:
                        close_connection(epfd, cur_fd)
                else:
                    # Handle client connection
                    var buffer_remaining = REQ_BUFF_SIZE - Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    var buf_ptr = reqbuf + (cur_fd * REQ_BUFF_SIZE) + Int(req_buf_cur_position - UInt64(req_buf_start_address))
                    var read_bytes = sys_recvfrom(cur_fd, buf_ptr, buffer_remaining, 0, 0, 0)
                    
                    if likely(read_bytes > 0):
                        var request_buffer_offset = 0
                        var response_buffer_filled_total = 0
                        
                        # Process potentially multiple pipelined requests
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
                                
                                # Generate response
                                var response_buffer_filled = example_callback(
                                    method, method_len,
                                    path, path_len,
                                    resbuf + response_buffer_filled_total,
                                    UnsafePointer[UInt8]()  # HTTP date - simplified
                                )
                                
                                response_buffer_filled_total += response_buffer_filled
                            else:
                                break
                        
                        # Handle buffer state updates
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
                        
                        # Send response
                        var wrote = sys_sendto(cur_fd, resbuf, response_buffer_filled_total, 0, 0, 0)
                        
                        if likely(wrote == response_buffer_filled_total):
                            # Successful write - continue
                            pass
                        elif unlikely(wrote < 0 and (-wrote == EAGAIN or -wrote == 11)):  # todo: make constant EINTR = 11 
                            # Handle EAGAIN/EINTR
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
                            # Would block - continue
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
        
        # Cleanup
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
# Main server function
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

fn go(
    port: UInt16, 
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Main server function matching the Rust go() function."""
    print("Starting server on port", port)
    
    # Attempt to set higher process priority
    var priority_result = sys_setpriority(PRIO_PROCESS, 0, -19)
    if priority_result != 0:
        print("Warning: Could not set priority: setpriority: Permission denied")
    
    # Create local variables to replace globals
    var http_date = AlignedHttpDate()
    var workers_inited = Atomic[DType.index](0)
    
    # Initialize HTTP date before launching workers
    var date_ptr = UnsafePointer(to=http_date.data[0])
    get_http_date(date_ptr)
    
    var num_cpu_cores = min(2, num_logical_cores())  # Limit for demo
    print("Starting", num_cpu_cores, "epoll-based HTTP workers via asyncrt")
    
    # Create task group for all workers (following async_demo.mojo pattern)
    var task_group = asyncrt.TaskGroup()
    
    # Launch epoll worker tasks (equivalent to spawning threads in Rust)
    for core in range(num_cpu_cores):
        print("Creating worker", core)
        
        var worker_coro = epoll_worker(core)
        # Use TaskGroup.create_task following the working pattern from async_demo.mojo
        task_group.create_task(worker_coro^)
        
        # Small delay to ensure workers are initialized in sequence
        sleep(0.005)  # todo: make constant
    
    print("All epoll workers launched")
    print("Waiting for workers to initialize their sockets...")
    
    # Give workers time to actually start and bind their sockets
    sleep(0.1)  # 100ms to let async workers start
    
    print("All workers should be listening on port 8080 (shared via SO_REUSEPORT)")
    print("Try: curl http://localhost:8080")
    
    # For now, let's wait for the workers to complete their demo runs
    # todo: make this date update loop like in Rust
    print("Waiting for workers to complete their connection handling...")
    task_group.wait()
    print("All workers completed their demo runs")
    print("Server shutting down")