from sys.ffi import external_call, c_int, c_long, c_size_t, c_uint, c_char
from sys.info import num_logical_cores, sizeof
from memory import memset_zero, memcpy, UnsafePointer
from time import sleep
from os.atomic import Atomic
from lightbug_http._libc import c_void
import os

# ===----------------------------------------------------------------------=== #
# System Constants (matching Rust const_sys)
# ===----------------------------------------------------------------------=== #

# Clone flags
alias CLONE_FILES = 0x400

# Priority constants
alias PRIO_PROCESS = 0

# Socket constants
alias AF_INET = 2
alias SOCK_STREAM = 1
alias SOL_SOCKET = 1
alias SO_REUSEADDR = 2
alias SO_REUSEPORT = 15
alias TCP_NODELAY = 1
alias IPPROTO_TCP = 6

# Epoll constants
alias EPOLLIN = 0x001
alias EPOLL_CTL_ADD = 1
alias EPOLL_CTL_DEL = 2
alias EPOLL_TIMEOUT_BLOCKING = -1
alias EPOLL_TIMEOUT_IMMEDIATE_RETURN = 0

# Error codes
alias EAGAIN = 11
alias EINTR = 4

# ===----------------------------------------------------------------------=== #
# Config Constants (matching Rust const_config)
# ===----------------------------------------------------------------------=== #

alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUFF_SIZE = 1024
alias RES_BUFF_SIZE = 1024
alias MAX_CONN = 1024

# ===----------------------------------------------------------------------=== #
# Structures
# ===----------------------------------------------------------------------=== #

@register_passable("trivial")
struct epoll_event:
    var events: UInt32
    var data: UInt64  # Union simplified to u64
    
    fn __init__(out self):
        self.events = 0
        self.data = 0

@register_passable("trivial")
struct sockaddr_in:
    var sin_family: UInt16
    var sin_port: UInt16
    var sin_addr: UInt32
    var sin_zero: UInt64
    
    fn __init__(out self, family: Int, port: UInt16, addr: UInt32):
        self.sin_family = UInt16(family)
        self.sin_port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8)  # htons
        self.sin_addr = addr
        self.sin_zero = 0

@register_passable("trivial")
struct timespec:
    var tv_sec: Int64
    var tv_nsec: Int64
    
    fn __init__(out self, sec: Int64, nsec: Int64):
        self.tv_sec = sec
        self.tv_nsec = nsec

# Aligned structures (matching Rust's #[repr(align(64))])
struct AlignedHttpDate:
    var data: UnsafePointer[UInt8]
    var original: UnsafePointer[UInt8]  # Keep track of original allocation
    
    fn __init__(out self):
        # Allocate extra space for alignment
        self.original = UnsafePointer[UInt8].alloc(35 + 64)
        # Calculate aligned address
        var addr = Int(self.original)
        var offset = 0
        if addr % 64 != 0:
            offset = 64 - (addr % 64)
        # Use pointer arithmetic to get aligned pointer
        self.data = self.original + offset
        memset_zero(self.data, 35)
    
    fn __del__(owned self):
        self.original.free()

struct AlignedEpollEvents:
    var data: UnsafePointer[epoll_event]
    var original: UnsafePointer[epoll_event]  # Track original for deallocation
    
    fn __init__(out self):
        # Allocate extra space for alignment
        self.original = UnsafePointer[epoll_event].alloc(MAX_EPOLL_EVENTS_RETURNED + 16)
        # Calculate aligned address
        var addr = Int(self.original)
        var offset = 0
        if addr % 64 != 0:
            # Calculate offset in terms of epoll_event elements
            var bytes_offset = 64 - (addr % 64)
            # Convert byte offset to element offset (rounding up)
            offset = (bytes_offset + sizeof[epoll_event]() - 1) // sizeof[epoll_event]()
        # Use pointer arithmetic to get aligned pointer
        self.data = self.original + offset
        memset_zero(self.data, MAX_EPOLL_EVENTS_RETURNED * sizeof[epoll_event]())
    
    fn __del__(owned self):
        self.original.free()

# ===----------------------------------------------------------------------=== #
# System Call Functions (separated)
# ===----------------------------------------------------------------------=== #

fn sys_setpriority(which: Int, who: Int, priority: Int) -> Int:
    """Set process/thread priority."""
    return Int(external_call["setpriority", c_int, c_int, c_int, c_int](which, who, priority))

fn sys_unshare(flags: Int) -> Int:
    """Unshare parts of the process execution context."""
    return Int(external_call["unshare", c_int, c_int](flags))

fn sys_epoll_create1(flags: Int) -> Int:
    """Create an epoll instance."""
    return Int(external_call["epoll_create1", c_int, c_int](flags))

fn sys_epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) -> Int:
    """Control an epoll instance."""
    return Int(external_call["epoll_ctl", c_int, c_int, c_int, c_int, UnsafePointer[epoll_event]](
        epfd, op, fd, event))

fn sys_epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) -> Int:
    """Wait for events on an epoll instance."""
    return Int(external_call["epoll_wait", c_int, c_int, UnsafePointer[epoll_event], c_int, c_int](
        epfd, events, maxevents, timeout))

fn sys_accept(sockfd: Int) -> Int:
    """Accept a connection on a socket."""
    return Int(external_call["accept", c_int, c_int, c_void, c_void](sockfd, 0, 0))

fn sys_recvfrom(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int) -> Int:
    """Receive data from a socket."""
    return Int(external_call["recvfrom", c_long, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_void, c_void](
        sockfd, buf, len, flags, 0, 0))

fn sys_sendto(sockfd: Int, buf: UnsafePointer[UInt8], len: Int, flags: Int) -> Int:
    """Send data to a socket."""
    return Int(external_call["sendto", c_long, c_int, UnsafePointer[UInt8], c_size_t, c_int, c_void, c_void](
        sockfd, buf, len, flags, 0, 0))

fn sys_nanosleep(req: UnsafePointer[timespec]) -> Int:
    """High-resolution sleep."""
    return Int(external_call["nanosleep", c_int, UnsafePointer[timespec], c_void](req, 0))

fn sys_sched_setaffinity(pid: Int, cpusetsize: Int, mask: UnsafePointer[UInt64]) -> Int:
    """Set CPU affinity mask."""
    return Int(external_call["sched_setaffinity", c_int, c_int, c_size_t, UnsafePointer[UInt64]](
        pid, cpusetsize, mask))

# ===----------------------------------------------------------------------=== #
# Network Functions (matching Rust net module)
# ===----------------------------------------------------------------------=== #

fn socket(domain: Int, type: Int, protocol: Int) -> Int:
    return Int(external_call["socket", c_int, c_int, c_int, c_int](domain, type, protocol))

fn bind(sockfd: Int, addr: sockaddr_in) -> Int:
    return Int(external_call["bind", c_int, c_int, UnsafePointer[sockaddr_in], c_uint](
        sockfd, UnsafePointer(to=addr), sizeof[sockaddr_in]()))

fn listen(sockfd: Int, backlog: Int) -> Int:
    return Int(external_call["listen", c_int, c_int, c_int](sockfd, backlog))

fn setsockopt(sockfd: Int, level: Int, optname: Int, optval: UnsafePointer[c_int], optlen: Int) -> Int:
    return Int(external_call["setsockopt", c_int, c_int, c_int, c_int, UnsafePointer[c_int], c_uint](
        sockfd, level, optname, optval, optlen))

fn close(fd: Int) -> Int:
    return Int(external_call["close", c_int, c_int](fd))

fn get_listener_fd(port: UInt16) -> (Int, Bool, Bool):
    """Create listener socket with SO_REUSEPORT."""
    var listener_fd = socket(AF_INET, SOCK_STREAM, 0)
    if listener_fd < 0:
        return (-1, False, False)
    
    # Set SO_REUSEADDR
    var reuseaddr = c_int(1)
    var ret = setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, 
                        UnsafePointer(to=reuseaddr), sizeof[c_int]())
    
    # Set SO_REUSEPORT (critical for multi-worker)
    var reuseport = c_int(1)
    ret = setsockopt(listener_fd, SOL_SOCKET, SO_REUSEPORT,
                    UnsafePointer(to=reuseport), sizeof[c_int]())
    
    # Bind
    var addr = sockaddr_in(AF_INET, port, 0)  # INADDR_ANY
    if bind(listener_fd, addr) < 0:
        _ = close(listener_fd)
        return (-1, False, False)
    
    # Listen
    if listen(listener_fd, 128) < 0:
        _ = close(listener_fd)
        return (-1, False, False)
    
    return (listener_fd, True, True)

fn setup_connection(fd: Int):
    """Configure connection socket options."""
    # TCP_NODELAY
    var nodelay = c_int(1)
    _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                  UnsafePointer(to=nodelay), sizeof[c_int]())

fn close_connection(epfd: Int, fd: Int):
    """Remove from epoll and close socket."""
    _ = sys_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, UnsafePointer[epoll_event]())
    _ = close(fd)

fn attach_reuseport_cbpf(listener_fd: Int):
    """Attach REUSEPORT BPF filter for CPU locality."""
    # TODO: Implement BPF attachment
    # This would require SO_ATTACH_REUSEPORT_CBPF sockopt
    pass

# ===----------------------------------------------------------------------=== #
# CPU Affinity
# ===----------------------------------------------------------------------=== #

fn set_current_thread_cpu_affinity_to(cpu_core: Int):
    """Pin thread to specific CPU core."""
    var cpu_set = UnsafePointer[UInt64].alloc(1)
    cpu_set[0] = UInt64(1) << cpu_core
    _ = sys_sched_setaffinity(0, 8, cpu_set)
    cpu_set.free()

# ===----------------------------------------------------------------------=== #
# HTTP Date
# ===----------------------------------------------------------------------=== #

fn get_http_date(buf: UnsafePointer[UInt8]):
    """Format current time as HTTP date."""
    # Simplified - would use actual time formatting
    var date_str = "Thu, 01 Jan 1970 00:00:00 GMT"
    var date_bytes = date_str.as_bytes()
    memcpy(buf, date_bytes.unsafe_ptr(), len(date_bytes))

# ===----------------------------------------------------------------------=== #
# HTTP Request Parser (simplified version of SIMD parser)
# ===----------------------------------------------------------------------=== #

fn parse_request_path_pipelined_simd(
    buffer: UnsafePointer[UInt8],
    buffer_len: Int,
    method: UnsafePointer[UnsafePointer[UInt8]],
    method_len: UnsafePointer[Int],
    path: UnsafePointer[UnsafePointer[UInt8]],
    path_len: UnsafePointer[Int]
) -> Int:
    """Parse HTTP request, return bytes consumed or 0 if incomplete."""
    if buffer_len < 16:
        return 0
    
    # Simple GET detection
    if buffer[0] == ord('G') and buffer[1] == ord('E') and buffer[2] == ord('T') and buffer[3] == ord(' '):
        method[] = buffer
        method_len[] = 3
        
        # Find path
        path[] = buffer + 4
        var i = 4
        while i < buffer_len and buffer[i] != ord(' ') and buffer[i] != ord('\r'):
            i += 1
        path_len[] = i - 4
        
        # Find end of headers (double CRLF)
        while i < buffer_len - 3:
            if buffer[i] == ord('\r') and buffer[i+1] == ord('\n') and 
               buffer[i+2] == ord('\r') and buffer[i+3] == ord('\n'):
                return i + 4
            i += 1
    
    return 0

# ===----------------------------------------------------------------------=== #
# Thread Worker (matching Rust threaded_worker)
# ===----------------------------------------------------------------------=== #

fn threaded_worker(
    port: UInt16,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    cpu_core: Int,
    num_cpu_cores: Int,
    num_workers_inited: UnsafePointer[Atomic[DType.index]],
    http_date: UnsafePointer[UInt8]
):
    """Worker thread main loop."""
    
    # Get listener socket
    var (listener_fd, _, _) = get_listener_fd(port)
    setup_connection(listener_fd)
    
    # Signal initialization complete
    _ = num_workers_inited[].fetch_add(1)
    
    # Wait for all workers to initialize before attaching BPF
    if cpu_core == 0:
        while Int(num_workers_inited[].load()) < num_cpu_cores:
            sleep(0.000001)  # 1 microsecond
        attach_reuseport_cbpf(listener_fd)
    
    # Create epoll instance
    var epfd = sys_epoll_create1(0)
    
    # Add listener to epoll
    var epoll_event_listener = epoll_event()
    epoll_event_listener.events = EPOLLIN
    epoll_event_listener.data = UInt64(listener_fd)
    _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, listener_fd, 
                     UnsafePointer(to=epoll_event_listener))
    
    # Allocate aligned buffers
    var epoll_events = AlignedEpollEvents()
    
    var saved_event = epoll_event()
    saved_event.events = EPOLLIN
    
    # Request buffer and state
    var reqbuf = UnsafePointer[UInt8].alloc(REQ_BUFF_SIZE * MAX_CONN)
    memset_zero(reqbuf, REQ_BUFF_SIZE * MAX_CONN)
    
    var reqbuf_cur_addr = UnsafePointer[UInt8].alloc(MAX_CONN)
    var reqbuf_residual = UnsafePointer[Int].alloc(MAX_CONN)
    
    # Initialize buffer addresses
    var reqbuf_start = Int(reqbuf)
    for i in range(MAX_CONN):
        reqbuf_cur_addr[i] = reqbuf_start + i * REQ_BUFF_SIZE
        reqbuf_residual[i] = 0
    
    # Response buffer
    var resbuf = UnsafePointer[UInt8].alloc(RES_BUFF_SIZE)
    var resbuf_start = Int(resbuf)
    
    var epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
    
    # Main event loop
    while True:
        var num_incoming_events = sys_epoll_wait(epfd, epoll_events.data,
                                                 MAX_EPOLL_EVENTS_RETURNED, epoll_wait_type)
        
        if num_incoming_events <= 0:
            epoll_wait_type = EPOLL_TIMEOUT_BLOCKING
            continue
        
        epoll_wait_type = EPOLL_TIMEOUT_IMMEDIATE_RETURN
        
        for index in range(num_incoming_events):
            var event = epoll_events.data[index]
            var cur_fd = Int(event.data)
            
            var req_buf_start_address = reqbuf_start + cur_fd * REQ_BUFF_SIZE
            var req_buf_cur_position = UnsafePointer(to=reqbuf_cur_addr[cur_fd])
            var residual = UnsafePointer(to=reqbuf_residual[cur_fd])
            
            if cur_fd == listener_fd:
                # Accept new connection
                var incoming_fd = sys_accept(listener_fd)
                
                if incoming_fd >= 0 and incoming_fd < MAX_CONN:
                    req_buf_cur_position[] = req_buf_start_address
                    residual[] = 0
                    setup_connection(incoming_fd)
                    saved_event.data = UInt64(incoming_fd)
                    _ = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, incoming_fd,
                                     UnsafePointer(to=saved_event))
                else:
                    close_connection(epfd, cur_fd)
            else:
                # Handle client connection
                var buffer_remaining = Int(REQ_BUFF_SIZE - (req_buf_cur_position[] - req_buf_start_address))
                var read = sys_recvfrom(cur_fd, 
                                       req_buf_cur_position,
                                       buffer_remaining, 0)
                
                if read > 0:
                    var request_buffer_offset = 0
                    var response_buffer_filled_total = 0
                    
                    # Process pipelined requests
                    while request_buffer_offset != (read + residual[]):
                        var method = UnsafePointer[UInt8]()
                        var method_len = 0
                        var path = UnsafePointer[UInt8]()
                        var path_len = 0
                        
                        var parse_start = UInt8(req_buf_cur_position[] - residual[] + request_buffer_offset)
                        var request_buffer_bytes_parsed = parse_request_path_pipelined_simd(
                            UnsafePointer[UInt8](to=parse_start),
                            read + residual[] - request_buffer_offset,
                            UnsafePointer(to=method),
                            UnsafePointer(to=method_len),
                            UnsafePointer(to=path),
                            UnsafePointer(to=path_len)
                        )
                        
                        if request_buffer_bytes_parsed > 0:
                            request_buffer_offset += request_buffer_bytes_parsed
                            var resbuf_from_start = UInt8(resbuf_start + response_buffer_filled_total)
                            
                            var response_buffer_filled = cb(
                                method, method_len,
                                path, path_len,
                                UnsafePointer[UInt8](to=resbuf_from_start),
                                http_date
                            )
                            response_buffer_filled_total += response_buffer_filled
                        else:
                            break
                    
                    # Update buffer state
                    if request_buffer_offset == 0 or response_buffer_filled_total == 0:
                        req_buf_cur_position[] = req_buf_start_address
                        residual[] = 0
                        close_connection(epfd, cur_fd)
                        continue
                    elif request_buffer_offset == (read + residual[]):
                        req_buf_cur_position[] = req_buf_start_address
                        residual[] = 0
                    else:
                        req_buf_cur_position[] += read
                        residual[] += (read - request_buffer_offset)
                    
                    # Send response
                    var resbuf_start_uint8 = UInt8(resbuf_start)
                    var wrote = sys_sendto(cur_fd,
                                         UnsafePointer[UInt8](to=resbuf_start_uint8),
                                         response_buffer_filled_total, 0)
                    
                    if wrote != response_buffer_filled_total:
                        if -wrote == EAGAIN or -wrote == EINTR:
                            pass  # Would block, try again later
                        else:
                            req_buf_cur_position[] = req_buf_start_address
                            residual[] = 0
                            close_connection(epfd, cur_fd)
                elif -read == EAGAIN or -read == EINTR:
                    pass  # Would block
                else:
                    # Error or connection closed
                    req_buf_cur_position[] = req_buf_start_address
                    residual[] = 0
                    close_connection(epfd, cur_fd)

# ===----------------------------------------------------------------------=== #
# Main Entry Point (matching Rust go function)
# ===----------------------------------------------------------------------=== #

fn go(
    port: UInt16,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Main server entry point."""
    
    # Set process priority
    _ = sys_setpriority(PRIO_PROCESS, 0, -19)
    
    # Initialize HTTP date
    var http_date = AlignedHttpDate()
    get_http_date(http_date.data)
    
    var num_workers_inited = Atomic[DType.index](0)
    var num_cpu_cores = num_logical_cores()
    
    print("Starting FaF server on port", port, "with", num_cpu_cores, "workers")
    
    # For now, run single worker in main thread
    # In production, would spawn OS threads here
    
    # Unshare file descriptor table
    _ = sys_unshare(CLONE_FILES)
    set_current_thread_cpu_affinity_to(0)
    threaded_worker(port, cb, 0, 1,  # Single worker for testing
                   UnsafePointer(to=num_workers_inited),
                   http_date.data)
    
    # This would normally be the date update loop
    # var sleep_time = timespec(1, 0)
    # while True:
    #     get_http_date(http_date.data)
    #     _ = sys_nanosleep(UnsafePointer(to=sleep_time))

# ===----------------------------------------------------------------------=== #
# Example Usage
# ===----------------------------------------------------------------------=== #

fn example_callback(
    method: UnsafePointer[UInt8], method_len: Int,
    path: UnsafePointer[UInt8], path_len: Int,
    response: UnsafePointer[UInt8],
    http_date: UnsafePointer[UInt8]
) -> Int:
    """Example HTTP response callback."""
    var resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
    var resp_bytes = resp.as_bytes()
    memcpy(response, resp_bytes.unsafe_ptr(), len(resp_bytes))
    return len(resp_bytes)
