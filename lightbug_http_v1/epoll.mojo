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
alias SO_REUSEADDR = 0x0004
alias SO_REUSEPORT = 0x0200

# Async version of the epoll server using Mojo's async runtime
# This replaces the pthread-based approach with TaskGroup/async tasks

# ===----------------------------------------------------------------------=== #
# Epoll Constants
# ===----------------------------------------------------------------------=== #

alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUF_SIZE = 1024
alias RES_BUF_SIZE = 1024
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
# Epoll structures and functions
# ===----------------------------------------------------------------------=== #

@register_passable("trivial")  
struct epoll_event:
    var events: UInt32
    var data: UInt64
    
    fn __init__(out self):
        self.events = 0
        self.data = 0

@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 32]
    
    fn __init__(out self):
        self.data = StaticTuple[UInt8, 32]()

# Epoll syscall wrappers
fn epoll_create1(flags: Int) -> Int:
    return Int(external_call["epoll_create1", c_int, c_int](flags))

fn epoll_ctl(epfd: Int, op: Int, fd: Int, event: UnsafePointer[epoll_event]) -> Int:
    return Int(external_call["epoll_ctl", c_int, c_int, c_int, c_int, UnsafePointer[epoll_event]](epfd, op, fd, event))

fn epoll_wait(epfd: Int, events: UnsafePointer[epoll_event], maxevents: Int, timeout: Int) -> Int:
    return Int(external_call["epoll_wait", c_int, c_int, UnsafePointer[epoll_event], c_int, c_int](epfd, events, maxevents, timeout))

fn nanosleep_simple(seconds: Float64):
    """Sleep for specified seconds using Mojo's sleep."""
    sleep(seconds)

# HTTP date function (simplified)
fn get_http_date(buf: UnsafePointer[UInt8], http_date: AlignedHttpDate):
    """Get current HTTP date string."""
    # Simplified implementation - in real code this would get actual date
    var date_str = "Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    var date_bytes = date_str.as_bytes()
    memcpy(buf, date_bytes.unsafe_ptr(), min(len(date_bytes), 32))

# ===----------------------------------------------------------------------=== #
# Worker task data structure
# ===----------------------------------------------------------------------=== #

@register_passable("trivial")
struct WorkerConfig:
    """Configuration for each worker task."""
    var port: UInt16
    var worker_id: Int
    var total_workers: Int
    
    fn __init__(out self, port: UInt16, worker_id: Int, total_workers: Int):
        self.port = port
        self.worker_id = worker_id
        self.total_workers = total_workers

# ===----------------------------------------------------------------------=== #
# Socket setup functions using working libc
# ===----------------------------------------------------------------------=== #

fn get_listener_fd_simple(port: UInt16) raises -> c_int:
    """Create and configure listener socket - simplified version without socket options."""
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    print("Created socket fd:", listener_fd)
    
    # Skip socket options for now - they're optimizations, not requirements
    # In production you'd want SO_REUSEADDR and SO_REUSEPORT but let's get basic functionality working first
    
    # Bind socket using the working sockaddr_in from libc
    var addr = sockaddr_in(Int(AddressFamily.AF_INET.value), port, 0)  # INADDR_ANY = 0
    try:
        bind(listener_fd, addr)
        print("Socket bound to port", port)
    except e:
        var _ = close(listener_fd)
        raise Error("Failed to bind socket: " + String(e))
    
    # Listen
    try:
        listen(listener_fd, 128)
        print("Socket listening with backlog 128")
    except e:
        var _ = close(listener_fd)
        raise Error("Failed to listen on socket: " + String(e))
    
    return listener_fd

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

# ===----------------------------------------------------------------------=== #
# Simplified async worker that focuses on demonstrating the async approach
# ===----------------------------------------------------------------------=== #

async fn worker_task_shared(
    config: WorkerConfig,
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int,
    workers_ready: UnsafePointer[Atomic[DType.index]],
    shared_listener_fd: c_int
):
    """Async worker task that shares a listener socket with other workers."""
    try:
        print("Worker", config.worker_id, "starting with shared listener fd", shared_listener_fd)
        
        # Signal that this worker is ready
        var _ = workers_ready[].fetch_add(1)
        
        print("Worker", config.worker_id, "ready, sharing listener on port", config.port)
        
        # Simplified event loop - accept connections from shared listener
        var req_buf = UnsafePointer[UInt8].alloc(REQ_BUF_SIZE)
        var res_buf = UnsafePointer[UInt8].alloc(RES_BUF_SIZE)
        var should_continue = True
        var connections_handled = 0
        
        while should_continue and connections_handled < 10:  # Limit for demo
            try:
                # Accept new connection from shared listener socket
                var client_fd = accept(shared_listener_fd)
                connections_handled += 1
                
                print("Worker", config.worker_id, "accepted connection", connections_handled)
                
                # Read data using working libc
                var bytes_read = recv(client_fd, req_buf.bitcast[UInt8](), REQ_BUF_SIZE - 1, 0)
                
                if bytes_read > 0:
                    # Null-terminate the request
                    req_buf[bytes_read] = 0
                    
                    # Parse basic HTTP request (simplified)
                    var method_ptr = req_buf
                    var method_len = 3  # Assume "GET"
                    var path_ptr = req_buf + 4  # Skip "GET "
                    var path_len = 1  # Assume "/"
                    
                    # Call the callback to generate response
                    var response_len = cb(
                        method_ptr, method_len,
                        path_ptr, path_len,
                        res_buf,
                        UnsafePointer[UInt8]()  # HTTP date - simplified
                    )
                    
                    # Send response using working libc
                    var _ = send(client_fd, res_buf.bitcast[c_void](), response_len, 0)
                    
                    print("Worker", config.worker_id, "sent response of", response_len, "bytes")
                
                # Close connection
                var _ = close(client_fd)
                
            except e:
                print("Worker", config.worker_id, "connection error:", e)
                # Continue to next connection
        
        # Cleanup (but don't close the shared listener)
        req_buf.free()
        res_buf.free()
        
        print("Worker", config.worker_id, "finished after handling", connections_handled, "connections")
        
    except e:
        print("Worker", config.worker_id, "error:", e)

# ===----------------------------------------------------------------------=== #
# Main server function using async runtime
# ===----------------------------------------------------------------------=== #

fn go_async_simple(
    port: UInt16, 
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Start the async HTTP server - replacement for the pthread-based version."""
    
    # Create the main listener socket ONCE here
    var listener_fd: c_int
    try:
        listener_fd = get_listener_fd_simple(port)
        print("Main listener socket created on port", port)
    except e:
        print("Failed to create main listener socket:", e)
        return
    
    var num_workers = min(4, num_logical_cores())  # Limit workers for demo
    print("Starting", num_workers, "async worker tasks")
    
    # Create atomic counter for tracking ready workers
    var workers_ready = Atomic[DType.index](0)
    var workers_ready_ptr = UnsafePointer(to=workers_ready)
    
    # Create task group for all workers
    var task_group = asyncrt.TaskGroup()
    
    # Launch worker tasks (equivalent to spawning threads in Rust)
    for worker_id in range(num_workers):
        var config = WorkerConfig(port, worker_id, num_workers)
        
        print("Creating async worker task for worker", worker_id)
        
        # Create worker task - pass the shared listener_fd
        var worker_coro = worker_task_shared(config, cb, workers_ready_ptr, listener_fd)
        task_group.create_task(worker_coro^)
        
        # Small delay to help with initialization order
        nanosleep_simple(0.01)  # 10ms delay
    
    # Wait for all workers to be ready
    while workers_ready.load() < num_workers:
        nanosleep_simple(0.001)  # 1ms polling
    
    print("All", num_workers, "workers are ready!")
    print("Server is running on port", port)
    print("Try: curl http://localhost:" + String(port))
    
    # Main server loop - for demo, run for 30 seconds then exit
    var run_time = 30.0
    var elapsed = 0.0
    var http_date = AlignedHttpDate()
    
    while elapsed < run_time:
        # Get pointer to first element of the StaticTuple
        var date_ptr = UnsafePointer(to=http_date.data[0])
        get_http_date(date_ptr, http_date)
        
        nanosleep_simple(1.0)  # Sleep for 1 second
        elapsed += 1.0
        
        if Int(elapsed) % 10 == 0:
            print("Server running for", Int(elapsed), "seconds...")
    
    print("Demo server shutting down after", run_time, "seconds")
    
    # Close the shared listener socket
    try:
        var _ = close(listener_fd)
    except:
        print("could not close listener_fd")
    print("Shared listener socket closed")
    
    # Note: In a real implementation, you'd want to properly shut down the task group
