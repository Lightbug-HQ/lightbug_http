from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int, external_call, c_long, c_size_t, c_uchar, c_ushort, c_char
from sys.info import sizeof, CompilationTarget, num_logical_cores
from memory import memcmp, UnsafePointer, stack_allocation, memset_zero, memcpy
from time import sleep

# Using existing working socket infrastructure from your codebase
from lightbug_http._libc import (
    sockaddr_in, 
    socket,
    bind,
    listen,
    accept,
    recv,
    send,
    close,
    c_void,
    AddressFamily,
    SOCK_STREAM,
)

# Simple synchronous HTTP server - replacement for the problematic async version
# This demonstrates the core HTTP handling logic without async complications

alias REQ_BUF_SIZE = 1024
alias RES_BUF_SIZE = 1024

fn get_listener_fd_simple(port: UInt16) raises -> c_int:
    """Create and configure listener socket - simplified version without socket options."""
    var listener_fd = socket(AddressFamily.AF_INET.value, SOCK_STREAM, 0)
    
    print("Created socket fd:", listener_fd)
    
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

fn simple_http_server(
    port: UInt16, 
    cb: fn(UnsafePointer[UInt8], Int, UnsafePointer[UInt8], Int, UnsafePointer[UInt8], UnsafePointer[UInt8]) -> Int
):
    """Simple synchronous HTTP server that handles one connection at a time."""
    
    # Create listener socket
    var listener_fd: c_int
    try:
        listener_fd = get_listener_fd_simple(port)
        print("HTTP server listening on port", port)
    except e:
        print("Failed to create listener socket:", e)
        return
    
    # Allocate buffers
    var req_buf = UnsafePointer[UInt8].alloc(REQ_BUF_SIZE)
    var res_buf = UnsafePointer[UInt8].alloc(RES_BUF_SIZE)
    
    var connections_handled = 0
    var max_connections = 5  # Handle 5 connections then exit for demo
    
    print("Server ready! Try: curl http://localhost:" + String(port))
    
    while connections_handled < max_connections:
        try:
            print("Waiting for connection", connections_handled + 1, "...")
            
            # Accept new connection
            var client_fd = accept(listener_fd)
            connections_handled += 1
            
            print("Accepted connection", connections_handled, ", client fd:", client_fd)
            
            # Read HTTP request
            var bytes_read = recv(client_fd, req_buf.bitcast[UInt8](), REQ_BUF_SIZE - 1, 0)
            
            if bytes_read > 0:
                # Null-terminate the request
                req_buf[bytes_read] = 0
                
                print("Received", bytes_read, "bytes")
                
                # Simple HTTP request parsing
                var method_ptr = req_buf
                var method_len = 3  # Assume "GET"
                var path_ptr = req_buf + 4  # Skip "GET "
                var path_len = 1  # Assume "/"
                
                # Generate response using callback
                var response_len = cb(
                    method_ptr, method_len,
                    path_ptr, path_len,
                    res_buf,
                    UnsafePointer[UInt8]()  # HTTP date - simplified
                )
                
                # Send response
                var _ = send(client_fd, res_buf.bitcast[c_void](), response_len, 0)
                
                print("Sent response of", response_len, "bytes")
            else:
                print("No data received")
            
            # Close client connection
            var _ = close(client_fd)
            print("Connection", connections_handled, "closed")
            
        except e:
            print("Error handling connection:", e)
            continue
    
    # Cleanup
    req_buf.free()
    res_buf.free()
    try:
        var _ = close(listener_fd)
    except:
        print("could not close")
    
    print("Simple HTTP server handled", connections_handled, "connections and is now shutting down")

fn main():
    """Main function."""
    print("Starting simple synchronous HTTP server...")
    simple_http_server(8080, example_callback)