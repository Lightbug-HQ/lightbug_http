#!/usr/bin/env mojo

from lightbug_http_v1.epoll import go, example_callback, AlignedHttpDate, StaticTuple

fn main():
    """Simple test to check if the epoll server starts without segfaulting."""
    print("Testing epoll server...")
    
    # Initialize HTTP date structure
    var http_date = AlignedHttpDate(StaticTuple[UInt8, 35]())
    
    # Initialize worker counter
    var num_workers_inited_storage = 0
    
    try:
        # Start server on port 8080 with minimal setup
        go(8080, example_callback, http_date, num_workers_inited_storage)
    except e:
        print("Error starting server:", e)