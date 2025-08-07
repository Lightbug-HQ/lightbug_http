from lightbug_http_v1.epoll import go_async_simple, example_callback, AlignedHttpDate, StaticTuple, UInt8

fn main():
    """Main function to start the server."""
    print("Starting server on port 8080")
    
    go_async_simple(8080, example_callback)