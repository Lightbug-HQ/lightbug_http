from lightbug_http_v1.epoll import go, example_callback

fn main():
    """Main function to start the server."""
    print("Starting server on port 8080")
    
    # Start the server - no need for global variables!
    # The HTTP date buffer is now handled internally
    go(8080, example_callback)
