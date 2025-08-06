from lightbug_http_v1.epoll import go, example_callback, AlignedHttpDate, StaticTuple, UInt8

fn main():
    """Main function to start the server."""
    print("Starting server on port 8080")
    
    # Initialize global HTTP_DATE
    HTTP_DATE = AlignedHttpDate(StaticTuple[UInt8, 35]())
    
    # Start the server
    var NUM_WORKERS_INITED = 0
    go(8080, example_callback, HTTP_DATE, NUM_WORKERS_INITED)