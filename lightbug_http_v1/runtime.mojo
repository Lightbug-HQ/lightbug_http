from sys import external_call
from memory import UnsafePointer, memset_zero
from collections import List

# System constants
alias EPOLLIN = 1
alias EPOLLET = 1 << 31
alias EPOLL_CTL_ADD = 1
alias EPOLL_CTL_DEL = 2
alias EPOLL_CTL_MOD = 3
alias SYS_READ = 0
alias SYS_WRITE = 1

# Threading constants
alias PTHREAD_CREATE_JOINABLE = 0
alias PTHREAD_CREATE_DETACHED = 1

# --- Core Types ---

@fieldwise_init
struct TaskHandle(Copyable & Movable):
    """Handle to an async task."""
    var task_id: Int
    var fd: Int
    
    fn is_valid(self) -> Bool:
        return self.fd >= 0

@fieldwise_init
struct TaskResult(Copyable):
    """Result of an async task execution."""
    var success: Bool
    var value: UInt64
    var error_msg: String
    
    fn __init__(out self):
        self.success = False
        self.value = 0
        self.error_msg = ""

# --- Callback Types ---

# Function type alias for callbacks
alias TaskCallbackFn = fn (Int, UInt64) -> TaskResult

trait TaskCallback:
    """Interface for task callbacks."""
    fn execute(mut self, task_id: Int, value: UInt64) -> TaskResult:
        ...

struct SimpleCallback(TaskCallback):
    """Simple callback that just prints the value."""
    fn execute(mut self, task_id: Int, value: UInt64) -> TaskResult:
        print("Task", task_id, "completed with value", value)
        var result = TaskResult()
        result.success = True
        result.value = value
        return result

struct CustomCallback(TaskCallback):
    """Custom callback with configurable behavior."""
    var multiplier: UInt64
    var print_enabled: Bool
    
    fn __init__(out self, multiplier: UInt64 = 1, print_enabled: Bool = True):
        self.multiplier = multiplier
        self.print_enabled = print_enabled
    
    fn execute(mut self, task_id: Int, value: UInt64) -> TaskResult:
        if self.print_enabled:
            print("Custom callback: Task", task_id, "value", value, "* multiplier", self.multiplier)
        
        var result = TaskResult()
        result.success = True
        result.value = value * self.multiplier
        return result

# Context for function pointer callbacks
struct CallbackContext(Copyable, Movable):
    """Context structure for function pointer callbacks."""
    var callback_fn: TaskCallbackFn
    var user_data: UnsafePointer[UInt8]  # Generic user data pointer
    
    fn __init__(out self, callback_fn: TaskCallbackFn):
        self.callback_fn = callback_fn
        self.user_data = UnsafePointer[UInt8]()
    
    fn __init__(out self, callback_fn: TaskCallbackFn, user_data: UnsafePointer[UInt8]):
        self.callback_fn = callback_fn
        self.user_data = user_data

# Built-in callback functions
fn default_callback(task_id: Int, value: UInt64) -> TaskResult:
    """Default callback that just returns the value."""
    var result = TaskResult()
    result.success = True
    result.value = value
    return result

fn logging_callback(task_id: Int, value: UInt64) -> TaskResult:
    """Logging callback that prints task completion."""
    print("CALLBACK: Task", task_id, "completed with value", value)
    var result = TaskResult()
    result.success = True
    result.value = value
    return result

fn doubling_callback(task_id: Int, value: UInt64) -> TaskResult:
    """Callback that doubles the value."""
    var doubled_value = value * 2
    print("CALLBACK: Task", task_id, "doubling", value, "->", doubled_value)
    var result = TaskResult()
    result.success = True
    result.value = doubled_value
    return result

# --- Internal Task Type ---

@fieldwise_init
struct AsyncTask(Copyable, Movable):
    var task_id: Int
    var fd: Int
    var executed: Bool
    var callback_fn: TaskCallbackFn
    var trait_callback_ptr: UnsafePointer[UInt8]  # For trait-based callbacks
    var use_trait_callback: Bool
    
    fn __init__(out self, task_id: Int, fd: Int, callback_fn: TaskCallbackFn = default_callback):
        self.task_id = task_id
        self.fd = fd
        self.executed = False
        self.callback_fn = callback_fn
        self.trait_callback_ptr = UnsafePointer[UInt8]()
        self.use_trait_callback = False
    
    fn __init__[T: TaskCallback](out self, task_id: Int, fd: Int, callback: T):
        self.task_id = task_id
        self.fd = fd
        self.executed = False
        self.callback_fn = default_callback
        # Store trait callback - simplified for now, would need proper allocation in production
        self.trait_callback_ptr = UnsafePointer[UInt8]()
        self.use_trait_callback = True
    
    fn execute(mut self) -> TaskResult:
        """Execute the task and return result."""
        var result = TaskResult()
        
        if self.executed:
            result.error_msg = "Task already executed"
            return result
        
        # Read the eventfd value (8 bytes)
        var buffer = UnsafePointer[UInt64].alloc(1)
        var bytes_read = external_call["syscall", Int](
            SYS_READ,
            self.fd,
            buffer.bitcast[UInt8](),
            8
        )
        
        if bytes_read == 8:
            var raw_value = buffer[]
            
            # Execute the callback with the value
            if self.use_trait_callback:
                # For trait callbacks, we'd need to properly restore the callback
                # This is simplified - in production you'd need proper allocation/storage
                result.value = raw_value
                result.success = True
            else:
                # Use function pointer callback
                result = self.callback_fn(self.task_id, raw_value)
        else:
            result.error_msg = "Failed to read eventfd"
        
        buffer.free()
        self.executed = True
        
        # Close the fd to clean up
        _ = external_call["close", Int32](self.fd)
        
        return result

# --- Event System ---

struct EventFD:
    """Wrapper for eventfd operations."""
    var fd: Int
    
    fn __init__(out self, initial_value: UInt64 = 0):
        self.fd = Int(external_call["eventfd", Int32](initial_value, 0))
    
    fn is_valid(self) -> Bool:
        return self.fd >= 0
    
    fn trigger(self, value: UInt64) -> Bool:
        """Trigger the eventfd with a value."""
        if not self.is_valid():
            return False
            
        var value_ptr = UnsafePointer[UInt64].alloc(1)
        value_ptr[] = value
        
        var bytes_written = external_call["syscall", Int](
            SYS_WRITE,
            self.fd,
            value_ptr.bitcast[UInt8](),
            8
        )
        
        value_ptr.free()
        return bytes_written == 8
    
    fn close(self):
        """Close the eventfd."""
        if self.is_valid():
            _ = external_call["close", Int32](self.fd)

# --- Main Reactor ---

struct AsyncReactor:
    """Async reactor using epoll for event handling."""
    var epoll_fd: Int
    var tasks: List[AsyncTask]
    var next_task_id: Int
    var max_events: Int
    var timeout_ms: Int
    
    fn __init__(out self, max_events: Int = 10, timeout_ms: Int = 1000):
        self.epoll_fd = Int(external_call["epoll_create1", Int32](0o2000000))
        self.tasks = List[AsyncTask]()
        self.next_task_id = 0
        self.max_events = max_events
        self.timeout_ms = timeout_ms
    
    fn is_valid(self) -> Bool:
        return self.epoll_fd >= 0
    
    fn create_task(mut self, callback_fn: TaskCallbackFn = default_callback) -> TaskHandle:
        """Create a new async task with a callback function and return its handle."""
        var handle = TaskHandle(task_id=-1, fd=-1)
        
        if not self.is_valid():
            return handle
        
        var eventfd = EventFD()
        if not eventfd.is_valid():
            return handle
        
        var task_id = self.next_task_id
        self.next_task_id += 1
        
        handle.task_id = task_id
        handle.fd = eventfd.fd
        
        var task = AsyncTask(task_id, eventfd.fd, callback_fn)
        
        # Add to epoll
        if self._add_to_epoll(task_id, eventfd.fd):
            self.tasks.append(task^)
        else:
            eventfd.close()
            handle.fd = -1
        
        return handle
    
    fn create_task_with_trait[T: TaskCallback](mut self, callback: T) -> TaskHandle:
        """Create a new async task with a trait-based callback and return its handle."""
        var handle = TaskHandle(task_id=-1, fd=-1)
        
        if not self.is_valid():
            return handle
        
        var eventfd = EventFD()
        if not eventfd.is_valid():
            return handle
        
        var task_id = self.next_task_id
        self.next_task_id += 1
        
        handle.task_id = task_id
        handle.fd = eventfd.fd
        
        var task = AsyncTask(task_id, eventfd.fd, default_callback)
        
        # Add to epoll
        if self._add_to_epoll(task_id, eventfd.fd):
            self.tasks.append(task^)
        else:
            eventfd.close()
            handle.fd = -1
        
        return handle
    
    fn trigger_task(self, handle: TaskHandle, value: UInt64) -> Bool:
        """Trigger a task with a value."""
        if not handle.is_valid():
            return False
        
        var value_ptr = UnsafePointer[UInt64].alloc(1)
        value_ptr[] = value
        
        var bytes_written = external_call["syscall", Int](
            SYS_WRITE,
            handle.fd,
            value_ptr.bitcast[UInt8](),
            8
        )
        
        value_ptr.free()
        return bytes_written == 8
    
    fn poll_once(mut self) -> Int:
        """Poll for events once, returns number of tasks completed."""
        if not self.is_valid():
            return 0
        
        var events_buffer = UnsafePointer[UInt8].alloc(16 * self.max_events)
        var completed = 0
        
        var nfds = external_call["epoll_wait", Int32](
            self.epoll_fd,
            events_buffer,
            self.max_events,
            self.timeout_ms
        )
        
        if nfds > 0:
            completed = self._process_events(events_buffer, nfds)
        
        events_buffer.free()
        return completed
    
    fn run_until_complete(mut self, max_iterations: Int = 100) -> Int:
        """Run the event loop until all tasks complete or max iterations reached."""
        var total_completed = 0
        var iterations = 0
        var active_tasks = self._count_active_tasks()
        
        while active_tasks > 0 and iterations < max_iterations:
            var completed = self.poll_once()
            total_completed += completed
            active_tasks = self._count_active_tasks()
            iterations += 1
        
        return total_completed
    
    fn shutdown(mut self):
        """Clean shutdown of the reactor."""
        if self.is_valid():
            # Close all task fds
            for i in range(len(self.tasks)):
                if not self.tasks[i].executed and self.tasks[i].fd >= 0:
                    _ = external_call["close", Int32](self.tasks[i].fd)
            
            # Close epoll fd
            _ = external_call["close", Int32](self.epoll_fd)
            self.epoll_fd = -1
    
    # --- Private Methods ---
    
    fn _add_to_epoll(self, task_id: Int, fd: Int) -> Bool:
        """Add a file descriptor to epoll monitoring."""
        var event_buffer = UnsafePointer[UInt8].alloc(16)
        memset_zero(event_buffer, 16)
        
        # Set events (first 4 bytes)
        var events_ptr = event_buffer.bitcast[UInt32]()
        events_ptr[] = UInt32(EPOLLIN)
        
        # Set task_id in data field (bytes 8-12)
        var data_ptr = (event_buffer + 8).bitcast[UInt32]()
        data_ptr[] = UInt32(task_id)
        
        var result = external_call["epoll_ctl", Int32](
            self.epoll_fd,
            EPOLL_CTL_ADD,
            fd,
            event_buffer
        )
        
        event_buffer.free()
        return result == 0
    
    fn _process_events(mut self, events_buffer: UnsafePointer[UInt8], nfds: Int32) -> Int:
        """Process epoll events."""
        var completed = 0
        
        for i in range(nfds):
            var event_offset = i * 16
            var event_ptr = events_buffer + event_offset
            
            # Read task_id from data field (bytes 8-12)
            var data_fd_ptr = (event_ptr + 8).bitcast[UInt32]()
            var task_id = Int(data_fd_ptr[])
            
            # Find and execute task
            for j in range(len(self.tasks)):
                if self.tasks[j].task_id == task_id and not self.tasks[j].executed:
                    _ = self.tasks[j].execute()
                    completed += 1
                    break
        
        return completed
    
    fn _count_active_tasks(self) -> Int:
        """Count tasks that haven't been executed yet."""
        var count = 0
        for i in range(len(self.tasks)):
            if not self.tasks[i].executed:
                count += 1
        return count

# --- Thread Pool ---

@fieldwise_init
struct WorkerData(Copyable):
    var worker_id: Int
    var reactor_ptr: UnsafePointer[AsyncReactor]

fn worker_thread_func(arg: UnsafePointer[UInt8]) -> UnsafePointer[UInt8]:
    """Worker thread function."""
    var data_ptr = arg.bitcast[WorkerData]()
    var data = data_ptr[]
    var reactor_ptr = data.reactor_ptr
    
    # Run the reactor event loop
    _ = reactor_ptr[].run_until_complete()
    
    return UnsafePointer[UInt8]()

struct AsyncRuntime:
    """High-level async runtime with thread pool."""
    var num_workers: Int
    var reactors: UnsafePointer[AsyncReactor]
    var threads: UnsafePointer[UInt64]
    var worker_data: UnsafePointer[WorkerData]
    var next_worker: Int
    var started: Bool
    
    fn __init__(out self, num_workers: Int = 2):
        self.num_workers = num_workers
        self.reactors = UnsafePointer[AsyncReactor].alloc(num_workers)
        self.threads = UnsafePointer[UInt64].alloc(num_workers)
        self.worker_data = UnsafePointer[WorkerData].alloc(num_workers)
        self.next_worker = 0
        self.started = False
        
        # Initialize reactors
        for i in range(num_workers):
            self.reactors[i] = AsyncReactor()
    
    fn spawn_task(mut self, callback_fn: TaskCallbackFn = default_callback) -> TaskHandle:
        """Spawn a new task on the next available worker with a callback."""
        var worker = self.next_worker
        self.next_worker = (self.next_worker + 1) % self.num_workers
        return self.reactors[worker].create_task(callback_fn)
    
    fn spawn_task_with_trait[T: TaskCallback](mut self, callback: T) -> TaskHandle:
        """Spawn a new task on the next available worker with a trait-based callback."""
        var worker = self.next_worker
        self.next_worker = (self.next_worker + 1) % self.num_workers
        return self.reactors[worker].create_task_with_trait[T](callback)
    
    fn trigger(self, handle: TaskHandle, value: UInt64) -> Bool:
        """Trigger a task with a value."""
        # Find which reactor owns this task by checking task_id ranges
        var worker = handle.task_id % self.num_workers
        return self.reactors[worker].trigger_task(handle, value)
    
    fn start(mut self):
        """Start all worker threads."""
        if self.started:
            return
        
        for i in range(self.num_workers):
            self.worker_data[i] = WorkerData(i, self.reactors + i)
            
            var thread_ptr = (self.threads + i).bitcast[UInt8]()
            var data_ptr = (self.worker_data + i).bitcast[UInt8]()
            
            _ = external_call["pthread_create", Int32](
                thread_ptr,
                UnsafePointer[UInt8](),
                worker_thread_func,
                data_ptr
            )
        
        self.started = True
    
    fn wait(self):
        """Wait for all worker threads to complete."""
        if not self.started:
            return
        
        for i in range(self.num_workers):
            _ = external_call["pthread_join", Int32](
                self.threads[i],
                UnsafePointer[UInt8]()
            )
    
    fn shutdown(mut self):
        """Shutdown the runtime."""
        self.wait()
        
        for i in range(self.num_workers):
            self.reactors[i].shutdown()
        
        self.reactors.free()
        self.threads.free()
        self.worker_data.free()
        self.started = False

# --- Example Usage ---

fn example_single_threaded():
    """Example of single-threaded reactor usage with callbacks."""
    print("=== Single-threaded example with callbacks ===")
    
    var reactor = AsyncReactor()
    
    # Create tasks with different callback types
    var handles = List[TaskHandle]()
    
    # Task with default callback
    handles.append(reactor.create_task())
    
    # Task with logging callback
    handles.append(reactor.create_task(logging_callback))
    
    # Task with doubling callback
    handles.append(reactor.create_task(doubling_callback))
    
    # Task with trait-based callback
    var custom_cb = CustomCallback(multiplier=3, print_enabled=True)
    handles.append(reactor.create_task_with_trait(custom_cb))
    
    # Trigger them with values
    for i in range(len(handles)):
        print("Triggering task", i, "with value", 100 + i)
        _ = reactor.trigger_task(handles[i], UInt64(100 + i))
    
    # Run event loop
    var completed = reactor.run_until_complete()
    print("Completed", completed, "tasks")
    
    reactor.shutdown()

fn example_multi_threaded():
    """Example of multi-threaded runtime usage with callbacks."""
    print("=== Multi-threaded example with callbacks ===")
    
    var runtime = AsyncRuntime(num_workers=2)
    
    # Spawn tasks with different callbacks
    var handles = List[TaskHandle]()
    
    # Mix of different callback types
    handles.append(runtime.spawn_task())  # default
    handles.append(runtime.spawn_task(logging_callback))
    handles.append(runtime.spawn_task(doubling_callback))
    
    var custom_cb = CustomCallback(multiplier=5, print_enabled=True)
    handles.append(runtime.spawn_task_with_trait(custom_cb))
    
    handles.append(runtime.spawn_task(logging_callback))
    handles.append(runtime.spawn_task(doubling_callback))
    
    # Trigger tasks
    for i in range(len(handles)):
        print("Triggering multi-threaded task", i, "with value", 200 + i)
        _ = runtime.trigger(handles[i], UInt64(200 + i))
    
    # Start workers and wait
    runtime.start()
    runtime.wait()
    
    runtime.shutdown()
    print("Runtime shutdown complete")

# --- Custom Callback Examples ---

fn my_custom_callback(task_id: Int, value: UInt64) -> TaskResult:
    """Example of a user-defined callback function."""
    print("MY CUSTOM CALLBACK: Processing task", task_id, "with value", value)
    var transformed_value = value + 1000  # Add some custom processing
    print("MY CUSTOM CALLBACK: Transformed value to", transformed_value)
    
    var result = TaskResult()
    result.success = True
    result.value = transformed_value
    return result

struct MyComplexCallback(TaskCallback):
    """Example of a complex trait-based callback with state."""
    var prefix: String
    var counter: Int
    var accumulator: UInt64
    
    fn __init__(out self, prefix: String):
        self.prefix = prefix
        self.counter = 0
        self.accumulator = 0
    
    fn execute(mut self, task_id: Int, value: UInt64) -> TaskResult:
        self.counter += 1
        self.accumulator += value
        
        print(self.prefix, "callback #", self.counter, "- Task", task_id, 
              "value:", value, "accumulator:", self.accumulator)
        
        var result = TaskResult()
        result.success = True
        result.value = self.accumulator  # Return accumulated value
        return result

fn example_custom_callbacks():
    """Example showing custom user-defined callbacks."""
    print("=== Custom callback examples ===")
    
    var reactor = AsyncReactor()
    var handles = List[TaskHandle]()
    
    # Function pointer callback
    handles.append(reactor.create_task(my_custom_callback))
    
    # Complex trait callback
    var complex_cb = MyComplexCallback("COMPLEX")
    handles.append(reactor.create_task_with_trait(complex_cb))
    
    # Trigger tasks
    for i in range(len(handles)):
        print("Triggering custom callback task", i)
        _ = reactor.trigger_task(handles[i], UInt64(50 + i * 10))
    
    var completed = reactor.run_until_complete()
    print("Completed", completed, "custom callback tasks")
    
    reactor.shutdown()

fn main():
    example_single_threaded()
    print()
    example_multi_threaded()
    print()
    example_custom_callbacks()