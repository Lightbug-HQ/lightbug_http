from sys import external_call
from memory import UnsafePointer, memset_zero
from collections import List
from testing import assert_true, assert_false, assert_equal, assert_not_equal

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

#fn main():
#    example_single_threaded()
#    print()
#    example_multi_threaded()
#    print()
#    example_custom_callbacks()



# ===----------------------------------------------------------------------=== #
# Basic Component Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_task_handle
fn test_task_handle() raises:
    print("== test_task_handle")
    
    # Test valid handle
    var valid_handle = runtime.TaskHandle(task_id=42, fd=10)
    # CHECK: TaskHandle valid: True
    print("TaskHandle valid:", valid_handle.is_valid())
    assert_true(valid_handle.is_valid(), "Valid handle should return True")
    assert_equal(valid_handle.task_id, 42, "Task ID should match")
    assert_equal(valid_handle.fd, 10, "FD should match")
    
    # Test invalid handle
    var invalid_handle = runtime.TaskHandle(task_id=-1, fd=-1)
    # CHECK: TaskHandle invalid: False
    print("TaskHandle invalid:", invalid_handle.is_valid())
    assert_false(invalid_handle.is_valid(), "Invalid handle should return False")


# CHECK-LABEL: test_task_result
fn test_task_result() raises:
    print("== test_task_result")
    
    # Test default construction
    var default_result = runtime.TaskResult()
    # CHECK: Default TaskResult success: False
    print("Default TaskResult success:", default_result.success)
    assert_false(default_result.success, "Default result should be unsuccessful")
    assert_equal(default_result.value, 0, "Default value should be 0")
    assert_equal(default_result.error_msg, "", "Default error message should be empty")
    
    # Test successful result
    var success_result = runtime.TaskResult()
    success_result.success = True
    success_result.value = 123
    # CHECK: Success TaskResult value: 123
    print("Success TaskResult value:", success_result.value)
    assert_true(success_result.success, "Success result should be successful")
    assert_equal(success_result.value, 123, "Value should match")


# CHECK-LABEL: test_eventfd
fn test_eventfd() raises:
    print("== test_eventfd")
    
    var eventfd = runtime.EventFD(0)
    if eventfd.is_valid():
        # CHECK: EventFD created successfully
        print("EventFD created successfully")
        assert_true(eventfd.is_valid(), "EventFD should be valid")
        
        # Test triggering with value
        var trigger_success = eventfd.trigger(42)
        # CHECK: EventFD trigger success: True
        print("EventFD trigger success:", trigger_success)
        assert_true(trigger_success, "EventFD trigger should succeed")
        
        eventfd.close()
    else:
        print("WARNING: EventFD creation failed - system may not support eventfd")


# ===----------------------------------------------------------------------=== #
# Callback Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_default_callback
fn test_default_callback() raises:
    print("== test_default_callback")
    
    var result = runtime.default_callback(1, 100)
    # CHECK: Default callback result: success=True, value=100
    print("Default callback result: success=" + String(result.success) + ", value=" + String(result.value))
    assert_true(result.success, "Default callback should succeed")
    assert_equal(result.value, 100, "Default callback should return input value")


# CHECK-LABEL: test_logging_callback
fn test_logging_callback() raises:
    print("== test_logging_callback")
    
    var result = runtime.logging_callback(2, 200)
    # CHECK: CALLBACK: Task 2 completed with value 200
    # CHECK: Logging callback result: success=True, value=200
    print("Logging callback result: success=" + String(result.success) + ", value=" + String(result.value))
    assert_true(result.success, "Logging callback should succeed")
    assert_equal(result.value, 200, "Logging callback should return input value")


# CHECK-LABEL: test_doubling_callback
fn test_doubling_callback() raises:
    print("== test_doubling_callback")
    
    var result = runtime.doubling_callback(3, 50)
    # CHECK: CALLBACK: Task 3 doubling 50 -> 100
    # CHECK: Doubling callback result: success=True, value=100
    print("Doubling callback result: success=" + String(result.success) + ", value=" + String(result.value))
    assert_true(result.success, "Doubling callback should succeed")
    assert_equal(result.value, 100, "Doubling callback should double the value")



# CHECK-LABEL: test_custom_callback_trait
fn test_custom_callback_trait() raises:
    print("== test_custom_callback_trait")
    
    var callback = runtime.CustomCallback(multiplier=3, print_enabled=True)
    var result = callback.execute(5, 20)
    # CHECK: Custom callback: Task 5 value 20 * multiplier 3
    # CHECK: Custom callback trait result: success=True, value=60
    print("Custom callback trait result: success=" + String(result.success) + ", value=" + String(result.value))
    assert_true(result.success, "Custom callback trait should succeed")
    assert_equal(result.value, 60, "Custom callback trait should multiply value")


# ===----------------------------------------------------------------------=== #
# Single-threaded Reactor Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_reactor_creation
fn test_reactor_creation() raises:
    print("== test_reactor_creation")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # CHECK: Reactor created successfully
        print("Reactor created successfully")
        assert_true(reactor.is_valid(), "Reactor should be valid")
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - system may not support epoll")


# CHECK-LABEL: test_reactor_task_creation
fn test_reactor_task_creation() raises:
    print("== test_reactor_task_creation")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # Test creating task with default callback
        var handle1 = reactor.create_task()
        if handle1.is_valid():
            # CHECK: Task 1 created successfully with ID: 0
            print("Task 1 created successfully with ID:", handle1.task_id)
            assert_true(handle1.is_valid(), "Task handle should be valid")
            assert_equal(handle1.task_id, 0, "First task should have ID 0")
        
        # Test creating task with custom callback
        var handle2 = reactor.create_task(runtime.logging_callback)
        if handle2.is_valid():
            # CHECK: Task 2 created successfully with ID: 1
            print("Task 2 created successfully with ID:", handle2.task_id)
            assert_true(handle2.is_valid(), "Task handle should be valid")
            assert_equal(handle2.task_id, 1, "Second task should have ID 1")
        
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - skipping task creation test")


# CHECK-LABEL: test_reactor_single_task_execution
fn test_reactor_single_task_execution() raises:
    print("== test_reactor_single_task_execution")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # Create a task with logging callback
        var handle = reactor.create_task(runtime.logging_callback)
        if handle.is_valid():
            # Trigger the task
            var trigger_success = reactor.trigger_task(handle, 150)
            # CHECK: Triggering task with value 150: True
            print("Triggering task with value 150:", trigger_success)
            assert_true(trigger_success, "Task trigger should succeed")
            
            # Run event loop once
            var completed = reactor.poll_once()
            # CHECK: CALLBACK: Task 0 completed with value 150
            # CHECK: Completed tasks: 1
            print("Completed tasks:", completed)
            assert_equal(completed, 1, "Should complete exactly 1 task")
        
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - skipping single task execution test")


# CHECK-LABEL: test_reactor_multiple_tasks
fn test_reactor_multiple_tasks() raises:
    print("== test_reactor_multiple_tasks")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        var handles = runtime.List[runtime.TaskHandle]()
        
        # Create multiple tasks with different callbacks
        handles.append(reactor.create_task(runtime.default_callback))
        handles.append(reactor.create_task(runtime.doubling_callback))
        handles.append(reactor.create_task(runtime.logging_callback))
        
        var valid_handles = 0
        for i in range(len(handles)):
            if handles[i].is_valid():
                valid_handles += 1
        
        # CHECK: Created 3 valid task handles
        print("Created", valid_handles, "valid task handles")
        assert_equal(valid_handles, 3, "Should create 3 valid handles")
        
        # Trigger all tasks
        for i in range(len(handles)):
            if handles[i].is_valid():
                var trigger_success = reactor.trigger_task(handles[i], UInt64(100 + i))
                assert_true(trigger_success, "Each task trigger should succeed")
        
        # Run until completion
        var total_completed = reactor.run_until_complete(max_iterations=10)
        # CHECK: CALLBACK: Task 1 doubling 101 -> 202
        # CHECK: CALLBACK: Task 2 completed with value 102
        # CHECK: Total completed tasks: 3
        print("Total completed tasks:", total_completed)
        assert_equal(total_completed, 3, "Should complete all 3 tasks")
        
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - skipping multiple tasks test")


# ===----------------------------------------------------------------------=== #
# Multi-threaded Runtime Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_runtime_creation
fn test_runtime_creation() raises:
    print("== test_runtime_creation")
    
    var runtime_instance = runtime.AsyncRuntime(num_workers=2)
    # CHECK: Runtime created with 2 workers
    print("Runtime created with 2 workers")
    assert_equal(runtime_instance.num_workers, 2, "Should have 2 workers")
    assert_false(runtime_instance.started, "Runtime should not be started initially")
    
    runtime_instance.shutdown()


# CHECK-LABEL: test_runtime_task_spawning
fn test_runtime_task_spawning() raises:
    print("== test_runtime_task_spawning")
    
    var runtime_instance = runtime.AsyncRuntime(num_workers=2)
    
    # Spawn tasks with different callbacks
    var handles = runtime.List[runtime.TaskHandle]()
    handles.append(runtime_instance.spawn_task(runtime.default_callback))
    handles.append(runtime_instance.spawn_task(runtime.logging_callback))
    handles.append(runtime_instance.spawn_task(runtime.doubling_callback))
    
    var valid_handles = 0
    for i in range(len(handles)):
        if handles[i].is_valid():
            valid_handles += 1
    
    # CHECK: Spawned 3 valid tasks
    print("Spawned", valid_handles, "valid tasks")
    assert_equal(valid_handles, 3, "Should spawn 3 valid tasks")
    
    runtime_instance.shutdown()


# ===----------------------------------------------------------------------=== #
# Edge Cases and Error Handling Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_invalid_handles
fn test_invalid_handles() raises:
    print("== test_invalid_handles")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # Test triggering invalid handle
        var invalid_handle = runtime.TaskHandle(task_id=-1, fd=-1)
        var trigger_result = reactor.trigger_task(invalid_handle, 100)
        # CHECK: Triggering invalid handle: False
        print("Triggering invalid handle:", trigger_result)
        assert_false(trigger_result, "Triggering invalid handle should fail")
        
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - skipping invalid handles test")


# CHECK-LABEL: test_reactor_shutdown
fn test_reactor_shutdown() raises:
    print("== test_reactor_shutdown")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # Create some tasks
        var handle1 = reactor.create_task()
        var handle2 = reactor.create_task()
        
        # Shutdown should clean up resources
        reactor.shutdown()
        # CHECK: Reactor shutdown completed
        print("Reactor shutdown completed")
        assert_false(reactor.is_valid(), "Reactor should be invalid after shutdown")
    else:
        print("WARNING: Reactor creation failed - skipping shutdown test")


# CHECK-LABEL: test_task_execution_idempotency
fn test_task_execution_idempotency() raises:
    print("== test_task_execution_idempotency")
    
    # This tests internal task execution behavior
    # Note: This is testing the AsyncTask.execute() method directly
    var task = runtime.AsyncTask(1, -1, runtime.default_callback)  # Use invalid fd for safety
    
    # First execution should fail due to invalid fd
    var result1 = task.execute()
    # CHECK: First execution failed as expected
    print("First execution failed as expected")
    assert_false(result1.success, "First execution should fail with invalid fd")
    assert_true(task.executed, "Task should be marked as executed")
    
    # Second execution should also fail (already executed)
    var result2 = task.execute()
    # CHECK: Second execution failed as expected
    print("Second execution failed as expected")
    assert_false(result2.success, "Second execution should fail (already executed)")
    assert_not_equal(result2.error_msg, "", "Should have error message about already executed")


# ===----------------------------------------------------------------------=== #
# Integration Tests
# ===----------------------------------------------------------------------=== #

# CHECK-LABEL: test_end_to_end_workflow
fn test_end_to_end_workflow() raises:
    print("== test_end_to_end_workflow")
    
    var reactor = runtime.AsyncReactor()
    if reactor.is_valid():
        # Test complete workflow: create -> trigger -> execute -> verify
        var handles = runtime.List[runtime.TaskHandle]()
        
        # Create tasks
        handles.append(reactor.create_task(runtime.default_callback))
        handles.append(reactor.create_task(runtime.doubling_callback))
        
        # Verify creation
        var created_count = 0
        for i in range(len(handles)):
            if handles[i].is_valid():
                created_count += 1
        
        # CHECK: End-to-end: Created 2 tasks
        print("End-to-end: Created", created_count, "tasks")
        assert_equal(created_count, 2, "Should create 2 tasks")
        
        # Trigger tasks
        var triggered_count = 0
        for i in range(len(handles)):
            if handles[i].is_valid():
                if reactor.trigger_task(handles[i], UInt64(50 * (i + 1))):
                    triggered_count += 1
        
        # CHECK: End-to-end: Triggered 2 tasks
        print("End-to-end: Triggered", triggered_count, "tasks")
        assert_equal(triggered_count, 2, "Should trigger 2 tasks")
        
        # Execute tasks
        var completed = reactor.run_until_complete(max_iterations=5)
        # CHECK: CALLBACK: Task 1 doubling 100 -> 200
        # CHECK: End-to-end: Completed 2 tasks
        print("End-to-end: Completed", completed, "tasks")
        assert_equal(completed, 2, "Should complete 2 tasks")
        
        reactor.shutdown()
    else:
        print("WARNING: Reactor creation failed - skipping end-to-end test")


# ===----------------------------------------------------------------------=== #
# Main Test Runner
# ===----------------------------------------------------------------------=== #

def main():
    print("Starting custom async runtime tests...")
    print()
    
    try:
        # Basic component tests
        test_task_handle()
        test_task_result()
        test_eventfd()
        print()
        
        # Callback tests
        test_default_callback()
        test_logging_callback()
        test_doubling_callback()
        # test_simple_callback_trait()
        test_custom_callback_trait()
        print()
        
        # Single-threaded reactor tests
        test_reactor_creation()
        test_reactor_task_creation()
        test_reactor_single_task_execution()
        test_reactor_multiple_tasks()
        print()
        
        # Multi-threaded runtime tests
        test_runtime_creation()
        test_runtime_task_spawning()
        print()
        
        # Edge cases and error handling
        test_invalid_handles()
        test_reactor_shutdown()
        test_task_execution_idempotency()
        print()
        
        # Integration tests
        test_end_to_end_workflow()
        print()
        
        # Performance tests
        # test_many_tasks()
        print()
        
        print("All custom async runtime tests completed!")
    except e:
        print("Test failed with error: ", e)
