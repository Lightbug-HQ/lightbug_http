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
    """Handle to an async task"""
    var task_id: Int
    var fd: Int
    
    fn is_valid(self) -> Bool:
        return self.fd >= 0

@fieldwise_init
struct TaskResult:
    """Result of an async task execution"""
    var success: Bool
    var value: UInt64
    var error_msg: String
    
    fn __init__(out self):
        self.success = False
        self.value = 0
        self.error_msg = ""

# --- Callback Types ---
trait TaskCallback:
    """Interface for task callbacks"""
    fn execute(self, task_id: Int, value: UInt64) -> TaskResult:
        ...

struct SimpleCallback(TaskCallback):
    """Simple callback that just prints the value"""
    fn execute(self, task_id: Int, value: UInt64) -> TaskResult:
        var result = TaskResult()
        result.success = True
        result.value = value
        return result

# --- Internal Task Type ---

@fieldwise_init
struct AsyncTask(Copyable, Movable):
    var task_id: Int
    var fd: Int
    var executed: Bool
    var callback_ptr: UnsafePointer[UInt8]  # Will store callback when we have proper trait support
    
    fn __init__(out self, task_id: Int, fd: Int):
        self.task_id = task_id
        self.fd = fd
        self.executed = False
        self.callback_ptr = UnsafePointer[UInt8]()
    
    fn execute(out self) -> TaskResult:
        """Execute the task and return result"""
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
            result.value = buffer[]
            result.success = True
        else:
            result.error_msg = "Failed to read eventfd"
        
        buffer.free()
        self.executed = True
        
        # Close the fd to clean up
        _ = external_call["close", Int32](self.fd)
        
        return result

# --- Event System ---

struct EventFD:
    """Wrapper for eventfd operations"""
    var fd: Int
    
    fn __init__(out self, initial_value: UInt64 = 0):
        self.fd = Int(external_call["eventfd", Int32](initial_value, 0))
    
    fn is_valid(self) -> Bool:
        return self.fd >= 0
    
    fn trigger(self, value: UInt64) -> Bool:
        """Trigger the eventfd with a value"""
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
        """Close the eventfd"""
        if self.is_valid():
            _ = external_call["close", Int32](self.fd)

# --- Main Reactor ---

struct AsyncReactor:
    """Async reactor using epoll for event handling"""
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
    
    fn create_task(self) -> TaskHandle:
        """Create a new async task and return its handle"""
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
        
        var task = AsyncTask(task_id, eventfd.fd)
        
        # Add to epoll
        if self._add_to_epoll(task_id, eventfd.fd):
            self.tasks.append(task^)
        else:
            eventfd.close()
            handle.fd = -1
        
        return handle
    
    fn trigger_task(self, handle: TaskHandle, value: UInt64) -> Bool:
        """Trigger a task with a value"""
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
    
    fn poll_once(out self) -> Int:
        """Poll for events once, returns number of tasks completed"""
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
    
    fn run_until_complete(self, max_iterations: Int = 100) -> Int:
        """Run the event loop until all tasks complete or max iterations reached"""
        var total_completed = 0
        var iterations = 0
        var active_tasks = self._count_active_tasks()
        
        while active_tasks > 0 and iterations < max_iterations:
            var completed = self.poll_once()
            total_completed += completed
            active_tasks = self._count_active_tasks()
            iterations += 1
        
        return total_completed
    
    fn shutdown(out self):
        """Clean shutdown of the reactor"""
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
        """Add a file descriptor to epoll monitoring"""
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
    
    fn _process_events(out self, events_buffer: UnsafePointer[UInt8], nfds: Int32) -> Int:
        """Process epoll events"""
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
        """Count tasks that haven't been executed yet"""
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
    """Worker thread function"""
    var data_ptr = arg.bitcast[WorkerData]()
    var data = data_ptr[]
    var reactor_ptr = data.reactor_ptr
    
    # Run the reactor event loop
    _ = reactor_ptr[].run_until_complete()
    
    return UnsafePointer[UInt8]()

struct AsyncRuntime:
    """High-level async runtime with thread pool"""
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
    
    fn spawn_task(mut self) -> TaskHandle:
        """Spawn a new task on the next available worker"""
        var worker = self.next_worker
        self.next_worker = (self.next_worker + 1) % self.num_workers
        return self.reactors[worker].create_task()
    
    fn trigger(self, handle: TaskHandle, value: UInt64) -> Bool:
        """Trigger a task with a value"""
        # Find which reactor owns this task by checking task_id ranges
        var worker = handle.task_id % self.num_workers
        return self.reactors[worker].trigger_task(handle, value)
    
    fn start(out self):
        """Start all worker threads"""
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
        """Wait for all worker threads to complete"""
        if not self.started:
            return
        
        for i in range(self.num_workers):
            _ = external_call["pthread_join", Int32](
                self.threads[i],
                UnsafePointer[UInt8]()
            )
    
    fn shutdown(out self):
        """Shutdown the runtime"""
        self.wait()
        
        for i in range(self.num_workers):
            self.reactors[i].shutdown()
        
        self.reactors.free()
        self.threads.free()
        self.worker_data.free()
        self.started = False

# --- Example Usage ---

fn example_single_threaded():
    """Example of single-threaded reactor usage"""
    print("=== Single-threaded example ===")
    
    var reactor = AsyncReactor()
    
    # Create some tasks
    var handles = List[TaskHandle]()
    for i in range(3):
        handles.append(reactor.create_task())
    
    # Trigger them with values
    for i in range(len(handles)):
        _ = reactor.trigger_task(handles[i], UInt64(100 + i))
    
    # Run event loop
    var completed = reactor.run_until_complete()
    print("Completed", completed, "tasks")
    
    reactor.shutdown()

fn example_multi_threaded():
    """Example of multi-threaded runtime usage"""
    print("=== Multi-threaded example ===")
    
    var runtime = AsyncRuntime(num_workers=2)
    
    # Spawn tasks
    var handles = List[TaskHandle]()
    for i in range(6):
        handles.append(runtime.spawn_task())
    
    # Trigger tasks
    for i in range(len(handles)):
        _ = runtime.trigger(handles[i], UInt64(200 + i))
    
    # Start workers and wait
    runtime.start()
    runtime.wait()
    
    runtime.shutdown()
    print("Runtime shutdown complete")

fn main():
    example_single_threaded()
    print()
    example_multi_threaded()