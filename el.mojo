from sys import external_call
from memory import UnsafePointer, memset_zero
from collections import List

# Threading constants
alias PTHREAD_CREATE_JOINABLE = 0
alias PTHREAD_CREATE_DETACHED = 1

# Epoll constants
alias EPOLLIN = 1
alias EPOLLET = 1 << 31  # Edge-triggered mode

@fieldwise_init
struct ThreadData(Copyable):
    var core_id: Int
    var reactor_ptr: UnsafePointer[UInt8]

@fieldwise_init
struct AsyncTask(Copyable, Movable):
    var task_id: Int
    var fd: Int
    var executed: Bool
    
    fn __init__(out self, task_id: Int, fd: Int):
        self.task_id = task_id
        self.fd = fd
        self.executed = False
    
    fn execute(mut self):
        if self.executed:
            print("Task", self.task_id, "already executed, skipping")
            return
            
        print("Task", self.task_id, "executing on fd", self.fd, "- Thread:", Int(external_call["pthread_self", UInt64]()))
        
        # Read the eventfd value (8 bytes)
        var buffer = UnsafePointer[UInt64].alloc(1)
        var bytes_read = external_call["syscall", Int](
            0,  # SYS_read
            self.fd,
            buffer.bitcast[UInt8](),
            8
        )
        
        if bytes_read == 8:
            var value = buffer[]
            print("  Read eventfd value:", value)
        else:
            print("  Error reading eventfd, bytes_read:", bytes_read)
        
        buffer.free()
        self.executed = True
        
        # Close the fd to clean up
        var _ = external_call["close", Int32](self.fd)
        print("  Closed eventfd", self.fd)

struct EpollReactor:
    var epoll_fd: Int
    var tasks: List[AsyncTask]
    var should_stop: Bool
    var tasks_completed: Int
    var total_tasks: Int
    
    fn __init__(out self):
        self.epoll_fd = Int(external_call["epoll_create1", Int32](0o2000000))
        self.tasks = List[AsyncTask]()
        self.should_stop = False
        self.tasks_completed = 0
        self.total_tasks = 0
        
        if self.epoll_fd == -1:
            print("Failed to create epoll instance")
    
    fn add_task(mut self, owned task: AsyncTask):
        var event_data: UInt32 = task.task_id
        var task_fd: Int = task.fd
        
        print("  Adding task", task.task_id, "with fd", task_fd, "to epoll")
        
        self.tasks.append(task^)
        self.total_tasks += 1
        
        # Linux epoll_event: 4 bytes events + 4 bytes padding + 8 bytes data
        var event_buffer = UnsafePointer[UInt8].alloc(16)
        memset_zero(event_buffer, 16)
        
        # Set events (first 4 bytes) - remove edge triggered for now
        var events_ptr = event_buffer.bitcast[UInt32]()
        events_ptr[] = UInt32(EPOLLIN)  # Level-triggered instead of edge-triggered
        
        # Set data in fd field (bytes 8-12)
        var data_ptr = (event_buffer + 8).bitcast[UInt32]()
        data_ptr[] = event_data
        
        var result = external_call["epoll_ctl", Int32](
            self.epoll_fd,
            1,  # EPOLL_CTL_ADD
            task_fd,
            event_buffer
        )
        
        event_buffer.free()
        
        if result == -1:
            print("Failed to add fd", task_fd, "to epoll")
        else:
            print("  Successfully added task", event_data, "with fd", task_fd, "to epoll")
    
    fn run_event_loop(mut self):
        var max_events = 10
        var events_buffer = UnsafePointer[UInt8].alloc(16 * max_events)
        var iteration = 0
        
        print("Event loop starting, waiting for", self.total_tasks, "tasks...")
        
        while self.tasks_completed < self.total_tasks and iteration < 15:
            iteration += 1
            
            var nfds = external_call["epoll_wait", Int32](
                self.epoll_fd,
                events_buffer,
                max_events,
                1000  # 1 second timeout
            )
            
            if nfds == -1:
                print("epoll_wait failed")
                break
            elif nfds == 0:
                print("Timeout iteration", iteration, "- completed", self.tasks_completed, "of", self.total_tasks)
                continue
            
            print("Got", nfds, "events (iteration", iteration, ")")
            
            # Process events
            for i in range(nfds):
                var event_offset = i * 16
                var event_ptr = events_buffer + event_offset
                
                # Read events (first 4 bytes)
                var events_field = (event_ptr.bitcast[UInt32]())[]
                
                # Read task_id from fd field (bytes 8-12)
                var data_fd_ptr = (event_ptr + 8).bitcast[UInt32]()
                var task_id = Int(data_fd_ptr[])
                
                print("  Event", i, ": task_id =", task_id, "events =", events_field)
                
                var found = False
                for j in range(len(self.tasks)):
                    if self.tasks[j].task_id == task_id and not self.tasks[j].executed:
                        self.tasks[j].execute()
                        self.tasks_completed += 1
                        print("Completed task", task_id, "(", self.tasks_completed, "/", self.total_tasks, ")")
                        found = True
                        break
                
                if not found:
                    print("  Skipping: Task", task_id, "not found or already executed")
        
        events_buffer.free()
        print("Event loop finished -", self.tasks_completed, "of", self.total_tasks, "tasks completed")

fn create_eventfd() -> Int:
    """Create an eventfd for notification"""
    # eventfd(initval, flags) - use 0 for both
    var fd = external_call["eventfd", Int32](0, 0)
    return Int(fd)

fn trigger_event(eventfd: Int, value: UInt64):
    """Write to eventfd to trigger event"""
    var value_ptr = UnsafePointer[UInt64].alloc(1)
    value_ptr[] = value
    
    var bytes_written = external_call["syscall", Int](
        1,  # SYS_write
        eventfd,
        value_ptr.bitcast[UInt8](),
        8
    )
    
    value_ptr.free()
    
    if bytes_written == 8:
        print("  Triggered eventfd", eventfd, "with value", value)
    else:
        print("  Failed to trigger eventfd", eventfd)

fn thread_worker(arg: UnsafePointer[UInt8]) -> UnsafePointer[UInt8]:
    var thread_data_ptr = arg.bitcast[ThreadData]()
    var thread_data = thread_data_ptr[]
    
    print("Worker thread", thread_data.core_id, "started")
    
    var reactor = EpollReactor()
    var eventfds = List[Int]()
    
    # Create all tasks first
    for i in range(3):
        var eventfd = create_eventfd()
        var task_id = thread_data.core_id * 10 + i
        
        print("Thread", thread_data.core_id, "creating task", task_id, "with eventfd", eventfd)
        
        var task = AsyncTask(task_id, eventfd)
        reactor.add_task(task^)
        eventfds.append(eventfd)
    
    print("Thread", thread_data.core_id, "triggering", len(eventfds), "events...")
    
    # Trigger all events
    for i in range(len(eventfds)):
        var value = UInt64(thread_data.core_id * 1000 + i + 1)  # Non-zero value
        trigger_event(eventfds[i], value)
    
    print("Thread", thread_data.core_id, "starting event loop...")
    
    # Run the event loop
    reactor.run_event_loop()
    
    print("Worker thread", thread_data.core_id, "finished")
    return UnsafePointer[UInt8]()

fn main():
    var num_cores = 2
    print("Starting async task scheduler with", num_cores, "worker threads")
    print("Using eventfd for clean event notification")
    
    var threads = UnsafePointer[UInt64].alloc(num_cores)
    var thread_data_array = UnsafePointer[ThreadData].alloc(num_cores)
    
    # Create worker threads
    for i in range(num_cores):
        thread_data_array[i] = ThreadData(i, UnsafePointer[UInt8]())
        
        var thread_ptr = (threads + i).bitcast[UInt8]()
        var data_ptr = (thread_data_array + i).bitcast[UInt8]()
        
        var create_result = external_call["pthread_create", Int32](
            thread_ptr,
            UnsafePointer[UInt8](),
            thread_worker,
            data_ptr
        )
        
        if create_result != 0:
            print("Failed to create worker thread", i)
        else:
            print("Created worker thread", i)
    
    # Wait for all threads
    for i in range(num_cores):
        var join_result = external_call["pthread_join", Int32](
            threads[i],
            UnsafePointer[UInt8]()
        )
        
        if join_result == 0:
            print("Worker thread", i, "joined")
        else:
            print("Failed to join worker thread", i)
    
    threads.free()
    thread_data_array.free()
    
    print("✅ Async task scheduler completed successfully!")
    print("All tasks executed across", num_cores, "worker threads using epoll + eventfd")