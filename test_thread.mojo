#!/usr/bin/env mojo

"""Test file for the thread module."""

from thread import (
    ThreadId, Thread, Builder, JoinHandle, Result, ThreadError,
    yield_now, sleep_ms, sleep, current, available_parallelism,
    Duration, Instant, now
)

fn test_thread_id():
    """Test ThreadId functionality."""
    print("Testing ThreadId...")
    
    var id1 = ThreadId()
    var id2 = ThreadId()
    
    print("ID1:", id1.as_u64())
    print("ID2:", id2.as_u64())
    print("IDs equal?", id1 == id2)
    print("IDs different?", id1 != id2)

fn test_current_thread():
    """Test current thread functionality."""
    print("Testing current thread...")
    
    var current_thread = current()
    var thread_id = current_thread.id()
    print("Current thread ID:", thread_id.as_u64())

fn test_duration():
    """Test Duration functionality."""
    print("Testing Duration...")
    
    var dur1 = Duration(seconds=5)
    var dur2 = Duration(milliseconds=1500)
    
    print("Duration 1 (5s) total nanoseconds:", dur1.total_nanoseconds())
    print("Duration 2 (1.5s) total nanoseconds:", dur2.total_nanoseconds())
    
    var diff = dur1 - dur2
    print("Difference nanoseconds:", diff.total_nanoseconds())

fn test_sleep():
    """Test sleep functionality."""
    print("Testing sleep...")
    
    print("Sleeping for 100ms...")
    sleep_ms(100)
    print("Done sleeping!")
    
    var dur = Duration(milliseconds=50)
    print("Sleeping for 50ms using Duration...")
    sleep(dur)
    print("Done sleeping with Duration!")

fn test_yield():
    """Test yield functionality."""
    print("Testing yield...")
    
    print("Yielding to other threads...")
    yield_now()
    print("Yielded!")

fn test_parallelism():
    """Test available_parallelism function."""
    print("Testing available_parallelism...")
    
    try:
        var cores = available_parallelism()
        print("Available CPU cores:", cores)
    except e:
        print("Error getting parallelism:", e)

fn test_builder():
    """Test Builder functionality."""
    print("Testing Builder...")
    
    var builder = Builder.new()
    var named_builder = builder.name("test-thread")
    var sized_builder = named_builder.stack_size(1024 * 1024)
    
    print("Builder created and configured")
    
    # Note: spawn is not fully implemented yet
    try:
        # This would fail with "not yet fully implemented" 
        # var handle = sized_builder.spawn(fn() -> Int: return 42)
        print("Spawn not yet fully implemented")
    except:
        print("Expected: spawn not implemented")

fn test_result_type():
    """Test Result type functionality."""
    print("Testing Result type...")
    
    # Test successful result
    var success_result = Result[Int](42)
    print("Success result is ok?", success_result.is_ok())
    print("Success result is err?", success_result.is_err())
    
    try:
        var value = success_result.value()
        print("Success result value:", value)
    except e:
        print("Error getting value:", e)
    
    # Test error result
    var error_result = Result[Int](ThreadError("Test error"))
    print("Error result is ok?", error_result.is_ok())
    print("Error result is err?", error_result.is_err())
    
    try:
        var value = error_result.value()
        print("Should not reach here")
    except e:
        print("Expected error:", e)

fn main():
    """Main test function."""
    print("=== Mojo Thread Module Tests ===")
    
    test_thread_id()
    print()
    
    test_current_thread()
    print()
    
    test_duration()
    print()
    
    test_sleep()
    print()
    
    test_yield()
    print()
    
    test_parallelism()
    print()
    
    test_builder()
    print()
    
    test_result_type()
    print()
    
    print("=== Tests Complete ===")
    print("Note: Full thread spawning is not yet implemented due to")
    print("complexity of handling function pointers and thread data in Mojo.")
