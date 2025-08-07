#!/usr/bin/env mojo

from runtime import asyncrt
from time import sleep

async fn simple_worker():
    """Simple async worker that just prints."""
    print("Worker starting")
    sleep(0.1)  # Simulate some work
    print("Worker finished")

fn test_task_group():
    """Test TaskGroup with simple void tasks."""
    print("=== Testing TaskGroup ===")
    print("Parallelism level:", asyncrt.parallelism_level())
    
    var task_group = asyncrt.TaskGroup()
    
    # Create multiple simple tasks
    for i in range(3):
        print("Creating task", i)
        var coro = simple_worker()
        task_group.create_task(coro^)
    
    print("Waiting for all tasks to complete...")
    task_group.wait()
    print("All TaskGroup tasks completed")

fn main():
    print("Testing Mojo AsyncRT functionality")
    
    test_task_group()
    
    print("Async test completed!")