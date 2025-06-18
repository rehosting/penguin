# Syscalls Plugin System

The Syscalls plugin provides a comprehensive interface for monitoring, filtering, and intercepting system calls in the guest via the IGLOO hypervisor interface. This system enables real-time analysis of guest behavior, security monitoring, and dynamic program analysis.

## Overview

The syscalls system operates through a multi-layer architecture:

1. **Kernel Layer**: IGLOO kernel module hooks into syscall entry/return points
2. **Hypervisor Layer**: Portal system manages communication between guest and host
3. **Plugin Layer**: Python plugins register callbacks and process syscall events

## Quick Start

```python
from penguin import plugins, Plugin

class MySyscallMonitor(Plugin):
    def __init__(self):
        # Register syscall hooks in __init__
        plugins.syscalls.syscall("on_sys_execve_enter")(self.monitor_execve)
        plugins.syscalls.syscall("on_all_sys_enter", comm_filter="target_process")(self.monitor_all)
    
    def monitor_execve(self, pt_regs, proto, syscall, filename, argv, envp):
        """Monitor process execution"""
        filename_str = yield from plugins.mem.read_str(filename)
        print(f"Process executing: {filename_str}")
    
    def monitor_all(self, pt_regs, proto, syscall):
        """Monitor all syscalls for a specific process"""
        print(f"Syscall: {proto.name} by {syscall.task.comm}")
```

## Core Concepts

### Syscall Events

Every syscall generates events that can be intercepted at two points:

- **Entry (`on_enter`)**: Before the syscall executes in the kernel
- **Return (`on_return`)**: After the syscall completes

### Hook Registration

Hooks are registered using the `@syscalls.syscall()` decorator with flexible filtering options:

```python
@syscalls.syscall(
    name_or_pattern="sys_openat",
    on_enter=True,
    on_return=True,
    comm_filter="target_app",
    pid_filter=1234,
    arg_filters=[None, ValueFilter.exact(0x42)],
    retval_filter=ValueFilter.success()
)
def my_handler(pt_regs, proto, syscall, *args):
    # Handler code here
    pass
```

## API Reference

### Decorator Parameters

#### `name_or_pattern` (Optional[str])
Specifies which syscalls to hook. Supports multiple formats:

```python
# Specific syscall
@syscalls.syscall("sys_open")

# Pattern-based (hsyscall format)
@syscalls.syscall("on_sys_execve_enter")
@syscalls.syscall("on_sys_openat_return")

# All syscalls
@syscalls.syscall("on_all_sys_enter")

# Unknown syscalls (those without metadata)
@syscalls.syscall("on_unknown_sys_enter")
```

#### `on_enter` / `on_return` (Optional[bool])
Control when the hook triggers:

```python
# Entry only (default if neither specified)
@syscalls.syscall("sys_open", on_enter=True)

# Return only
@syscalls.syscall("sys_open", on_return=True)

# Both entry and return
@syscalls.syscall("sys_open", on_enter=True, on_return=True)
```

#### `comm_filter` (Optional[str])
Filter by process name:

```python
@syscalls.syscall("sys_write", comm_filter="nginx")
def monitor_nginx_writes(pt_regs, proto, syscall, fd, buf, count):
    pass
```

#### `pid_filter` (Optional[int])
Filter by specific process ID:

```python
@syscalls.syscall("sys_read", pid_filter=1234)
def monitor_specific_process(pt_regs, proto, syscall, fd, buf, count):
    pass
```

### Advanced Filtering with ValueFilter

The `ValueFilter` class provides sophisticated argument and return value filtering:

```python
from apis.syscalls import ValueFilter

# Exact match
ValueFilter.exact(42)

# Numeric comparisons
ValueFilter.greater(100)
ValueFilter.less_equal(1000)
ValueFilter.range(10, 20)

# Success/error filtering
ValueFilter.success()  # >= 0
ValueFilter.error()    # < 0

# Bitwise operations
ValueFilter.bitmask_set(0x0001)    # All specified bits set
ValueFilter.bitmask_clear(0x0002)  # All specified bits clear
```

#### `arg_filters` (Optional[List[Any]])
Filter by syscall arguments:

```python
@syscalls.syscall(
    "sys_ioctl",
    arg_filters=[
        None,                          # arg0: no filter
        ValueFilter.exact(0xabcd),     # arg1: exact match
        ValueFilter.range(100, 200)    # arg2: range filter
    ]
)
def filtered_ioctl(pt_regs, proto, syscall, fd, cmd, arg):
    pass
```

#### `retval_filter` (Optional[Any])
Filter by return value:

```python
# Only successful calls
@syscalls.syscall("sys_open", on_return=True, retval_filter=ValueFilter.success())

# Specific error codes
@syscalls.syscall("sys_open", on_return=True, retval_filter=ValueFilter.exact(-2))  # ENOENT

# Backward compatibility with simple values
@syscalls.syscall("sys_getpid", on_return=True, retval_filter=1234)
```

## Handler Function Signatures

### Standard Handlers

```python
def handler(regs, proto, syscall, *args):
    """
    regs: Register/context object (formerly pt_regs, now typically a PtRegsWrapper)
        - Contains the CPU register state at the time of the syscall.
        - Provides access to general-purpose registers, PC, SP, etc.
        - Used for advanced introspection or argument extraction.
    proto: SyscallPrototype with metadata (name, types, arg names)
    syscall: SyscallEvent object with runtime data
    *args: Unpacked syscall arguments (for known syscalls)
    """
```

### All-Syscall Handlers

```python
def all_handler(regs, proto, syscall):
    """
    For on_all_sys_* handlers, arguments are not unpacked
    Access via syscall.args array instead
    """
```

## SyscallEvent Object

The `syscall` parameter provides access to runtime information:

```python
def my_handler(regs, proto, syscall, *args):
    # Basic information
    print(f"Syscall: {syscall.name}")
    print(f"Process: {syscall.task.comm}")
    print(f"PC: {syscall.pc:#x}")
    
    # Arguments (raw values)
    for i in range(syscall.argc):
        print(f"arg[{i}]: {syscall.args[i]:#x}")
    
    # Return value (for return handlers)
    print(f"Return value: {syscall.retval}")
    
    # Modify behavior
    syscall.skip_syscall = True    # Skip syscall execution
    syscall.retval = 42           # Set return value
```

## SyscallPrototype Object

The `proto` parameter contains syscall metadata:

```python
def my_handler(regs, proto, syscall, *args):
    print(f"Syscall name: {proto.name}")
    print(f"Argument count: {proto.nargs}")
    
    # Argument metadata
    for i in range(proto.nargs):
        print(f"arg[{i}]: {proto.types[i]} {proto.names[i]}")
```

## Practical Examples

### Process Monitoring

```python
@syscalls.syscall("on_sys_execve_enter")
def track_process_creation(regs, proto, syscall, filename, argv, envp):
    """Monitor process creation"""
    args = []
    try:
        # Read string arguments from guest memory
        filename_str = yield from plugins.mem.read_str(filename)
        args_list = yield from plugins.mem.read_ptrlist(argv)
        
        print(f"New process: {filename_str}")
        print(f"Arguments: {args_list}")
        
        # Log to file or database
        with open("process_log.txt", "a") as f:
            f.write(f"{filename_str} {' '.join(args_list)}\n")
            
    except Exception as e:
        print(f"Error reading process arguments: {e}")
```

### File Access Monitoring

```python
@syscalls.syscall("on_sys_openat_enter")
def monitor_file_access(regs, proto, syscall, dirfd, pathname, flags, mode):
    """Monitor file access attempts"""
    try:
        path_str = yield from plugins.mem.read_str(pathname)
        
        # Check for sensitive files
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/ssh/"]
        if any(sens in path_str for sens in sensitive_files):
            print(f"ALERT: Access to sensitive file: {path_str}")
            
            # Optionally block the access
            if "/etc/shadow" in path_str:
                syscall.skip_syscall = True
                syscall.retval = -13  # EACCES
                
    except Exception as e:
        print(f"Error reading pathname: {e}")
```

### Network Monitoring

```python
@syscalls.syscall("on_sys_sendto_enter", comm_filter="target_app")
def monitor_network_send(regs, proto, syscall, sockfd, buf, length, flags, dest_addr, addrlen):
    """Monitor network sends from specific application"""
    try:
        # Read the data being sent
        data = yield from plugins.mem.read_bytes(buf, min(length, 100))  # First 100 bytes
        
        print(f"Network send: {len(data)} bytes")
        print(f"Data preview: {data[:50]}")
        
        # Check for suspicious patterns
        if b"password" in data.lower():
            print("WARNING: Potential password transmission detected")
            
    except Exception as e:
        print(f"Error reading network data: {e}")
```

### Return Value Analysis

```python
@syscalls.syscall("on_sys_open_return", retval_filter=ValueFilter.error())
def track_failed_opens(regs, proto, syscall):
    """Track failed file open attempts"""
    # Get the original arguments from saved state
    filename = syscall.args[0]  # pathname argument
    
    try:
        path_str = yield from plugins.mem.read_str(filename)
        error_code = -syscall.retval
        
        print(f"Failed to open: {path_str} (error: {error_code})")
        
        # Log failed access attempts
        with open("failed_access.log", "a") as f:
            f.write(f"{path_str} {error_code}\n")
            
    except Exception as e:
        print(f"Error processing failed open: {e}")
```

### Complex Filtering Example

```python
@syscalls.syscall(
    "sys_ioctl",
    comm_filter="target_driver",
    arg_filters=[
        None,                                    # fd: any
        ValueFilter.range(0x1000, 0x2000),     # cmd: in range
        ValueFilter.bitmask_set(0x0001)         # arg: has specific bit set
    ],
    retval_filter=ValueFilter.success()
)
def monitor_specific_ioctls(regs, proto, syscall, fd, cmd, arg):
    """Monitor specific ioctl patterns"""
    print(f"Targeted ioctl: fd={fd}, cmd={cmd:#x}, arg={arg:#x}")
```

## Performance Considerations

### Hook Granularity

- **Specific syscalls**: Lowest overhead, only hook what you need
- **Process filtering**: Reduces events but still processes all syscalls
- **All syscalls**: Highest overhead, use sparingly

```python
# Good: Specific and filtered
@syscalls.syscall("sys_write", comm_filter="target_app")

# Moderate: Broader but still filtered
@syscalls.syscall("on_all_sys_enter", comm_filter="target_app")

# Heavy: No filtering
@syscalls.syscall("on_all_sys_enter")
```

### Memory Access

Reading guest memory is expensive. Cache results when possible:

```python
# Cache frequently accessed strings
_path_cache = {}

def cached_read_string(addr):
    if addr in _path_cache:
        return _path_cache[addr]
    
    path = yield from plugins.mem.read_str(addr)
    _path_cache[addr] = path
    return path
```

### Filtering Efficiency

Use the most restrictive filters first:

```python
# Good: Process filter eliminates most events early
@syscalls.syscall("sys_write", comm_filter="target", retval_filter=ValueFilter.success())

# Less efficient: Complex argument filters on all processes
@syscalls.syscall("sys_write", arg_filters=[None, None, ValueFilter.greater(1000)])
```

## Error Handling

### Memory Access Failures

Always handle memory read failures gracefully:

```python
def safe_handler(regs, proto, syscall, pathname):
    try:
        path_str = yield from plugins.mem.read_str(pathname)
        # Process path_str
    except Exception as e:
        # Log error but don't crash
        print(f"Failed to read pathname: {e}")
        return
```

### Portal Communication

The portal system handles most communication errors, but be aware of timeouts:

```python
def robust_handler(regs, proto, syscall, buf, length):
    if length > 1024 * 1024:  # 1MB
        print("Buffer too large, skipping read")
        return
    
    try:
        data = yield from plugins.mem.read_bytes(buf, length)
        # Process data
    except Exception as e:
        print(f"Memory read failed: {e}")
```

## Hook Management

### Dynamic Control

Enable/disable hooks at runtime:

```python
# Disable a hook
yield from syscalls.disable_syscall(my_handler_function)

# Re-enable it
yield from syscalls.enable_syscall(my_handler_function)

# Or by function name
yield from syscalls.disable_syscall("my_handler_function")
```

### Hook Information

Access hook configuration:

```python
# Get syscall prototype information
proto = syscalls.get_syscall_info_by_name("sys_open")
if proto:
    print(f"Syscall: {proto.name}")
    for i in range(proto.nargs):
        print(f"  {proto.types[i]} {proto.names[i]}")
```

## Integration with Other Plugins

### With Portal Plugin

The syscalls plugin integrates seamlessly with the portal system:

```python
def combined_handler(pt_regs, proto, syscall, fd):
    # Use portal for additional context
    proc = yield from plugins.portal.get_proc()
    mappings = yield from plugins.portal.get_mappings()
    
    print(f"Syscall by PID {proc.pid}: {proto.name}")
```

### With OSI Plugin

Combine with OS introspection:

```python
def osi_enhanced_handler(pt_regs, proto, syscall, *args):
    # Get process information
    current_proc = yield from plugins.OSI.get_proc()
    if current_proc:
        print(f"Process: {current_proc.name} (PID: {current_proc.pid})")
```

## Testing

The system includes comprehensive tests demonstrating usage patterns:

```python
# From syscall_test.py
@syscalls.syscall("on_sys_ioctl_enter", 
                  comm_filter="send_syscall",
                  arg_filters=[None, 0xabcd])
def test_skip_retval(pt_regs, proto, syscall, fd, op, arg):
    """Test syscall skipping and return value modification"""
    assert fd == 9, f"Expected fd 9, got {fd:#x}"
    assert op == 0xabcd, f"Expected op 0xabcd, got {op:#x}"
    
    # Skip the syscall and set custom return value
    syscall.skip_syscall = True
    syscall.retval = 43
```

## Troubleshooting

### Common Issues

1. **Hook not triggering**: Check syscall name normalization
   ```python
   # These are equivalent:
   "sys_openat"
   "openat"
   "_sys_openat"
   ```

2. **Argument mismatch**: Verify syscall prototype
   ```python
   proto = syscalls.get_syscall_info_by_name("openat")
   print(f"Expected args: {proto.nargs}")
   ```

3. **Memory read failures**: Handle invalid pointers
   ```python
   if addr and addr != 0:
       try:
           data = yield from plugins.mem.read_str(addr)
       except:
           print("Invalid memory address")
   ```

### Debugging

Enable debug logging:

```python
import logging
logging.getLogger("syscalls").setLevel(logging.DEBUG)
```

Use the syscall event information for debugging:

```python
def debug_handler(regs, proto, syscall, *args):
    print(f"Syscall: {proto.name}")
    print(f"Args: {[hex(arg) for arg in syscall.args[:syscall.argc]]}")
    print(f"Process: {syscall.task.comm}")
    print(f"PC: {syscall.pc:#x}")
```

## Best Practices

1. **Filter early and often**: Use the most specific filters possible
2. **Handle errors gracefully**: Always expect memory access to fail
3. **Cache expensive operations**: Don't re-read the same memory
4. **Use appropriate hook points**: Entry for argument analysis, return for result analysis
5. **Test thoroughly**: Use the provided test framework to verify behavior
6. **Monitor performance**: Syscall hooks can impact guest performance significantly

The syscalls system provides a powerful foundation for dynamic analysis, security monitoring, and program understanding in virtualized environments.
