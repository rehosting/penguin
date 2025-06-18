# Uprobes Plugin System

The Uprobes plugin provides a flexible interface for monitoring, filtering, and intercepting user-space function calls in guest processes via the IGLOO hypervisor and portal interface. This enables dynamic tracing, security monitoring, and program analysis at the function level in user applications and libraries.

## Overview

The uprobes system operates through a multi-layer architecture:

1. **Kernel Layer**: IGLOO kernel module registers uprobes at specified file offsets or symbols, with process and PID filtering.
2. **Hypervisor Layer**: Portal system manages communication between guest and host, relaying probe events.
3. **Plugin Layer**: Python plugins register uprobes and process events via callback functions.

## Quick Start

```python
from penguin import plugins, Plugin

class MyUprobeMonitor(Plugin):
    def __init__(self):
        # Register a uprobe on 'main' in /usr/bin/myapp for all processes named 'target'
        @plugins.uprobes.uprobe("/usr/bin/myapp", "main", process_filter="target")
        def on_main_entry(pt_regs):
            print(f"main() called! PC={pt_regs.pc:#x}")

        # Register a return probe on a library function
        @plugins.uprobes.uretprobe("/usr/lib/libfoo.so", "foo_func", process_filter="target")
        def on_foo_func_return(pt_regs):
            print(f"foo_func returned! Return value: {pt_regs.retval}")
```

## Core Concepts

### Uprobe Events

A uprobe event is generated when a monitored function is entered or returned from. Each event provides access to the CPU register state (`pt_regs`) at the probe point.

### Probe Registration

Probes are registered using the `@uprobes.uprobe()` or `@uprobes.uretprobe()` decorators, supporting flexible filtering and symbol/offset selection.

```python
@uprobes.uprobe(
    path="/usr/lib/libfoo.so",
    symbol="foo_func",
    process_filter="target_app",
    on_enter=True,
    on_return=False,
    pid_filter=1234
)
def my_handler(pt_regs):
    # Handler code here
    pass
```

## API Reference

### Decorator Parameters

#### `path` (str or None)
Path to the executable or library file. Supports wildcards (`*`). If `None`, will search all known libraries for the symbol.

#### `symbol` (str or int)
Function name (string) or file offset (integer) at which to place the probe.

#### `process_filter` (Optional[str])
Filter by process name (comm):

```python
@uprobes.uprobe("/usr/bin/myapp", "main", process_filter="target")
def monitor_main(pt_regs):
    pass
```

#### `pid_filter` (Optional[int])
Filter by specific process ID:

```python
@uprobes.uprobe("/usr/bin/myapp", "main", pid_filter=1234)
def monitor_pid(pt_regs):
    pass
```

#### `on_enter` / `on_return` (bool)
Control when the probe triggers:

```python
# Entry only (default)
@uprobes.uprobe("/usr/bin/myapp", "main", on_enter=True)

# Return only
@uprobes.uretprobe("/usr/bin/myapp", "main", on_return=True)

# Both entry and return
@uprobes.uprobe("/usr/bin/myapp", "main", on_enter=True, on_return=True)
```

#### `fail_register_ok` (bool)
If True, do not raise an error if the symbol is not found.

### Handler Function Signature

```python
def handler(pt_regs):
    """
    pt_regs: Register state at probe point (see below)
    """
```

## pt_regs Object

The `pt_regs` parameter provides access to the CPU register state at the probe point:

```python
def my_handler(pt_regs):
    print(f"PC: {pt_regs.pc:#x}")
    print(f"SP: {pt_regs.sp:#x}")
    print(f"Return value: {pt_regs.retval}")  # On return probes
    # Access general-purpose registers as needed
```

## Practical Examples

### Monitor Function Entry

```python
@uprobes.uprobe("/usr/bin/myapp", "main")
def on_main_entry(pt_regs):
    print(f"main() called at PC={pt_regs.pc:#x}")
```

### Monitor Function Return

```python
@uprobes.uretprobe("/usr/lib/libfoo.so", "foo_func")
def on_foo_func_return(pt_regs):
    print(f"foo_func returned, retval={pt_regs.retval}")
```

### Wildcard Library Matching

```python
@uprobes.uprobe("libssl*", "SSL_read")
def monitor_ssl_read(pt_regs):
    print("SSL_read called!")
```

### Register on All Libraries Containing a Symbol

```python
@uprobes.uprobe(None, "malloc")
def monitor_malloc(pt_regs):
    print("malloc called in some library!")
```

### Offset-based Probes

```python
@uprobes.uprobe("/usr/bin/myapp", 0x1234)
def on_offset(pt_regs):
    print("Hit offset 0x1234 in myapp")
```

### Process and PID Filtering

```python
@uprobes.uprobe("/usr/bin/myapp", "main", process_filter="target", pid_filter=4321)
def filtered_handler(pt_regs):
    print("main() called by target process with PID 4321")
```

## Performance Considerations

- **Specific probes**: Register only the functions you need to minimize overhead.
- **Process/PID filtering**: Reduces the number of events delivered to the host.
- **Wildcard/pathless probes**: May register probes in many libraries; use sparingly.

## Error Handling

- Always check for symbol resolution errors; use `fail_register_ok=True` to ignore missing symbols.
- Handle missing or invalid register state gracefully in handlers.

## Hook Management

### Dynamic Control

Enable/disable probes at runtime:

```python
# Unregister a probe by ID
yield from uprobes.unregister(probe_id)
```

### Probe Information

Access probe configuration:

```python
probe_id = plugins.uprobes._func_to_probe_id[my_handler]
info = plugins.uprobes.probe_info[probe_id]
print(f"Probe at {info['path']}:{info['offset']}")
```

## Integration with Other Plugins

### With Portal Plugin

Uprobes are managed via the portal system and can be combined with other portal-based plugins for richer context.

### With OSI Plugin

Combine with OS introspection for process metadata:

```python
def handler(pt_regs):
    proc = yield from plugins.OSI.get_proc()
    print(f"Probe hit in process {proc.name} (PID {proc.pid})")
```

## Testing

The system supports automated tests for probe registration, event delivery, and filtering.

```python
@uprobes.uprobe("/usr/bin/testprog", "main", process_filter="testproc")
def test_probe(pt_regs):
    assert pt_regs.pc != 0
```

## Troubleshooting

### Common Issues

1. **Probe not triggering**: Check path and symbol normalization, process filters, and PID filters.
2. **Symbol not found**: Ensure the symbols database is present and up to date.
3. **Multiple matches**: Wildcard or pathless probes may register in multiple libraries.

### Debugging

Enable debug logging:

```python
import logging
logging.getLogger("uprobes").setLevel(logging.DEBUG)
```

Print probe event details:

```python
def debug_handler(pt_regs):
    print(f"PC: {pt_regs.pc:#x}, Registers: {pt_regs.regs}")
```

## Best Practices

1. **Be specific**: Register probes only where needed.
2. **Filter early**: Use process and PID filters to reduce event volume.
3. **Handle errors**: Always expect symbol resolution or memory access to fail.
4. **Cache expensive lookups**: If reading memory or symbols, cache results.
5. **Test thoroughly**: Use the test framework to verify probe behavior.
6. **Monitor performance**: Excessive probes can impact guest performance.

The uprobes system provides a powerful foundation for dynamic user-space analysis, security monitoring, and program understanding in virtualized environments.
