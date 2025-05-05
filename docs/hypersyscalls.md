# Hypersyscalls 

## What are Hypersyscalls?

**Hypersyscalls** are a tool for monitoring and modifying system calls in the guest OS using a cooperative, hypercall-based protocol. Unlike traditional syscall introspection (e.g., the `syscalls2` plugin), hypersyscalls require the guest to explicitly notify the hypervisor about syscall events via hypercalls. This approach is robust to kernel changes and works across different OS versions without modification.

## How Hypersyscalls Work

1. **Guest Instrumentation:** The guest OS (or a kernel module) is modified to:
   - Register syscall definitions with the hypervisor using a special hypercall.
   - Notify the hypervisor at syscall entry and exit points via hypercalls, passing syscall numbers, arguments, and return values.

2. **Host/Plugin Handling:** The `hypersyscalls` plugin in PANDA receives these notifications and exposes a flexible callback API for Python plugins to monitor or modify syscall behavior.

3. **Callback API:** Plugins can register Python functions to be called on syscall entry, return, all syscalls, or unknown syscalls using the `hsyscall` or `hypersyscall` decorators.

## Example: Using Hypersyscalls in a Python Plugin

```python
from pandare2 import PyPlugin

class MySyscallLogger(PyPlugin):
    def __init__(self, panda):
        # Log every syscall entry
        @panda.hsyscall("on_all_sys_enter")
        def log_syscall_entry(cpu, proto, syscall, hook):
            print(f"Syscall entry: {proto.name}({[syscall.args[i] for i in range(proto.nargs)]})")

        # Log every syscall return
        @panda.hsyscall("on_all_sys_return")
        def log_syscall_return(cpu, proto, syscall, hook):
            print(f"Syscall return: {proto.name} -> {syscall.retval}")
```

You can also hook specific syscalls:

```python
@panda.hsyscall("on_sys_open_enter")
def on_open(cpu, proto, syscall, hook, *args):
    print(f"open called with args: {args}")
```

Or unknown syscalls:

```python
@panda.hsyscall("on_unknown_sys_enter")
def on_unknown(cpu, proto, syscall, hook):
    print(f"Unknown syscall {syscall.nr}")
```

---

## API: Modifying Arguments, Skipping, and Changing Return Values

The `syscall` object passed to your callback provides a rich API for introspection and modification:

### Changing Arguments

You can modify syscall arguments by assigning to `syscall.args` or by using the named arguments in the callback (if present):

```python
@panda.hsyscall("on_sys_open_enter")
def force_open_readonly(cpu, proto, syscall, hook, filename, flags, mode):
    # Force all open() calls to be read-only
    syscall.args[1] = 0  # flags = O_RDONLY
    print(f"Modified open flags to O_RDONLY for {filename}")
```

Or, equivalently:

```python
@panda.hsyscall("on_sys_open_enter")
def force_open_readonly(cpu, proto, syscall, hook, *args):
    syscall.args[1] = 0  # flags = O_RDONLY
```

### Skipping a Syscall

You can skip the actual execution of a syscall and return a value directly by setting `syscall.skip_syscall = True` and assigning to `syscall.retval`:

```python
@panda.hsyscall("on_sys_unlink_enter")
def block_unlink(cpu, proto, syscall, hook, *args):
    # Prevent file deletion
    syscall.skip_syscall = True
    syscall.retval = -1  # Return error code (e.g., -EPERM)
    print("Blocked unlink syscall!")
```

### Changing the Return Value

You can override the return value of a syscall on return:

```python
@panda.hsyscall("on_sys_getpid_return")
def fake_getpid(cpu, proto, syscall, hook, *args):
    syscall.retval = 1234  # Override the return value
```

Or, for more advanced use, you can combine argument modification, skipping, and return value changes:

```python
@panda.hsyscall("on_sys_write_enter")
def intercept_write(cpu, proto, syscall, hook, fd, buf, count):
    # Example: block writes to fd 2 (stderr)
    if fd == 2:
        syscall.skip_syscall = True
        syscall.retval = count  # Pretend we wrote all bytes
        print("Suppressed write to stderr")
    else:
        # Optionally, modify the buffer pointer or count
        syscall.args[2] = min(count, 10)  # Only allow up to 10 bytes to be written
```

---

## More Examples

### Logging All Arguments and Return Values

```python
@panda.hsyscall("on_all_sys_return")
def log_all_returns(cpu, proto, syscall, hook):
    print(f"{proto.name}({', '.join(str(a) for a in syscall.args)}) = {syscall.retval}")
```

### Hooking Unknown Syscalls

```python
@panda.hsyscall("on_unknown_sys_enter")
def unknown_syscall(cpu, proto, syscall, hook):
    print(f"Unknown syscall {syscall.nr} with args: {syscall.args}")
    # Optionally, skip or modify as above
```

---

## Differences from `syscalls2`

| Feature                | `hypersyscalls`                | `syscalls2`                |
|------------------------|--------------------------------|----------------------------|
| **Guest requirements** | Guest must be instrumented to notify the hypervisor via hypercalls (kernel patch/module) | No guest changes needed; works via introspection |
| **Callback API**       | Python: `hsyscall`/`hypersyscall` decorators; can hook entry, return, all, unknown, or specific syscalls | C: Register C callbacks for each syscall or use generic hooks |
| **Syscall info**       | Guest provides syscall table and argument types at runtime | PANDA uses built-in syscall tables for known OSes |
| **Robustness**         | Works across kernel versions and custom kernels (as long as guest is instrumented) | May break if kernel changes or symbols are missing |
| **Modification**       | Can modify syscall arguments, skip syscalls, and change return values via the `syscall` object | Can also modify, but may be less reliable due to introspection limitations |
| **Performance**        | Slight overhead due to guest-hypervisor communication | Lower overhead, but less robust |
| **Use case**           | Best for research, fuzzing, or analysis where guest can be modified | Best for quick analysis of standard OSes without guest changes |

---

---

## References

- See [`pyplugins/analysis/syscalls.py`](../pyplugins/analysis/syscalls.py) for usage examples.
- See [`pyplugins/interventions/lifeguard.py`](../pyplugins/interventions/lifeguard.py) for a plugin that blocks signals using hypersyscalls.
- See [`panda-ng/plugins/hypersyscalls/README.md`](../panda-ng/plugins/hypersyscalls/README.md) for C API details.

