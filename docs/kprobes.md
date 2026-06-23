# Kprobes Plugin System

The Kprobes plugin provides a flexible interface for monitoring, filtering, and intercepting kernel-space function calls in the guest via the IGLOO hypervisor and portal interface. This enables dynamic kernel tracing, security monitoring, and program analysis at the function level inside the guest kernel.

## Overview

The kprobes system operates through a multi-layer architecture:

1. **Kernel Layer**: The IGLOO kernel module registers kprobes on kernel functions identified by symbol name. The guest kernel resolves the symbol via `kallsyms`, applies an optional byte offset, and supports process and PID filtering.
2. **Hypervisor Layer**: The portal system manages communication between guest and host, relaying probe events.
3. **Plugin Layer**: Python plugins register kprobes and process events via callback functions.

Unlike uprobes, which hook user-space code by file path and offset, kprobes hook **kernel** functions by symbol name. There is no path or address resolution on the host side; the symbol string is sent to the guest kernel, which resolves it.

## Quick Start

```python
from penguin import plugins, Plugin

class MyKprobeMonitor(Plugin):
    def __init__(self):
        # Register a kprobe on the kernel function 'do_filp_open'
        @plugins.kprobes.kprobe(symbol="do_filp_open")
        def on_open_entry(pt_regs):
            print(f"do_filp_open() called! PC={pt_regs.pc:#x}")

        # Register a return probe on a kernel function
        @plugins.kprobes.kretprobe(symbol="do_filp_open")
        def on_open_return(pt_regs):
            print(f"do_filp_open returned! Return value: {pt_regs.retval}")
```

## Core Concepts

### Kprobe Events

A kprobe event is generated when a monitored kernel function is entered or returned from. Each event provides access to the CPU register state (`pt_regs`) at the probe point.

### Probe Registration

Probes are registered using the `@kprobes.kprobe()` or `@kprobes.kretprobe()` decorators, supporting symbol-based selection, an optional byte offset, and process / PID filtering.

```python
@kprobes.kprobe(
    symbol="do_filp_open",
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

#### `symbol` (str)

Kernel symbol name to probe. The guest kernel resolves it via `kallsyms`. Some kernel functions carry compiler-generated suffixes (e.g. `do_execveat_common.isra.0`); register on the concrete name. You can discover the real name with:

```python
for name in plugins.kffi.ffi.search_symbols("do_execveat_common*"):
    ...
```

#### `offset` (int)

Byte offset from the symbol at which to place the probe (default `0`). Return probes (`kretprobe`) force `offset=0`.

> **MIPS caveat — use `offset=0` (function entry).** MIPS has no hardware
> single-step, so the kernel single-steps a probed instruction *out of line*
> (it copies the instruction to a scratch slot, executes it there, then
> resumes). For instructions in the middle of a function this can resume with
> corrupted CPU state and crash the probed thread. In testing, an entry probe
> (`offset=0`) and `kretprobe` on a function are rock-solid on all MIPS
> variants, but a non-zero offset into some functions (e.g. `vfs_read+4`)
> reliably Oopses the guest kernel (`get_signal` NULL-deref → SIGSEGV → panic),
> while the identical probe on ARM/x86 runs fine. This is an inherent MIPS
> kprobe (single-step-out-of-line) limitation, not specific to Penguin. Prefer
> entry probes / kretprobes on MIPS; treat non-zero offsets as unsupported
> there.

#### `process_filter` (Optional[str])

Filter by process name (comm):

```python
@kprobes.kprobe(symbol="do_filp_open", process_filter="target")
def monitor_open(pt_regs):
    pass
```

#### `pid_filter` (Optional[int])

Filter by specific process ID:

```python
@kprobes.kprobe(symbol="do_filp_open", pid_filter=1234)
def monitor_pid(pt_regs):
    pass
```

#### `on_enter` / `on_return` (bool)

Control when the probe triggers:

```python
# Entry only (default)
@kprobes.kprobe(symbol="do_filp_open", on_enter=True)

# Return only
@kprobes.kretprobe(symbol="do_filp_open")

# Both entry and return
@kprobes.kprobe(symbol="do_filp_open", on_enter=True, on_return=True)
```

When a probe is registered for both entry and return, the handler is invoked twice. Use the injected `is_enter` argument (see below) to distinguish the two.

#### `read_only` (bool)

If True, modifications to `pt_regs` made in the handler are not written back to the guest.

#### `fail_register_ok` (bool)

If True, do not raise an error if registration fails.

### Handler Function Signature

The handler always receives `pt_regs` as its first argument. Additional context can be requested using "signature sugar": declaring extra positional or keyword parameters injects context values.

```python
def handler(pt_regs):
    """pt_regs: register state at the probe point."""

def handler(pt_regs, is_enter):
    """is_enter: True on function entry, False on return."""

def handler(pt_regs, is_enter, tgid_pid):
    """tgid_pid: (tgid << 32) | tid for the triggering task."""

def handler(pt_regs, **ctx):
    """ctx contains is_enter and tgid_pid."""
```

The injection rules:

- 1 extra positional arg -> `is_enter`
- 2 extra positional args -> `is_enter`, `tgid_pid`
- Parameters explicitly named `is_enter` / `tgid_pid` are bound by name.
- A `**kwargs` parameter receives `is_enter` and `tgid_pid`.

Handlers may be plain functions or generators (`yield from`) so they can perform portal memory reads.

## pt_regs Object

The `pt_regs` parameter provides architecture-agnostic access to the CPU register state at the probe point:

```python
def my_handler(pt_regs):
    print(f"PC: {pt_regs.pc:#x}")
    print(f"SP: {pt_regs.sp:#x}")
    print(f"Return value: {pt_regs.get_return_value()}")  # On return probes
    a, b = pt_regs.get_args(2)                              # First two args
```

Note that kernel functions follow the kernel calling convention; `get_args` returns register-passed arguments for the architecture.

## Practical Examples

### Inspect a kernel path open

```python
@kprobes.kprobe(symbol="do_filp_open")
def on_open(pt_regs):
    args = pt_regs.get_args(5)
    struct_filename = yield from plugins.kffi.read_type(args[1], "struct filename")
    path = yield from plugins.mem.read_str(struct_filename.name.address)
    print(f"opening {path}")
```

### Check a kernel return value

```python
@kprobes.kprobe(symbol="do_filp_open", on_enter=False, on_return=True)
def on_open_return(pt_regs):
    retval = int(plugins.kprobes.panda.ffi.cast("target_long", pt_regs.get_return_value()))
    if retval == -2:  # -ENOENT
        print("open failed: no such file")
    if False:
        yield
```

### Probe a symbol with a suffix

```python
for name in plugins.kffi.ffi.search_symbols("do_execveat_common*"):
    plugins.kprobes.kprobe(symbol=name)(on_exec)
    break
```

## Hook Management

### Unregistering

Probes can be unregistered by handle (the decorator return value), by function, or by name:

```python
handle = kprobes.kprobe(symbol="do_filp_open")(on_open)
...
kprobes.unregister(handle)          # by handle
kprobes.unregister(on_open)         # by function
kprobes.unregister("on_open")       # by name
```

## Integration with Other Plugins

### With KFFI

Use `plugins.kffi.read_type` / `read_type_panda` to decode kernel structs referenced by probe arguments, and `plugins.kffi.ffi.search_symbols` to resolve symbol names.

### With OSI

Combine with OS introspection for process metadata:

```python
def handler(pt_regs):
    proc = yield from plugins.osi.get_proc()
    print(f"kprobe hit in process {proc.name} (PID {proc.pid})")
```

## Best Practices

1. **Be specific**: Probe only the kernel functions you need to minimize overhead.
2. **Filter early**: Use process and PID filters to reduce event volume.
3. **Mind symbol suffixes**: Inlined/cloned kernel functions may carry `.isra.N`, `.constprop.N`, etc. — resolve the concrete name.
4. **Handle errors**: Memory reads and symbol resolution can fail; guard accordingly.
5. **Use `is_enter`**: For combined entry+return probes, branch on `is_enter`.

The kprobes system provides a powerful foundation for dynamic kernel analysis, security monitoring, and program understanding in virtualized environments.
