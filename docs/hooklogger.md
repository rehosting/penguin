# HookLogger: format-string instrumentation

HookLogger is the "easy mode" for dynamic binary instrumentation. You describe
what to capture with a printf-style **action string** and it builds the uprobe or
syscall hook for you — handling the parts that are tedious and
architecture-specific:

- per-arch argument retrieval (calling conventions),
- memory dereferencing (strings, pointers, buffers),
- endianness conversion (detected automatically),
- pairing entry and exit probes so a hook can report a return value.

## The action string

```text
[bp|break] [print] func_name(arg_fmt, ...) [= ret_fmt, ...]
```

- `func_name` — the function or syscall to hook (`malloc`, `sys_read`).
- `(...)` — formats for the arguments, captured at **entry**.
- `= ...` — optional; formats for the return value(s), captured at **exit**.
- `bp` / `break` — drop into a Python debugger (PDB) when the hook fires.

### Format specifiers

| Specifier | Meaning | Source |
|---|---|---|
| `%d` / `%i` | signed integer | register/stack value |
| `%u` | unsigned integer | register/stack value |
| `%x` / `%X` | hexadecimal | register/stack value |
| `%p` | pointer (`0x...`) | register/stack value |
| `%s` | string (`char *`) | dereferenced at entry, read to the NUL |
| `%c` | character | low 8 bits |
| `%b` | boolean | True/False |
| `%fd` | file descriptor | resolved to a filename via OSI |
| `%proc` | process name | current process, via OSI |
| `%x64`, `%u32`, … | memory dump | reads that bit width (8/16/32/64) from the pointer |

### Deferred resolution: `:out`

Pointer formats such as `%s` are dereferenced at function *entry*. For output
parameters — a buffer the callee fills in — you want the pointer captured at
entry but the memory read at exit. Append `:out` to defer it:

- `%s:out` — capture the `char *` at entry, read the string at exit.
- `%x64:out` — capture the pointer at entry, read 64 bits at exit.

So to see the data a `read()` actually returned:

```text
sys_read(%fd, %s:out, %d) = %d
```

## Filters and output

Every registration takes the same optional scoping arguments:

| Argument | CLI flag | Effect |
|---|---|---|
| `pid_filter` | `--pid` | only fire for this PID |
| `process_filter` | `--proc` | only fire for this process name |
| `logfile` | `--output` | append to this file in the results directory; otherwise the hook logs through penguin's logger |

## Driving it from the command line

The `breakpoint` CLI talks to a running guest over the RemoteCtrl plugin's Unix
socket (`results/latest/remotectrl.sock` by default, overridable with `--sock`).
RemoteCtrl loads HookLogger itself if it is not already loaded.

```bash
# trace every strlen argument in libc
breakpoint uprobe --path /lib/libc.so.6 --symbol strlen --action "print %s"

# what did this read() actually return?
breakpoint syscall --name sys_read --action "print %fd, %s:out, %d = %d"

# scope to one process, log to a file in the results dir
breakpoint uprobe --path /bin/mybin --symbol do_work \
    --action "print %x, %d" --proc mybin --output work.log

breakpoint list             # what is registered
breakpoint disable 3        # remove one hook by id
```

## Driving it from Python

From a pyplugin, or any code with the plugin manager in scope:

```python
plugins.load_plugin('hooklogger')

hook_id = plugins.hooklogger.register_uprobe(
    path="/usr/bin/wget",
    symbol="connect",
    action_str="print(%fd, %p) = %d",
    process_filter="wget",
    logfile="connections.log",
)

plugins.hooklogger.register_syscall(
    "sys_read", "print %fd, %s:out, %d = %d", logfile="reads.log",
)

plugins.hooklogger.list_hooks()        # [{'id': .., 'type': .., 'action': ..}]
plugins.hooklogger.disable_hook(hook_id)
plugins.hooklogger.disable_all()
```

## See also

- [uprobes.md](uprobes.md) and [syscalls.md](syscalls.md) — the lower-level
  interfaces HookLogger is built on, for when you need a real callback rather
  than a format string.
- [plugins.md](plugins.md) — the plugin catalogue, including RemoteCtrl.
