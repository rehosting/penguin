"""
# Syscalls Logger Plugin

This plugin records system call events to the penguin database. It parses Linux error codes from header files,
maps error numbers to names and explanations, and logs detailed syscall information including arguments,
return values, and process context.

## Purpose

- Monitors all system call return events and execve/execveat entries in the guest.
- Records syscall arguments, return values, and error codes with explanations.
- Enables later analysis of system call activity and process behavior.

## Usage

```python
from pyplugins.loggers.syscalls_logger import PyPandaSysLog

syscalls_logger = PyPandaSysLog(panda)
# Syscall events will be logged automatically.
```

This plugin is loaded automatically as part of the penguin plugin system. It requires the `syscalls`, `mem`,
`portal`, and `osi` plugins to be active.

The plugin extracts relevant fields and stores them in the database using the `Syscall` event type.

## Arguments

- `outdir`: Output directory for the SQLite database file.
- `procs`: Optional list of process names to filter syscall logging. If not provided, all processes are logged.

"""

import re
from os.path import join
from events.types import Syscall
from penguin import plugins, Plugin
import functools

"""
This code acquires the error numbers from linux to map in the syscall plugin
"""
# read some errno.h to get the error codes and names
errcode_to_errname = {}
errcode_to_explanation = {}

errno_resources = join(plugins.resources, "errno")

with open(join(errno_resources, "errno-base.h")) as f:
    errno_base = f.read()

with open(join(errno_resources, "generic.h")) as f:
    errno = errno_base + "\n" + f.read()

with open(join(errno_resources, "mips.h")) as f:
    errno_mips = errno_base + "\n" + f.read()

matches = re.findall(
    r"#define\s*(?P<errname>E[A-Z0-9]*)\s*(?P<errcode>\d*)\s*/\*(?P<explanation>.*)\*/",
    errno,
    re.MULTILINE,
)
for match in matches:
    errname, errcode, explanation = match
    errcode_to_errname[int(errcode)] = errname.strip()
    errcode_to_explanation[int(errcode)] = explanation.strip()

errcode_to_errname_mips = {}
errcode_to_explanation_mips = {}

matches = re.findall(
    r"#define\s*(?P<errname>E[A-Z0-9]*)\s*(?P<errcode>\d*)\s*/\*(?P<explanation>.*)\*/",
    errno_mips,
    re.MULTILINE,
)
for match in matches:
    errname, errcode, explanation = match
    errcode_to_errname_mips[int(errcode)] = errname.strip()
    errcode_to_explanation_mips[int(errcode)] = explanation.strip()

"""
This is our internal representation of a syscall event
"""

syscalls = plugins.syscalls


class PyPandaSysLog(Plugin):
    """
    Plugin for logging system call events to the database.

    Hooks into system call return and execve/execveat entry events and records them as `Syscall` events.
    """

    def __init__(self, panda) -> None:
        """
        Initialize the PyPandaSysLog plugin.

        - Sets up the output directory and database reference.
        - Loads error code mappings for the current architecture.
        - Registers hooks for syscall return and execve/execveat entry events, optionally filtered by process.

        **Parameters:**
        - `panda`: The PANDA instance.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        self.saved_syscall_info = {}
        self.DB = plugins.DB

        procs = self.get_arg("procs")

        if panda.arch_name in ["mips", "mipsel"]:
            self.errcode_to_errname = errcode_to_errname_mips
            self.errcode_to_explanation = errcode_to_explanation_mips
        else:
            self.errcode_to_errname = errcode_to_errname
            self.errcode_to_explanation = errcode_to_explanation

        # These syscalls won't necessarily return so we log them on enter
        monitor_enter_syscalls = [
            'execve',
            'execveat',
            'exit',
            'exit_group',
            'vfork',
            'reboot',
            'sigreturn',
            'setcontext',
        ]

        if procs:
            for proc in procs:
                syscalls.syscall("on_all_sys_return", comm_filter=proc)(
                    self.all_sys_ret)
                for syscall_name in monitor_enter_syscalls:
                    syscalls.syscall(f"on_sys_{syscall_name}_enter", comm_filter=proc)(
                        self.sys_record_enter)
        else:
            syscalls.syscall("on_all_sys_return")(self.all_sys_ret)
            for syscall_name in monitor_enter_syscalls:
                syscalls.syscall(f"on_sys_{syscall_name}_enter")(self.sys_record_enter)

    def sys_record_enter(self, regs, proto, syscall, *args) -> None:
        """
        Callback for handling execve/execveat syscall entry events.

        **Parameters:**
        - `regs`: Register/context object.
        - `proto`: Syscall prototype.
        - `syscall`: Syscall object.
        - `*args`: Additional syscall arguments.

        Yields from `handle_syscall` to log the syscall event.

        **Returns:** None
        """
        yield from self.handle_syscall(regs, proto, syscall)

    def all_sys_ret(self, regs, proto, syscall) -> None:
        """
        Callback for handling all syscall return events.

        **Parameters:**
        - `regs`: Register/context object.
        - `proto`: Syscall prototype.
        - `syscall`: Syscall object.

        Yields from `handle_syscall` to log the syscall event, except for execve.

        **Returns:** None
        """
        protoname, _, _ = self.get_syscall_proto(proto, proto.name)
        if "execve" not in protoname:
            yield from self.handle_syscall(regs, proto, syscall)

    def get_arg_repr(self, argval, ctype: str, name: str) -> str:
        """
        Format a syscall argument for logging.

        **Parameters:**
        - `argval`: The argument value.
        - `ctype` (`str`): The C type of the argument.
        - `name` (`str`): The argument name.

        Returns a string representation of the argument, resolving pointers and strings as needed.

        **Returns:** `str`
        """
        if name == "fd":
            fd_name = yield from plugins.osi.get_fd_name(argval)
            return f"{argval:#x}({fd_name or '[???]'})"
        # Convert argval to a proper Python integer
        argval_uint = int(self.panda.ffi.cast("target_ulong", argval))

        # Handle basic integer types
        if ctype in ['int', 'unsigned int', 'pid_t', 'uid_t', 'gid_t', 'key_t', 'mqd_t', '__u32', '__s32', 'u32', 'clockid_t', 'umode_t', 'unsigned', 'qid_t', 'old_uid_t', 'old_gid_t', 'key_serial_t', 'timer_t']:
            # argval_int = int(self.panda.ffi.cast("target_long", argval))
            # return str(argval_int)
            return f"{argval_uint:#x}"

        # Handle larger integer types (displayed as hex)
        elif ctype in ['unsigned long', 'long', 'size_t', 'off_t', 'loff_t', 'aio_context_t']:
            return f"{argval_uint:#x}"

        # Handle string pointers
        elif ctype in ['const char *', 'char *']:
            if argval_uint == 0:
                return "[NULL]"
            val = yield from plugins.mem.read_str(argval)
            return f'{argval_uint:#x}("{val}")'

        # Handle array of strings
        elif ctype == 'const char *const *':
            if argval_uint == 0:
                return "[NULL]"
            result = []
            addr = argval_uint
            max_args = 20  # Limit to avoid infinite loops
            for i in range(max_args):
                ptr = yield from plugins.mem.read_ptr(addr + (i * self.panda.bits // 8))
                if ptr == 0:
                    break
                str_val = yield from plugins.mem.read_str(ptr)
                if str_val == "":
                    break
                result.append(str_val)
            return f"{argval_uint:#x}([{', '.join(repr(s) for s in result)}])"

        # Handle numeric pointer types
        elif ctype in ['int *', 'unsigned int *', 'unsigned long *', 'uid_t *', 'gid_t *', 'old_uid_t *', 'old_gid_t *', 'size_t *', 'off_t *', 'loff_t *', 'u32 *', 'u64 *', 'timer_t *', 'aio_context_t *', 'unsigned *']:
            if argval_uint == 0:
                return "[NULL]"
            return f"{argval_uint:#x}(ptr)"

        # Handle other pointer types (like structs, etc.)
        elif '*' in ctype:
            if argval_uint == 0:
                return "[NULL]"
            # For struct pointers, just return the address and type
            if 'struct' in ctype or 'union' in ctype:
                type_name = ctype.replace('const ', '').replace(' *', '')
                return f"{argval_uint:#x}({type_name})"
            # For void pointers or other generic pointers
            return f"{argval_uint:#x}(ptr)"

        # Handle other types
        elif 'struct' in ctype or 'union' in ctype:
            # Direct struct/union value rather than pointer
            return f"{argval_uint:#x}({ctype} value)"

        # Default fallback for any unhandled types
        return f"{argval_uint:#x}"

    def cstr(self, x) -> str:
        """
        Convert a C string or pointer to a Python string.

        **Parameters:**
        - `x`: The C string or pointer.

        **Returns:** `str`
        """
        if isinstance(x, str):
            return x
        return "" if x == self.panda.ffi.NULL else self.panda.ffi.string(x).decode()

    @functools.lru_cache
    def get_syscall_proto(self, proto, name) -> tuple:
        """
        Retrieve the syscall prototype information.

        **Parameters:**
        - `proto`: The syscall prototype object.
        - `name`: The syscall name.

        Returns a tuple of (protoname, types, names).

        **Returns:** `tuple`
        """
        protoname = self.cstr(proto.name)
        types = [self.cstr(proto.types[i]) for i in range(proto.nargs)]
        names = [self.cstr(proto.names[i]) for i in range(proto.nargs)]
        return protoname, types, names

    def handle_syscall(self, regs, proto, syscall) -> None:
        """
        Handle and log a syscall event.

        **Parameters:**
        - `regs`: Register/context object.
        - `proto`: Syscall prototype.
        - `syscall`: Syscall object.

        Extracts arguments, formats them, determines return value and error code,
        and logs the event to the database.

        **Returns:** None
        """
        protoname, types, names = self.get_syscall_proto(
            proto, proto.name)
        args = [syscall.args[i] for i in range(proto.nargs)]
        args_repr = []
        for i, j in enumerate(types):
            val = yield from self.get_arg_repr(syscall.args[i], j, names[i])
            args_repr.append(f"{names[i]}={val}")

        retval = int(self.panda.ffi.cast("target_long", syscall.retval))
        errnum = -retval
        if errnum in self.errcode_to_errname:
            retno_repr = f"{self.errcode_to_errname[errnum]}({self.errcode_to_explanation[errnum]})"
        else:
            retno_repr = f"{retval:#x}"

        proc_args = yield from plugins.osi.get_args()
        proc = "?" if not proc_args else proc_args[0]

        func_args = {
            "name": protoname,
            "args": args,
            "args_repr": args_repr,
            "retno": retval,
            "retno_repr": retno_repr,
            "procname": proc,
        }
        self.add_syscall(**func_args)

    def add_syscall(
        self,
        name: str,
        procname: str = None,
        retno: int = None,
        args: list = None,
        args_repr: list = None,
        retno_repr: str = None,
    ) -> None:
        """
        Add a syscall event to the database.

        **Parameters:**
        - `name` (`str`): Syscall name.
        - `procname` (`str`, optional): Process name.
        - `retno` (`int`, optional): Return value.
        - `args` (`list`, optional): Raw argument values.
        - `args_repr` (`list`, optional): String representations of arguments.
        - `retno_repr` (`str`, optional): String representation of return value.

        **Returns:** None
        """
        if args is None:
            args = []
        if args_repr is None:
            args_repr = []
        keys = {
            "name": name,
            "procname": procname or "[none]",
            "retno": int(self.panda.ffi.cast("target_long", retno)) if retno else None,
            "retno_repr": retno_repr,
        }
        for i in range(len(args)):
            keys[f"arg{i}"] = int(self.panda.ffi.cast("target_long", args[i]))
        for i in range(len(args_repr)):
            keys[f"arg{i}_repr"] = args_repr[i]
        self.DB.add_event(Syscall(**keys))
