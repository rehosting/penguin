"""
Syscalls Logger Plugin
======================

This plugin records system call events to the penguin database. It parses Linux error codes from header files,
maps error numbers to names and explanations, and logs detailed syscall information including arguments,
return values, and process context.

Purpose
-------

- Monitors all system call return events and execve/execveat entries in the guest.
- Records syscall arguments, return values, and error codes with explanations.
- Enables later analysis of system call activity and process behavior.

Usage
-----

.. code-block:: python

    from pyplugins.loggers.syscalls_logger import PyPandaSysLog

    syscalls_logger = PyPandaSysLog(panda)
    # Syscall events will be logged automatically.

This plugin is loaded automatically as part of the penguin plugin system. It requires the syscalls, mem,
portal, and osi plugins to be active.

The plugin extracts relevant fields and stores them in the database using the Syscall event type.

Arguments
---------

- outdir: Output directory for the SQLite database file.
- procs: Optional list of process names to filter syscall logging. If not provided, all processes are logged.

"""

import re
from os.path import join
from events.types import Syscall
from penguin import plugins, Plugin
import functools

ERRNO_REGEX = re.compile(
    r"#define\s*(?P<errname>E[A-Z0-9]*)\s*(?P<errcode>\d*)\s*/\*(?P<explanation>.*)\*/",
    re.MULTILINE
)


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
        self.DB = plugins.DB

        # PANDA/FFI Optimization
        self.ffi = panda.ffi
        self.cast = self.ffi.cast
        self.mem_read_str = plugins.mem.read_str
        self.mem_read_ptr_list = plugins.mem.read_char_ptrlist
        self.osi_get_fd = plugins.osi.get_fd_name

        self._init_error_codes(panda)
        self._init_type_handlers() # Pre-compile type logic

        # Hook registration (Same as original)
        procs = self.get_arg("procs")
        monitor_enter_syscalls = ['execve', 'execveat', 'exit', 'exit_group', 'vfork', 'reboot', 'sigreturn', 'setcontext']

        if procs:
            for proc in procs:
                syscalls.syscall("on_all_sys_return", comm_filter=proc, read_only=True)(self.all_sys_ret)
                for sc in monitor_enter_syscalls:
                    syscalls.syscall(f"on_sys_{sc}_enter", comm_filter=proc, read_only=True)(self.sys_record_enter)
        else:
            syscalls.syscall("on_all_sys_return", read_only=True)(self.all_sys_ret)
            for sc in monitor_enter_syscalls:
                syscalls.syscall(f"on_sys_{sc}_enter", read_only=True)(self.sys_record_enter)

    def _init_type_handlers(self):
        """Define specialized handlers to avoid string matching in hot path"""
        
        # Helper to mark handlers: (function, is_generator)
        def handle_fd(argval):
            fd_name = yield from self.osi_get_fd(argval)
            return f"{argval:#x}({fd_name or '[???]'})"

        def handle_int(argval):
            return f"{argval:#x}"

        def handle_str(argval):
            if argval == 0: return "[NULL]"
            val = yield from self.mem_read_str(argval)
            return f'{argval:#x}("{val}")'

        def handle_str_array(argval):
            if argval == 0: return "[NULL]"
            str_list = yield from self.mem_read_ptr_list(argval, 20)
            repr_str = ', '.join(repr(s) for s in str_list)
            return f"{argval:#x}([{repr_str}])"

        def handle_ptr(argval, type_name="ptr"):
            if argval == 0: return "[NULL]"
            return f"{argval:#x}({type_name})"

        # Map handlers to a tuple: (func, is_generator_flag)
        self.handlers = {
            'fd': (handle_fd, True),
            'int': (handle_int, False),
            'str': (handle_str, True),
            'str_array': (handle_str_array, True),
            'ptr': (handle_ptr, False)
        }

        self.STRING_TYPES = frozenset({'const char *', 'char *'})
        self.PTR_TYPES = frozenset({
            'int *', 'unsigned int *', 'unsigned long *', 'uid_t *', 'gid_t *', 
            'old_uid_t *', 'old_gid_t *', 'size_t *', 'off_t *', 'loff_t *', 
            'u32 *', 'u64 *', 'timer_t *', 'aio_context_t *', 'unsigned *'
        })
        
        # Pre-allocate the row template to avoid repeated dict growth/filling
        self.row_template = {
            "name": "", "procname": "?", "retno": 0, "retno_repr": "0",
            "arg0": 0, "arg0_repr": "", "arg1": 0, "arg1_repr": "",
            "arg2": 0, "arg2_repr": "", "arg3": 0, "arg3_repr": "",
            "arg4": 0, "arg4_repr": "", "arg5": 0, "arg5_repr": ""
        }

    def _resolve_handler(self, ctype, name):
        """
        Returns: (handler_func, is_generator, extra_arg)
        """
        if name == "fd":
            func, is_gen = self.handlers['fd']
            return func, is_gen, None
        
        if ctype in self.STRING_TYPES:
            func, is_gen = self.handlers['str']
            return func, is_gen, None
        
        if ctype == 'const char *const *':
            func, is_gen = self.handlers['str_array']
            return func, is_gen, None
            
        if '*' in ctype:
            display_type = "ptr"
            if 'struct' in ctype or 'union' in ctype:
                display_type = ctype.replace('const ', '').replace(' *', '')
            elif ctype in self.PTR_TYPES:
                display_type = "ptr"
            
            func, is_gen = self.handlers['ptr']
            return func, is_gen, display_type

        func, is_gen = self.handlers['int']
        return func, is_gen, None

    def _init_error_codes(self, panda):
        """
        Parses errno headers. Moved from global scope to init to speed up import time.
        """
        errno_resources = join(plugins.resources, "errno")
        
        # Helper to read file content
        def read_file(name):
            with open(join(errno_resources, name)) as f:
                return f.read()

        errno_base = read_file("errno-base.h")
        
        def parse_errors(content):
            mapping_name = {}
            mapping_expl = {}
            for match in ERRNO_REGEX.finditer(content):
                errname = match.group('errname').strip()
                errcode = int(match.group('errcode'))
                explanation = match.group('explanation').strip()
                mapping_name[errcode] = errname
                mapping_expl[errcode] = explanation
            return mapping_name, mapping_expl

        if panda.arch_name in ["mips", "mipsel"]:
            content = errno_base + "\n" + read_file("mips.h")
        else:
            content = errno_base + "\n" + read_file("generic.h")
            
        self.errcode_to_errname, self.errcode_to_explanation = parse_errors(content)

    def cstr(self, x) -> str:
        if isinstance(x, str): return x
        return "" if x == self.ffi.NULL else self.ffi.string(x).decode()

    @functools.lru_cache(maxsize=256)
    def get_syscall_processors(self, proto):
        """
        Returns cached list of: (arg_name, handler_func, is_gen, extra_data)
        """
        processors = []
        protoname = self.cstr(proto.name)
        
        for i in range(proto.nargs):
            ctype = self.cstr(proto.types[i])
            argname = self.cstr(proto.names[i])
            # Unpack the 3-item tuple from _resolve_handler
            handler, is_gen, extra = self._resolve_handler(ctype, argname)
            processors.append((argname, handler, is_gen, extra))
            
        return protoname, processors

    def sys_record_enter(self, regs, proto, syscall, *args) -> None:
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
        if "execve" not in self.cstr(proto.name):
            yield from self.handle_syscall(regs, proto, syscall)

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
        # Localize lookups for speed
        cast = self.cast
        err_name_map = self.errcode_to_errname
        err_expl_map = self.errcode_to_explanation
        syscall_args = syscall.args
        
        # 1. Get cached processors
        protoname, processors = self.get_syscall_processors(proto)
        
        # 2. Fast Template Copy (Faster than creating new dict + filling blanks)
        row_data = self.row_template.copy()
        row_data["name"] = protoname

        # 3. Process Arguments (Hot Loop)
        for i, (name, handler, is_gen, extra) in enumerate(processors):
            # Casting overhead: assuming target_ulong fits in standard int logic
            raw_val = int(cast("target_ulong", syscall_args[i]))
            
            row_data[f"arg{i}"] = raw_val
            
            # Use pre-calculated flags to avoid isinstance() checks
            if extra:
                val_str = handler(raw_val, extra)
            elif is_gen:
                val_str = yield from handler(raw_val)
            else:
                val_str = handler(raw_val)
            
            row_data[f"arg{i}_repr"] = f"{name}={val_str}"

        # 4. Handle Return Value
        retval = int(cast("target_long", syscall.retval))
        row_data["retno"] = retval
        
        # Error code lookup (Check negative retval)
        errnum = -retval
        if errnum in err_name_map:
            # Using get() on second map is safer and fast
            row_data["retno_repr"] = f"{err_name_map[errnum]}({err_expl_map.get(errnum, '')})"
        else:
            row_data["retno_repr"] = f"{retval:#x}"

        # 5. Get Process Info (OSI)
        proc_args = yield from plugins.osi.get_args()
        if proc_args:
            row_data["procname"] = proc_args[0]
        else:
            row_data["procname"] = "[none]"
        self.DB.add_event(Syscall, row_data)