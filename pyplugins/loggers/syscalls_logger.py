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
import struct
from os.path import join
from pengutils.events import Syscall
from penguin import plugins, Plugin
import functools
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop

ERRNO_REGEX = re.compile(
    r"#define\s*(?P<errname>E[A-Z0-9]*)\s*(?P<errcode>\d*)\s*/\*(?P<explanation>.*)\*/",
    re.MULTILINE
)


syscalls = plugins.syscalls

_ARG_IGNORE = 0
_ARG_SCALAR = 1
_ARG_CSTRING = 2
_ARG_STRING_ARRAY = 3
_ARG_BUFFER = 5
_ARG_BUFFER_OUT = 6

_LOG_ENTRY = 1
_LOG_RETURN = 2

_ARG_F_TRUNCATED = 1 << 0
_ARG_F_FAULT = 1 << 1
_ARG_F_NULL = 1 << 2
_ARG_F_ARRAY_END = 1 << 3

_RECORD_HEADER_FMT = "HHIQQqIIII6Q16s48s"
_TLV_HEADER_FMT = "BBHI"
_SCHEMA_FMT = "48sB6BxH"
_CONFIG_FMT = "IIII"


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
        self.cbs = []
        self._pending_entries = {}
        self._pending_portal_cmds = []

        self._init_error_codes(panda)
        self._init_type_handlers()  # Pre-compile type logic

        procs = self.get_arg("procs")
        self.monitor_enter_syscalls = [
            'execve', 'execveat', 'exit', 'exit_group', 'vfork', 'reboot', 'sigreturn', 'setcontext']
        self._proc_filter = set(procs or [])
        self._header_struct = struct.Struct(
            f"{plugins.portal.endian_format}{_RECORD_HEADER_FMT}")
        self._tlv_struct = struct.Struct(
            f"{plugins.portal.endian_format}{_TLV_HEADER_FMT}")
        self._schema_struct = struct.Struct(
            f"{plugins.portal.endian_format}{_SCHEMA_FMT}")
        self._config_struct = struct.Struct(
            f"{plugins.portal.endian_format}{_CONFIG_FMT}")
        plugins.portal.register_interrupt_handler(
            "syscalls_logger", self._portal_interrupt_handler, always=True)
        self._queue_logger_setup()

    def enable(self, args={}):
        self._queue_logger_setup()

    def disable(self):
        cbs = self.cbs
        self.cbs = []
        for cb in cbs:
            syscalls.unregister(cb)
        self._pending_portal_cmds.append(
            PortalCmd(hop.HYPER_OP_CONFIG_SYSCALL_LOGGER,
                      size=self._config_struct.size,
                      data=self._config_struct.pack(0, 0, 0, 0)))
        plugins.portal.queue_interrupt("syscalls_logger")

    def _init_type_handlers(self):
        """Define specialized handlers to avoid string matching in hot path"""

        def handle_int(argval):
            return f"{argval:#x}"

        def handle_str(argval, captured=None, flags=0):
            if argval == 0:
                return "[NULL]"
            if flags & _ARG_F_NULL:
                return "[NULL]"
            if flags & _ARG_F_FAULT:
                return f'{argval:#x}([FAULT])'
            val = captured if captured is not None else ""
            suffix = "...[TRUNCATED]" if flags & _ARG_F_TRUNCATED else ""
            return f'{argval:#x}("{val}{suffix}")'

        def handle_str_array(argval, captured=None, flags=0):
            if argval == 0:
                return "[NULL]"
            if flags & _ARG_F_NULL:
                return "[NULL]"
            if flags & _ARG_F_FAULT:
                return f"{argval:#x}([FAULT])"
            str_list = captured or []
            repr_str = ', '.join(repr(s) for s in str_list)
            if flags & _ARG_F_TRUNCATED:
                repr_str = f"{repr_str}, '[TRUNCATED]'" if repr_str else "'[TRUNCATED]'"
            return f"{argval:#x}([{repr_str}])"

        def handle_ptr(argval, type_name="ptr"):
            if argval == 0:
                return "[NULL]"
            return f"{argval:#x}({type_name})"

        self.handlers = {
            'fd': (handle_int, False),
            'int': (handle_int, False),
            'str': (handle_str, False),
            'str_array': (handle_str_array, False),
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

        self.errcode_to_errname, self.errcode_to_explanation = parse_errors(
            content)

    def cstr(self, x) -> str:
        if isinstance(x, str):
            return x
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

    def _queue_logger_setup(self):
        # The portal data page is smaller than the kernel-side max record, so
        # configure records to fit one drain response.
        record_limit = max(512, plugins.portal.regions_size - 256)
        string_limit = min(4096, max(128, record_limit // 2))
        self._pending_portal_cmds.append(
            PortalCmd(hop.HYPER_OP_CONFIG_SYSCALL_LOGGER,
                      size=self._config_struct.size,
                      data=self._config_struct.pack(1, string_limit, record_limit, 1)))
        for schema in self._default_schemas():
            self._pending_portal_cmds.append(
                PortalCmd(hop.HYPER_OP_REGISTER_SYSCALL_LOGGER_SCHEMA,
                          size=len(schema), data=schema))
        plugins.portal.queue_interrupt("syscalls_logger")

    def _schema_bytes(self, name, arg_types):
        fixed = list(arg_types[:6]) + [_ARG_IGNORE] * (6 - len(arg_types))
        return self._schema_struct.pack(
            name.encode("utf-8")[:47].ljust(48, b"\x00"),
            min(len(arg_types), 6),
            *fixed,
            0)

    def _default_schemas(self):
        return [
            self._schema_bytes("open", [_ARG_CSTRING, _ARG_SCALAR, _ARG_SCALAR]),
            self._schema_bytes("openat", [_ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR, _ARG_SCALAR]),
            self._schema_bytes("creat", [_ARG_CSTRING, _ARG_SCALAR]),
            self._schema_bytes("chdir", [_ARG_CSTRING]),
            self._schema_bytes("mkdir", [_ARG_CSTRING, _ARG_SCALAR]),
            self._schema_bytes("mkdirat", [_ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR]),
            self._schema_bytes("rmdir", [_ARG_CSTRING]),
            self._schema_bytes("unlink", [_ARG_CSTRING]),
            self._schema_bytes("unlinkat", [_ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR]),
            self._schema_bytes("rename", [_ARG_CSTRING, _ARG_CSTRING]),
            self._schema_bytes("renameat", [_ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR, _ARG_CSTRING]),
            self._schema_bytes("renameat2", [_ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR, _ARG_CSTRING, _ARG_SCALAR]),
            self._schema_bytes("execve", [_ARG_CSTRING, _ARG_STRING_ARRAY, _ARG_STRING_ARRAY]),
            self._schema_bytes("execveat", [_ARG_SCALAR, _ARG_CSTRING, _ARG_STRING_ARRAY, _ARG_STRING_ARRAY, _ARG_SCALAR]),
            self._schema_bytes("connect", [_ARG_SCALAR, _ARG_SCALAR, _ARG_SCALAR]),
            self._schema_bytes("read", [_ARG_SCALAR, _ARG_BUFFER_OUT, _ARG_SCALAR]),
            self._schema_bytes("write", [_ARG_SCALAR, _ARG_BUFFER, _ARG_SCALAR]),
        ]

    def _portal_interrupt_handler(self):
        while self._pending_portal_cmds:
            yield self._pending_portal_cmds.pop(0)
        while True:
            data = yield PortalCmd(hop.HYPER_OP_DRAIN_SYSCALL_LOG)
            if not data or isinstance(data, int):
                break
            self._process_log_batch(data)

    def _decode_cstr(self, raw):
        raw = raw.split(b"\x00", 1)[0]
        return raw.decode("utf-8", errors="replace")

    def _parse_payload(self, payload):
        captured = {}
        off = 0
        while off + self._tlv_struct.size <= len(payload):
            arg_index, capture_type, flags, size = self._tlv_struct.unpack_from(payload, off)
            off += self._tlv_struct.size
            raw = payload[off:off + size]
            off += size
            if capture_type == _ARG_CSTRING:
                captured[arg_index] = (self._decode_cstr(raw), flags)
            elif capture_type == _ARG_STRING_ARRAY:
                values, merged_flags = captured.get(arg_index, ([], 0))
                merged_flags |= flags
                if size:
                    values.append(self._decode_cstr(raw))
                captured[arg_index] = (values, merged_flags)
            elif capture_type in (_ARG_BUFFER, _ARG_BUFFER_OUT):
                captured[arg_index] = (raw.decode("utf-8", errors="replace"), flags)
        return captured

    def _process_log_batch(self, data):
        off = 0
        header_size = self._header_struct.size
        while off + header_size <= len(data):
            total_len = struct.unpack_from(f"{plugins.portal.endian_format}I", data, off + 4)[0]
            if total_len < header_size or off + total_len > len(data):
                break
            fields = self._header_struct.unpack_from(data, off)
            record = self._record_from_fields(fields, data[off + header_size:off + total_len])
            self._handle_log_record(record)
            off += total_len

    def _record_from_fields(self, fields, payload):
        (version, record_type, total_len, seq, pc, retval, pid, tgid, argc,
         payload_len, *rest) = fields
        args = rest[:6]
        comm = self._decode_cstr(rest[6])
        name = self._decode_cstr(rest[7])
        return {
            "type": record_type,
            "seq": seq,
            "retval": retval,
            "pid": pid,
            "tgid": tgid,
            "argc": argc,
            "args": args,
            "comm": comm,
            "name": f"sys_{name}" if not name.startswith("sys_") else name,
            "captured": self._parse_payload(payload[:payload_len]),
        }

    def _handle_log_record(self, record):
        if self._proc_filter and record["comm"] not in self._proc_filter:
            return
        if record["type"] == _LOG_ENTRY:
            row = self._row_from_record(record)
            self._pending_entries[record["seq"]] = row
            clean_name = record["name"][4:] if record["name"].startswith("sys_") else record["name"]
            if clean_name in self.monitor_enter_syscalls:
                self.DB.add_event(Syscall, row.copy())
            return
        if record["type"] == _LOG_RETURN:
            row = self._pending_entries.pop(record["seq"], None)
            if record["captured"]:
                row = self._row_from_record(record)
            if row is None:
                row = self._row_from_record(record)
            self._fill_retval(row, record["retval"])
            self.DB.add_event(Syscall, row)

    def _row_from_record(self, record):
        proto = syscalls._syscall_info_table.get(
            syscalls._clean_syscall_name(record["name"]))
        if proto is None:
            proto = syscalls._syscall_info_table.get(record["name"].removeprefix("sys_"))
        if proto is None:
            proto = type("_Proto", (), {
                "name": record["name"],
                "nargs": min(record["argc"], 6),
                "types": ["int"] * min(record["argc"], 6),
                "names": [f"unknown{i+1}" for i in range(min(record["argc"], 6))]
            })()

        row_data = self.row_template.copy()
        row_data["name"] = proto.name
        row_data["procname"] = record["comm"] or "[none]"
        processors = []
        for i in range(proto.nargs):
            ctype = proto.types[i]
            argname = proto.names[i]
            processors.append((argname, *self._resolve_handler(ctype, argname)))

        for i, (name, handler, is_gen, extra) in enumerate(processors[:6]):
            raw_val = int(record["args"][i])
            row_data[f"arg{i}"] = raw_val
            captured, flags = record["captured"].get(i, (None, 0))
            if extra:
                val_str = handler(raw_val, extra)
            elif handler in (self.handlers['str'][0], self.handlers['str_array'][0]):
                val_str = handler(raw_val, captured, flags)
            else:
                val_str = handler(raw_val)
            row_data[f"arg{i}_repr"] = f"{name}={val_str}"
        self._fill_retval(row_data, record["retval"])
        return row_data

    def _fill_retval(self, row_data, retval):
        row_data["retno"] = int(retval)
        errnum = -int(retval)
        if errnum in self.errcode_to_errname:
            row_data["retno_repr"] = (
                f"{self.errcode_to_errname[errnum]}"
                f"({self.errcode_to_explanation.get(errnum, '')})")
        else:
            row_data["retno_repr"] = f"{int(retval):#x}"

    def sys_record_enter(self, regs, proto, syscall, *args) -> None:
        return None

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
            return None

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
