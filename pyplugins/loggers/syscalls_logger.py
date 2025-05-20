import re
from pandare2 import PyPlugin
from os.path import join
from events.types import Syscall
from penguin import plugins
from penguin import getColoredLogger
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


class PyPandaSysLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.saved_syscall_info = {}
        self.logger = getColoredLogger("syslog")
        self.DB = plugins.DB

        procs = self.get_arg("procs")

        if panda.arch_name in ["mips", "mipsel"]:
            self.errcode_to_errname = errcode_to_errname_mips
            self.errcode_to_explanation = errcode_to_explanation_mips
        else:
            self.errcode_to_errname = errcode_to_errname
            self.errcode_to_explanation = errcode_to_explanation

        if procs:
            for proc in procs:
                syscalls.syscall("on_all_sys_return", comm_filter=proc)(
                    self.all_sys_ret)
                syscalls.syscall("on_sys_execve_enter", comm_filter=proc)(
                    self.sys_execve_enter)
                syscalls.syscall("on_sys_execveat_enter", comm_filter=proc)(
                    self.sys_execve_enter)
        else:
            syscalls.syscall("on_all_sys_return")(self.all_sys_ret)
            syscalls.syscall("on_sys_execve_enter")(self.sys_execve_enter)
            syscalls.syscall("on_sys_execveat_enter")(self.sys_execve_enter)

    @plugins.portal.wrap
    def sys_execve_enter(self, proto, syscall, *args):
        yield from self.handle_syscall(proto, syscall)

    @plugins.portal.wrap
    def all_sys_ret(self, proto, syscall):
        protoname, _, _ = self.get_syscall_proto(proto, proto.syscall_nr)
        if "execve" not in protoname:
            yield from self.handle_syscall(proto, syscall)

    def get_arg_repr(self, argval, ctype, name):
        if name == "fd":
            fd_name = yield from plugins.portal.get_fd_name(argval)
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
            val = yield from plugins.portal.read_str(argval)
            return f'{argval_uint:#x}("{val}")'

        # Handle array of strings
        elif ctype == 'const char *const *':
            if argval_uint == 0:
                return "[NULL]"
            result = []
            addr = argval_uint
            max_args = 20  # Limit to avoid infinite loops
            for i in range(max_args):
                ptr = yield from plugins.portal.read_ptr(addr + (i * self.panda.bits // 8))
                if ptr == 0:
                    break
                str_val = yield from plugins.portal.read_str(ptr)
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

    def cstr(self, x):
        if isinstance(x, str):
            return x
        return "" if x == self.panda.ffi.NULL else self.panda.ffi.string(x).decode()

    @functools.lru_cache
    def get_syscall_proto(self, proto, num):
        protoname = self.cstr(proto.name)
        types = [self.cstr(proto.types[i]) for i in range(proto.nargs)]
        names = [self.cstr(proto.names[i]) for i in range(proto.nargs)]
        return protoname, types, names

    def handle_syscall(self, proto, syscall):
        protoname, types, names = self.get_syscall_proto(
            proto, proto.syscall_nr)
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

        proc_args = yield from plugins.portal.get_args()
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
        name,
        procname=None,
        retno=None,
        args=None,
        args_repr=None,
        retno_repr=None,
    ):
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
