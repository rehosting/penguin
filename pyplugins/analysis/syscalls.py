import contextlib
import re
from pandare2 import PyPlugin
from os.path import join
from events.types import Syscall
from penguin import plugins

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


class PyPandaSysLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.saved_syscall_info = {}
        self.DB = plugins.DB

        if panda.arch_name in ["mips", "mipsel"]:
            self.errcode_to_errname = errcode_to_errname_mips
            self.errcode_to_explanation = errcode_to_explanation_mips
        else:
            self.errcode_to_errname = errcode_to_errname
            self.errcode_to_explanation = errcode_to_explanation

        panda.hsyscall("on_all_sys_enter")(self.all_sys_enter)
        panda.hsyscall("on_all_sys_return")(self.all_sys_ret)

    def all_sys_enter(self, cpu, proto, syscall, hook):
        nargs = proto.nargs
        panda = self.panda
        syscall_name = panda.ffi.string(proto.name).decode()
        try_replace_args = {}

        procname = panda.get_process_name(cpu)

        args = []
        # why? because it can read the stack and fail
        for i in range(nargs):
            try:
                arg = panda.arch.get_arg(cpu, i + 1, convention="syscall")
            except ValueError:
                arg = 0
                try_replace_args[i] = (0, "arg")
            args.append(arg)
        args_repr = [
            syscall.args[i] for i in range(nargs)
        ]
        func_args = {
            "name": syscall_name,
            "procname": procname,
            "retno": None,
            "args": args,
            "args_repr": args_repr,
        }
        if syscall.task in self.saved_syscall_info:
            self.return_syscall(self.saved_syscall_info[syscall.task], None)
        self.saved_syscall_info[syscall.task] = (func_args, try_replace_args)

    def all_sys_ret(self, cpu, proto, syscall, hook):
        if sysinfo := self.saved_syscall_info.pop(syscall.task, None):
            self.return_syscall(
                sysinfo, syscall.retval 
            )

    # def uninit(self):
        # print("Called uninit...")
        # while self.saved_syscall_info:
        #     sysinfo = self.saved_syscall_info.popitem()
        #     self.return_syscall(sysinfo, None)

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

    def return_syscall(self, syscall_info, retval):
        func_args, try_replace_args = syscall_info
        for i, (argval, ctype) in try_replace_args.items():
            panda, cpu = self.panda, self.panda.get_cpu()
            with contextlib.suppress(ValueError):
                buf = (
                    panda.read_str(cpu, argval) if argval != 0 else "[NULL]"
                    if "STR" in ctype
                    else (
                        panda.arch.get_arg(cpu, i + 1, convention="syscall")
                        if "arg" in ctype
                        else panda.virtual_memory_read(panda.get_cpu(), argval, 20)
                    )
                )
                func_args["args_repr"][i] = f'{argval:#x}("{buf}")'
        if retval is not None:
            func_args["retno"] = int(self.panda.ffi.cast("target_long", retval))
            errnum = -func_args["retno"]
            if errnum in self.errcode_to_errname:
                func_args["retno_repr"] = (
                    f"{self.errcode_to_errname[errnum]}({self.errcode_to_explanation[errnum]})"
                )
            else:
                func_args["retno_repr"] = f"{func_args['retno']:#x}"
            retval = int(self.panda.ffi.cast("target_long", retval))
        self.add_syscall(**func_args)
