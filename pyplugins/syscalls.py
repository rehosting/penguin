import contextlib, re
from pandare import PyPlugin
from os.path import join, dirname
from penguin.db import Event
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy import ForeignKey
from typing import Optional


"""
This code acquires the error numbers from linux to map in the syscall plugin
"""
# read some errno.h to get the error codes and names
errcode_to_errname = {}
errcode_to_explanation = {}

RESOURCES = join(dirname(__file__), "errno")

with open(join(RESOURCES, "errno-base.h")) as f:
    errno_base = f.read()

with open(join(RESOURCES, "generic.h")) as f:
    errno = errno_base + "\n" + f.read()

with open(join(RESOURCES, "mips.h")) as f:
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


class Syscall(Event):
    __tablename__ = "syscall"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    name: Mapped[str]
    retno: Mapped[Optional[int]]
    retno_repr: Mapped[Optional[str]]
    arg0: Mapped[Optional[int]]
    arg0_repr: Mapped[Optional[str]]
    arg1: Mapped[Optional[int]]
    arg1_repr: Mapped[Optional[str]]
    arg2: Mapped[Optional[int]]
    arg2_repr: Mapped[Optional[str]]
    arg3: Mapped[Optional[int]]
    arg3_repr: Mapped[Optional[str]]
    arg4: Mapped[Optional[int]]
    arg4_repr: Mapped[Optional[str]]
    arg5: Mapped[Optional[int]]
    arg5_repr: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "syscall",
    }

    def __str__(self):
        args = []
        for i in range(6):
            arg, arg_repr = getattr(self, f"arg{i}"), getattr(self, f"arg{i}_repr")
            if arg is not None:
                args.append(f"{arg_repr}({arg:#x})")
        return f"{self.name}({', '.join(args)}) = {self.retno}({self.retno_repr})"


class PyPandaSysLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = self.get_arg("db")
        self.saved_syscall_info = {}

        if panda.arch_name in ["mips", "mipsel"]:
            self.errcode_to_errname = errcode_to_errname_mips
            self.errcode_to_explanation = errcode_to_explanation_mips
        else:
            self.errcode_to_errname = errcode_to_errname
            self.errcode_to_explanation = errcode_to_explanation

        panda.ppp("syscalls2", "on_all_sys_enter2")(self.all_sys_enter)
        panda.ppp("syscalls2", "on_all_sys_return")(self.all_sys_ret)

    def all_sys_enter(self, cpu, pc, info, ctx):
        if info == self.panda.ffi.NULL or ctx == self.panda.ffi.NULL:
            return
        nargs = info.nargs
        panda = self.panda
        syscall_name = panda.ffi.string(info.name).decode()
        try_replace_args = {}

        def process_arg(type_, arg, argn, i):
            def read_type(type_, arg):
                return panda.ffi.cast(f"{type_}_t", arg)

            t = "uint32" if panda.bits == 32 else "uint64"
            name = (
                "?" if argn == self.panda.ffi.NULL else panda.ffi.string(argn).decode()
            )
            if name == "fd":
                argval = int(read_type(t, arg))
                fname = panda.get_file_name(cpu, argval)
                return f"FD:{argval}({fname.decode('latin-1') if fname else 'None'})"
            elif name == "pathname":
                try:
                    return panda.read_str(cpu, arg)
                except ValueError:
                    try_replace_args[i] = (arg, "STR")
                    return

            argtype = panda.ffi.string(panda.ffi.cast("syscall_argtype_t", type_))
            lookup_cast_tbl = {
                "SYSCALL_ARG_U64": "uint64",
                "SYSCALL_ARG_U32": "uint32",
                "SYSCALL_ARG_U16": "uint16",
                "SYSCALL_ARG_S64": "int64",
                "SYSCALL_ARG_S32": "int32",
                "SYSCALL_ARG_S16": "int16",
            }
            if argtype in lookup_cast_tbl:
                return f"{int(read_type(lookup_cast_tbl[argtype], arg)):#x}"
            argval = int(read_type(t, arg))
            if argtype.endswith("_PTR"):
                try:
                    if "STR" in argtype:
                        buf = panda.read_str(cpu, argval).decode(errors="ignore")
                    else:
                        buf = panda.virtual_memory_read(cpu, argval, 20)
                except Exception:
                    buf = "?"
                    try_replace_args[i] = (argval, argtype)
                return f'{argval:#x}("{buf}")'
            elif "STRUCT" in argtype:
                return f"{argval:#x} (struct)"
            return hex(panda.arch.get_arg(cpu, argn + 1, convention="syscall"))

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
            process_arg(info.argt[i], args[i], info.argn[i], i) for i in range(nargs)
        ]
        func_args = {
            "name": syscall_name,
            "procname": procname,
            "retno": None,
            "args": args,
            "args_repr": args_repr,
        }
        if info.noreturn:
            self.add_syscall(**func_args)
        else:
            asid = self.panda.get_id(cpu)
            if asid in self.saved_syscall_info:
                self.return_syscall(self.saved_syscall_info[asid], None)
            self.saved_syscall_info[asid] = (func_args, try_replace_args)

    def all_sys_ret(self, cpu, pc, callno):
        asid = self.panda.get_id(cpu)
        if sysinfo := self.saved_syscall_info.pop(asid, None):
            self.return_syscall(
                sysinfo, self.panda.arch.get_retval(cpu, convention="syscall")
            )

    def uninit(self):
        print("Called uninit...")
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
        syscall = Syscall(**keys)
        self.DB.add_event(syscall)

    def return_syscall(self, syscall_info, retval):
        func_args, try_replace_args = syscall_info
        for i, (argval, ctype) in try_replace_args.items():
            panda, cpu = self.panda, self.panda.get_cpu()
            with contextlib.suppress(ValueError):
                buf = (
                    panda.read_str(cpu, argval)
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
