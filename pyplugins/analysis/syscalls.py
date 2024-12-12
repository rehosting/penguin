import contextlib
import re
from pandare import PyPlugin
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

        panda.ppp("syscalls2", "on_all_sys_enter2")(self.all_sys_enter)
        panda.ppp("syscalls2", "on_all_sys_return")(self.all_sys_ret)

    def all_sys_enter(self, cpu, pc, info, ctx):
        if info == self.panda.ffi.NULL or ctx == self.panda.ffi.NULL:
            return

        nargs = info.nargs
        panda = self.panda
        syscall_name = panda.ffi.string(info.name).decode()
        try_replace_args = {}

        procname = panda.get_process_name(cpu)

        # Collect syscall arguments
        args = []
        for i in range(nargs):
            try:
                arg = panda.arch.get_arg(cpu, i + 1, convention="syscall")
            except ValueError:
                arg = 0  # Default to 0 if an argument cannot be fetched
                try_replace_args[i] = (0, "arg")  # Track this for potential replacement later
            args.append(arg)

        def process_arg(type_, arg, argn, i):
            def read_type(type_, arg):
                return panda.ffi.cast(f"{type_}_t", arg)

            t = "uint32" if panda.bits == 32 else "uint64"
            name = "?" if argn == panda.ffi.NULL else panda.ffi.string(argn).decode()
            argval = int(read_type(t, arg))

            # Special handling for sockaddr-related syscalls
            sockaddr_syscalls = {
                'sys_bind': 1,
                'sys_connect': 1,
                'sys_accept4': 1,
                'sys_sendto': 4,
            }
            if syscall_name in sockaddr_syscalls and i == sockaddr_syscalls[syscall_name]:
                sockaddr_addr = argval
                if syscall_name == 'sys_accept4':
                    addrlen_ptr = args[2]
                    addrlen = self.read_int_from_ptr(panda, cpu, addrlen_ptr)
                elif syscall_name == 'sys_sendto':
                    addrlen = args[5] if len(args) > 5 else 0
                else:
                    addrlen = args[2] if len(args) > 2 else 0
                return self.process_sockaddr(panda, cpu, sockaddr_addr, addrlen)

            # Special handling for syscalls with custom structures
            if syscall_name == 'sys_socketpair' and i == 3:
                fds_addr = argval
                return self.process_socketpair_fds(panda, cpu, fds_addr)
            if syscall_name in ['sys_sendmsg', 'sys_recvmsg'] and i == 1:
                msghdr_addr = argval
                return self.process_msghdr(panda, cpu, msghdr_addr)

            # Handle known argument names
            if name == "fd":
                fname = panda.get_file_name(cpu, argval)
                return f"FD:{argval}({fname.decode('latin-1') if fname else 'None'})"
            elif name == "pathname":
                try:
                    return panda.read_str(cpu, argval)
                except ValueError:
                    try_replace_args[i] = (argval, "STR")
                    return

            # Determine argument type
            argtype = panda.ffi.string(panda.ffi.cast("syscall_argtype_t", type_))
            lookup_cast_tbl = {
                "SYSCALL_ARG_U64": "uint64",
                "SYSCALL_ARG_U32": "uint32",
                "SYSCALL_ARG_U16": "uint16",
                "SYSCALL_ARG_S64": "int64",
                "SYSCALL_ARG_S32": "int32",
                "SYSCALL_ARG_S16": "int16",
            }

            # If sys_kill pid argument (arg0) is a signed 32-bit value, handle carefully
            # to avoid negative sign-extension issues if not intended.
            if syscall_name == "sys_kill" and i == 0:
                # Forcefully interpret as a signed 32-bit integer
                masked_val = arg & 0xffffffff
                casted_val = int(panda.ffi.cast("int32_t", masked_val))
                print(f"SYS_KILL masked_val:{masked_val} casted_val:{casted_val}")
                return f"{casted_val}({casted_val:#x})"

            if argtype in lookup_cast_tbl:
                casted_val = int(read_type(lookup_cast_tbl[argtype], arg))
                if argtype.startswith("SYSCALL_ARG_S"):
                    return f"{casted_val}({casted_val:#x})"
                else:
                    return f"{casted_val:#x}"

            if argtype.endswith("_PTR"):
                try:
                    if "STR" in argtype:
                        buf = panda.read_str(cpu, argval) if argval != 0 else '[NULL]'
                    else:
                        buf = panda.virtual_memory_read(cpu, argval, 20)
                except Exception:
                    buf = "?"
                    try_replace_args[i] = (argval, argtype)
                return f'{argval:#x}("{buf}")'
            elif "STRUCT" in argtype:
                return f"{argval:#x} (struct)"

            # Default fallback
            return hex(argval)

        # Process each argument once
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

    def add_syscall(
        self,
        name,
        procname=None,
        retno=None,
        args=None,
        args_repr=None,
        retno_repr=None,
        pid=None,
    ):
        if args is None:
            args = []
        if args_repr is None:
            args_repr = []
        
        keys = {
            "name": name,
            "procname": procname or "[none]",
            "retno": retno,
            "retno_repr": retno_repr,
            "pid": pid,
        }

        # Add arguments to the syscall record
        for i in range(len(args)):
            keys[f"arg{i}"] = int(self.panda.ffi.cast("target_long", args[i]))
        for i in range(len(args_repr)):
            keys[f"arg{i}_repr"] = args_repr[i]

        self.DB.add_event(Syscall(**keys))


    def return_syscall(self, syscall_info, retval):
        func_args, try_replace_args = syscall_info
        panda, cpu = self.panda, self.panda.get_cpu()

        # Replace arguments that couldn't be resolved earlier
        for i, (argval, ctype) in try_replace_args.items():
            with contextlib.suppress(ValueError):
                if "STR" in ctype:
                    buf = panda.read_str(cpu, argval) if argval != 0 else "[NULL]"
                elif "arg" in ctype:
                    buf = panda.arch.get_arg(cpu, i + 1, convention="syscall")
                else:
                    buf = panda.virtual_memory_read(cpu, argval, 20)
                func_args["args_repr"][i] = f'{argval:#x}("{buf}")'

        # Handle return value
        if retval is not None:
            # Correctly cast return value to signed 32-bit integer
            retno = int(self.panda.ffi.cast("int32_t", retval))
            func_args["retno"] = retno

            # Map errors to errno descriptions
            errnum = -retno
            if errnum in self.errcode_to_errname:
                func_args["retno_repr"] = f"{self.errcode_to_errname[errnum]}({self.errcode_to_explanation[errnum]})"
            else:
                func_args["retno_repr"] = f"{retno:#x}"
        else:
            func_args["retno"] = None
            func_args["retno_repr"] = "None"

        self.add_syscall(**func_args)


    def process_sockaddr(self, panda, cpu, sockaddr_addr, addrlen):
        if sockaddr_addr == 0:
            # Handle NULL sockaddr
            return f'{sockaddr_addr:#x}("[NULL sockaddr]")'
        try:
            sin_family_bytes = panda.virtual_memory_read(cpu, sockaddr_addr, 2)
            sin_family = int.from_bytes(sin_family_bytes, byteorder='little')
        except Exception:
            return f'{sockaddr_addr:#x}("[Invalid sockaddr]")'

        if sin_family == 1:  # AF_UNIX
            try:
                path_len = addrlen - 2
                if path_len <= 0:
                    return f'{sockaddr_addr:#x}("[Invalid path length]")'
                path_bytes = panda.virtual_memory_read(cpu, sockaddr_addr + 2, path_len)
                socket_path = path_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                return f'{sockaddr_addr:#x}("{socket_path}")'
            except Exception:
                return f'{sockaddr_addr:#x}("[Error reading AF_UNIX path]")'
        elif sin_family == 2:  # AF_INET
            try:
                sin_port_bytes = panda.virtual_memory_read(cpu, sockaddr_addr + 2, 2)
                sin_port = int.from_bytes(sin_port_bytes, byteorder='big')
                sin_addr_bytes = panda.virtual_memory_read(cpu, sockaddr_addr + 4, 4)
                sin_addr = '.'.join(map(str, sin_addr_bytes))
                return f'{sockaddr_addr:#x}("AF_INET:{sin_addr}:{sin_port}")'
            except Exception:
                return f'{sockaddr_addr:#x}("[Error reading AF_INET address]")'
        elif sin_family == 10:  # AF_INET6
            try:
                sin6_port_bytes = panda.virtual_memory_read(cpu, sockaddr_addr + 2, 2)
                sin6_port = int.from_bytes(sin6_port_bytes, byteorder='big')
                sin6_addr_bytes = panda.virtual_memory_read(cpu, sockaddr_addr + 8, 16)
                sin6_addr = ':'.join('{:02x}{:02x}'.format(sin6_addr_bytes[i], sin6_addr_bytes[i+1])
                                    for i in range(0, 16, 2))
                return f'{sockaddr_addr:#x}("AF_INET6:[{sin6_addr}]:{sin6_port}")'
            except Exception:
                return f'{sockaddr_addr:#x}("[Error reading AF_INET6 address]")'
        else:
            return f'{sockaddr_addr:#x}("[Unknown AF {sin_family}]")'


    def process_socketpair_fds(self, panda, cpu, fds_addr):
        try:
            fds_bytes = panda.virtual_memory_read(cpu, fds_addr, 8 if panda.bits == 32 else 16)
            fd1 = int.from_bytes(fds_bytes[:4], byteorder='little')
            fd2 = int.from_bytes(fds_bytes[4:8], byteorder='little')
            return f'{fds_addr:#x}([FDs: {fd1}, {fd2}])'
        except Exception:
            return f'{fds_addr:#x}("[Error reading FDs]")'

    def process_msghdr(self, panda, cpu, msghdr_addr):
        try:
            offset = 0
            ptr_size = 4 if panda.bits == 32 else 8

            msg_name_ptr_bytes = panda.virtual_memory_read(cpu, msghdr_addr + offset, ptr_size)
            msg_name_ptr = int.from_bytes(msg_name_ptr_bytes, byteorder='little')
            offset += ptr_size

            msg_namelen_bytes = panda.virtual_memory_read(cpu, msghdr_addr + offset, ptr_size)
            msg_namelen = int.from_bytes(msg_namelen_bytes, byteorder='little')
            offset += ptr_size

            # Process msg_name if present
            if msg_name_ptr != 0 and msg_namelen > 0:
                addr_str = self.process_sockaddr(panda, cpu, msg_name_ptr, msg_namelen)
            else:
                addr_str = 'None'

            return f'{msghdr_addr:#x}(msg_name: {addr_str})'
        except Exception:
            return f'{msghdr_addr:#x}("[Error reading msghdr]")'

    def read_int_from_ptr(self, panda, cpu, addr):
        try:
            int_size = 4 if panda.bits == 32 else 8
            int_bytes = panda.virtual_memory_read(cpu, addr, int_size)
            return int.from_bytes(int_bytes, byteorder='little')
        except Exception:
            return 0
