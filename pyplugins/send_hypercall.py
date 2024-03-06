import struct
import os
from pandare import PyPlugin

UBOOT_LOG="uboot.log"

class SendHypercall(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        open(os.path.join(self.outdir, UBOOT_LOG), "w").close()
        self.uboot_log = set()

        self.ppp.Core.ppp_reg_cb('igloo_send_hypercall', self.on_send_hypercall)

        # Command-specific fields
        self.uboot_env = self.get_arg("conf").get("uboot_env", dict())

    def on_send_hypercall(self, cpu, buf_addr, buf_num_ptrs):
        arch_bytes = self.panda.bits // 8

        # Read list of pointers
        buf_addr = self.panda.arch.get_arg(cpu, 1)
        buf_num_ptrs = self.panda.arch.get_arg(cpu, 2)
        buf_size = buf_num_ptrs * arch_bytes
        buf = self.panda.virtual_memory_read(cpu, buf_addr, buf_size, fmt="bytearray")

        # Unpack list of pointers
        word_char = 'I' if arch_bytes == 4 else 'Q' # TODO: is this correct for big-endian guests?
        ptrs = struct.unpack_from(f"{buf_num_ptrs}{word_char}", buf)
        str_ptrs, out_addr = ptrs[:-1], ptrs[-1]

        # Read command and arg strings
        try:
            strs = [self.panda.read_str(cpu, ptr) for ptr in str_ptrs]
        except ValueError:
            print(f"Send hypercall failed to read guest memory. Skipping")
            return
        cmd, args = strs[0], strs[1:]

        # Simulate command
        f = getattr(self, f"cmd_{cmd}")
        if f is None:
            raise ValueError("Unknown send_hypercall command")
        try:
            ret_val, out_str = f(*args)
        except Exception as e:
            print(f"Send hypercall: exception while processing {cmd}: {e}")
            return

        # Debug logging
        #import sys
        #print(f"{cmd} {' '.join(args)} -> {ret_val}, {repr(out_str)}", file=sys.stderr)

        # Send output to guest
        #assert len(out_str) < 0x1000
        self.panda.virtual_memory_write(cpu, out_addr, out_str.encode())
        self.panda.arch.set_retval(cpu, ret_val)

    def cmd_fw_setenv(self, var, val):
        if var not in self.uboot_log:
            self.uboot_log.add(var)
            with open(os.path.join(self.outdir, UBOOT_LOG), "a") as f:
                f.write(f"{var}={val}\n")
        self.uboot_env[var] = val
        return 0, ""

    def cmd_fw_getenv(self, var):
        try:
            return 0, self.uboot_env[var]
        except KeyError:
            if var not in self.uboot_log:
                self.uboot_log.add(var)
                with open(os.path.join(self.outdir, UBOOT_LOG), "a") as f:
                    f.write(var + "\n")
            return 1, ""

    def cmd_fw_printenv(self, arg):
        raise NotImplementedError("fw_printenv shim unimplemented")
