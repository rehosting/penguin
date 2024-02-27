import struct
from pandare import PyPlugin

class SendHypercall(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
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
        word_char = 'I' if arch_bytes == 4 else 'Q'
        ptrs = struct.unpack_from(f"{buf_num_ptrs}{word_char}", buf)
        str_ptrs, out_addr = ptrs[:-1], ptrs[-1]

        # Read command and arg strings
        strs = [self.panda.read_str(cpu, ptr) for ptr in str_ptrs]
        cmd, args = strs[0], strs[1:]

        # Simulate command
        f = getattr(self, f"cmd_{cmd}")
        if f is None:
            raise ValueError("Unknown send_hypercall command")
        ret_val, out_str = f(*args)

        # Debug logging
        import sys
        print(f"{cmd} {' '.join(args)} -> {ret_val}, {repr(out_str)}", file=sys.stderr)

        # Send output to guest
        assert len(out_str) < 0x1000
        self.panda.virtual_memory_write(cpu, out_addr, out_str.encode())
        self.panda.arch.set_retval(cpu, ret_val)

    def cmd_fw_setenv(self, var, val):
        self.uboot_env[var] = val
        return 0, ""

    def cmd_fw_getenv(self, var):
        try:
            return 0, self.uboot_env[var]
        except KeyError:
            return 1, ""

    def cmd_fw_printenv(self):
        raise NotImplementedError("fw_printenv shim unimplemented")
