import os
import csv
import struct
import os
from penguin import getColoredLogger
from pandare import PyPlugin

UBOOT_LOG="uboot.log"

class SendHypercall(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        open(os.path.join(self.outdir, UBOOT_LOG), "w").close()
        self.uboot_log = set()

        self.ppp.Core.ppp_reg_cb('igloo_send_hypercall', self.on_send_hypercall)
        self.logger = getColoredLogger("plugins.send_hypercall")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        # Command-specific init

        ## U-Boot
        self.uboot_env = self.get_arg("conf").get("uboot_env", dict())

        ## Bash
        outdir = self.get_arg("outdir")
        path = os.path.join(outdir, "bash_cov.csv")
        self.bash_cov_csv = open(path, "w")
        csv.writer(self.bash_cov_csv).writerow(["filename", "lineno", "pid", "command"])
        self.bash_cov_csv.flush()

    def on_send_hypercall(self, cpu, buf_addr, buf_num_ptrs):
        arch_bytes = self.panda.bits // 8

        # Read list of pointers
        buf_addr = self.panda.arch.get_arg(cpu, 1)
        buf_num_ptrs = self.panda.arch.get_arg(cpu, 2)
        buf_size = buf_num_ptrs * arch_bytes
        buf = self.panda.virtual_memory_read(cpu, buf_addr, buf_size, fmt="bytearray")

        # Unpack list of pointers
        word_char = 'I' if arch_bytes == 4 else 'Q' 
        endianness = '>' if self.panda.arch_name in ["mips", "mips64eb"] else '<'
        ptrs = struct.unpack_from(f"{endianness}{buf_num_ptrs}{word_char}", buf)
        str_ptrs, out_addr = ptrs[:-1], ptrs[-1]

        # Read command and arg strings
        try:
            strs = [self.panda.read_str(cpu, ptr) for ptr in str_ptrs]
        except ValueError:
            self.logger.error(f"Failed to read guest memory. Skipping")
            return
        cmd, args = strs[0], strs[1:]

        # Simulate command
        f = getattr(self, f"cmd_{cmd}")
        if f is None:
            raise ValueError("Unknown send_hypercall command")
        try:
            ret_val, out_str = f(*args)
        except Exception as e:
            self.logger.error(f"Exception while processing {cmd}:")
            self.logger.exception(e)
            return

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
        self.logger.debug(f"fw_setenv {var}={val}")
        return 0, ""

    def cmd_fw_getenv(self, var):
        try:
            return 0, self.uboot_env[var]
        except KeyError:
            if var not in self.uboot_log:
                self.uboot_log.add(var)
                with open(os.path.join(self.outdir, UBOOT_LOG), "a") as f:
                    f.write(var + "\n")
            self.logger.debug(f"fw_getenv {var}")
            return 1, ""

    def cmd_fw_printenv(self, arg):
        raise NotImplementedError("fw_printenv shim unimplemented")

    def cmd_bash_command(self, cmd, path, lineno, pid):
        csv.writer(self.bash_cov_csv).writerow([path, lineno, pid, cmd])
        self.bash_cov_csv.flush()
        self.logger.debug(f"bash_command {path}:{lineno} {pid}: {cmd}")
        return 0, ""
