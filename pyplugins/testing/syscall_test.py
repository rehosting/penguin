"""
This plugin verifies that hypercalls are being made correctly.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger
from os.path import join

SYSCALL_ARG1 = 0x1338c0def2f2f3f2
SYSCALL_ARG2 = 0xdeadbeeff1f1f1f1
SYSCALL_ARG3 = 0x1337c0defeedc0de
SYSCALL_ARG4 = 0xdeedbeeff1f1f0f2
SYSCALL_ARG5 = 0xdeadbeeff1f1f1f2


class SyscallTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.syscall_test")
        self.panda.hsyscall("on_sys_clone_enter")(self.syscall_test)
        self.panda.hsyscall("on_sys_getpid_return")(self.getpid)
        self.success_clone = None
        self.success_getpid = None
        self.reported_clone = False
        self.reported_getpid = False

    def getpid(self, cpu, proto, syscall, hook, *args):
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if syscall.retval != proc.pid and syscall.retval != 0:
            self.logger.error(
                f"Syscall test failed: getpid returned {syscall.retval:#x}, expected {proc.pid:#x}")
            self.success_getpid = False
            self.report_getpid()
            return
        if "send_syscall" in self.panda.get_process_name(cpu):
            self.success_getpid = True
            self.report_getpid()

    def syscall_test(self, cpu, proto, syscall, hook, *args):
        if self.reported_clone:
            return
        if "send_syscall" not in self.panda.get_process_name(cpu):
            return
        self.logger.info(f"Syscall test: {syscall} {args}")
        constants = [SYSCALL_ARG1, SYSCALL_ARG2,
                     SYSCALL_ARG3, SYSCALL_ARG4,
                     SYSCALL_ARG5]
        success = True
        for i, constant in enumerate(constants):
            arg = args[i]
            mask = 0xFFFFFFFFFFFFFFFF
            if self.panda.bits == 32:
                mask = 0xFFFFFFFF
            if arg != constant & mask:
                self.logger.error(
                    f"Syscall test failed: arg{i + 1} = {arg:#x}, expected {constant:#x}")
                success = False
                break

        if not success:
            self.logger.error("Syscall test failed: args mismatch")
            return

        if self.panda.ffi.string(proto.name) != b"sys_clone":
            self.logger.error(
                "Syscall test failed: proto doesn't say sys_clone")
            return

        if success:
            syscall.retval = 42
            syscall.skip_syscall = True
            self.logger.info("Syscall test passed")
            self.success_clone = success
            self.report_clone()

    def report_clone(self):
        if self.reported_clone:
            return
        self.reported_clone = True

        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            if self.success_clone is None:
                self.logger.error("Syscall clone test: not run")
                f.write("Syscall clone test: no getpid calls\n")
                return
            result = "passed" if self.success_clone else "failed"
            self.logger.info(f"Syscall clone test: {result}")
            f.write(f"Syscall clone test: {result}\n")

    def report_getpid(self):
        if self.reported_getpid:
            return
        self.reported_getpid = True

        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            result = "passed" if self.success_getpid else "failed"
            self.logger.info(f"Syscall getpid test: {result}")
            f.write(f"Syscall getpid test: {result}\n")

    def uninit(self):
        self.report_clone()
        self.report_getpid()
