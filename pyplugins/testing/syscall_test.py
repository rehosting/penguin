"""
This plugin verifies that hypercalls are being made correctly.
"""

from penguin import plugins, Plugin
from os.path import join
from apis.syscalls import ValueFilter

SYSCALL_ARG1 = 0x1338c0def2f2f3f2
SYSCALL_ARG2 = 0xdeadbeeff1f1f1f1
SYSCALL_ARG3 = 0x1337c0defeedc0de
SYSCALL_ARG4 = 0xdeedbeeff1f1f0f2
SYSCALL_ARG5 = 0xdeadbeeff1f1f1f2

syscalls = plugins.syscalls


class SyscallTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.success_clone = None
        self.success_getpid = None
        self.reported_clone = False
        self.reported_getpid = False
        self.ioctl_ret_num = 0
        self.ioctl_ret2_num = 0
        self.ioctl_ret3_num = 0
        self.getpids = 0  # For unregister test
        self.hook_unregistered = False
        syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                         arg_filters=[None, 0xabcd])(self.test_skip_retval)
        self.getpid_hook = syscalls.syscall("on_sys_getpid_return")(self.getpid)

    def test_skip_retval(self, regs, proto, syscall, fd, op, arg):
        assert fd == 9, f"Expected fd 9, got {fd:#x}"
        assert op == 0xabcd, f"Expected op 0xabcd, got {op:#x}"
        syscall.skip_syscall = True
        syscall.retval = 43

    @syscalls.syscall("on_sys_ioctl_return", comm_filter="send_syscall",
                      arg_filters=[ValueFilter.exact(0x13)],
                      read_only=True)
    def ioctl_ret(self, regs, proto, syscall, fd, op, arg):
        self.ioctl_ret_num += 1
        assert fd == 0x13, f"Expected op 0x13, got {fd:#x}"
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            f.write(f"Syscall ioctl_reg: success {self.ioctl_ret_num}\n")

    @syscalls.syscall("on_sys_ioctl_return", comm_filter="send_syscall",
                      arg_filters=[0x13, 0x1234])
    def ioctl_ret2(self, regs, proto, syscall, fd, op, arg):
        self.ioctl_ret2_num += 1
        assert fd == 0x13, f"Expected fd 0x13, got {fd:#x}"
        assert op == 0x1234, f"Expected cmd 0x1234, got {op:#x}"
        assert self.ioctl_ret2_num <= 2, "ioctl_ret2 Called too many times"
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            f.write(f"Syscall ioctl_reg2: success {self.ioctl_ret2_num}\n")

    @syscalls.syscall("on_sys_ioctl_return", comm_filter="send_syscall",
                      arg_filters=[0x13,
                                   ValueFilter.range(0x1234, 0x1235), 0xabcd])
    def ioctl_ret3(self, regs, proto, syscall, fd, op, arg):
        self.ioctl_ret3_num += 1
        assert fd == 0x13, f"Expected fd 0x13, got {fd:#x}"
        assert op == 0x1234, f"Expected op 0x1234, got {op:#x}"
        assert arg == 0xabcd, f"Expected arg 0xabcd, got {arg:#x}"
        assert self.ioctl_ret3_num <= 3, "ioctl_ret3 Called too many times"
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            f.write(f"Syscall ioctl_reg3: success {self.ioctl_ret3_num}\n")

    @syscalls.syscall("on_sys_ioctl_return", comm_filter="nosend_syscall",
                      arg_filters=[None, ValueFilter.bitmask_set(0x1234)])
    def ioctl_noret(self, regs, proto, syscall, fd, op, arg):
        # this shouldn't be called
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            f.write("Syscall ioctl_noret: failure\n")

    def getpid(self, regs, proto, syscall, *args):
        if "send_syscall" in self.panda.get_process_name(self.panda.get_cpu()):
            self.success_getpid = True
            self.report_getpid()

            if not self.hook_unregistered:
                result = plugins.syscalls.unregister_syscall_hook(self.getpid)

                if not result:
                    self.logger.error("Failed to unregister getpid hook!")

                self.hook_unregistered = True
            self.getpids += 1

    @syscalls.syscall("on_sys_clone_enter")
    def syscall_test(self, regs, proto, syscall, *args):
        if self.reported_clone:
            return
        if "send_syscall" not in self.panda.get_process_name(
                self.panda.get_cpu()):
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

        if proto.name != "sys_clone":
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

    def report_unregister(self):
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            result = "passed" if self.getpids == 1 else "failed"
            self.logger.info(f"Syscall unregister test: {result} (getpid hook called {self.getpids} times)")
            f.write(f"Syscall unregister test: {result}\n")

    def uninit(self):
        self.report_clone()
        self.report_getpid()
        self.report_unregister()
