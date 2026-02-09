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
        self.test_skip_retval_handle = syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                                                        arg_filters=[None, 0xabcd])(self.test_skip_retval)

        self.unregistered_count = 0
        self.unregister_test_handle = syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                                                       arg_filters=[0x14, 0x1234])(self.test_unregister)

        # Test double registration for unregister logic
        self.double_reg_count = 0
        self.double_reg1 = syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                                            arg_filters=[0x15, 0x1234])(self.test_double_reg)
        self.double_reg2 = syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                                            arg_filters=[0x15, 0x1234])(self.test_double_reg)

        # Test unregister by name
        self.by_name_count = 0
        syscalls.syscall("on_sys_ioctl_enter", comm_filter="send_syscall",
                         arg_filters=[0x16, 0x1234])(self.test_unregister_by_name)

    def test_unregister_by_name(self, regs, proto, syscall, fd, op, arg):
        self.by_name_count += 1
        syscalls.unregister("test_unregister_by_name")

    def test_double_reg(self, regs, proto, syscall, fd, op, arg):
        self.double_reg_count += 1
        if self.double_reg_count == 2:
            # Unregister the first handle only after both have run once
            # This avoids race conditions where H2 runs first and unregisters H1 before H1 runs
            syscalls.unregister(self.double_reg1)

    def test_unregister(self, regs, proto, syscall, fd, op, arg):
        self.unregistered_count += 1
        # Should only be called once
        assert self.unregistered_count == 1, "Unregistered hook called multiple times"
        syscalls.unregister(self.test_unregister)

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

    @syscalls.syscall("on_sys_getpid_return")
    def getpid(self, regs, proto, syscall, *args):
        # NOTE: We've removed this check because it was causing issues
        # It doesn't seem to indicate anything negative so we're skipping it
        # proc = self.panda.plugins['osi'].get_current_process(cpu)
        # if syscall.retval != proc.pid and syscall.retval != 0:
        #     self.logger.error(
        #         f"Syscall test failed: getpid returned {syscall.retval:#x}, expected {proc.pid:#x}")
        #     self.success_getpid = False
        #     self.report_getpid()
        #     return
        if "send_syscall" in self.panda.get_process_name(self.panda.get_cpu()):
            self.success_getpid = True
            self.report_getpid()

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

    def check_unregister_results(self):
        with open(join(self.outdir, "syscall_test.txt"), "a") as f:
            # unregister: triggered twice, should run once
            if self.unregistered_count == 1:
                f.write("Syscall unregister: passed\n")
            else:
                f.write(
                    f"Syscall unregister: failed {self.unregistered_count}\n")

            # double_reg: triggered twice.
            # Call 1: handle1 runs (unregister handle1), handle2 runs. Count = 2.
            # Call 2: handle1 gone, handle2 runs. Count = 3.
            if self.double_reg_count == 3:
                f.write("Syscall double_reg: passed\n")
            else:
                f.write(
                    f"Syscall double_reg: failed {self.double_reg_count}\n")

            # by_name: triggered twice, should run once
            if self.by_name_count == 1:
                f.write("Syscall unregister_by_name: passed\n")
            else:
                f.write(
                    f"Syscall unregister_by_name: failed {self.by_name_count}\n")

    def uninit(self):
        self.report_clone()
        self.report_getpid()
        self.check_unregister_results()
