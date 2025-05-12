#!/usr/bin/env python3
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins

IFNAMSIZ = 16
SIOCGIFFLAGS = 0x8913
SIOCDEVPRIVATE = 0x89F0


class TestIoctlInteraction(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.ioctl_interaction_test")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.syscall_test = self.panda.hsyscall(
            "on_sys_ioctl_return")(self.syscall_test)

    @plugins.portal.wrap
    def syscall_test(self, cpu, proto, syscall, hook, fd, op, arg):
        if op == SIOCDEVPRIVATE:
            interface = yield from plugins.portal.read_str(arg)
            self.logger.info(f"Interface: {interface}")
            data = yield from plugins.portal.read_int(arg + IFNAMSIZ)
            self.logger.info(f"Data: {data:#x}")

            # we overwrite the interface name, read it back, and assert it matches
            to_write = "test"
            yield from plugins.portal.write_str(arg, to_write)
            interface = yield from plugins.portal.read_str(arg)

            assert interface == to_write, f"Expected {to_write}, got {interface}, r/w failed"

            # we overwrite the data, read it back, and assert it matches
            to_write_int = 0x12345678
            yield from plugins.portal.write_int(arg + IFNAMSIZ, to_write_int)
            data = yield from plugins.portal.read_int(arg + IFNAMSIZ)

            assert data == to_write_int, f"Expected {to_write_int:#x}, got {data:#x}, r/w failed"

            fd_name = yield from plugins.portal.get_fd_name(fd) or "[???]"
            self.logger.info(f"FD: {fd_name}")

            args = yield from plugins.portal.get_proc_args()
            self.logger.info(f"Found process: {args}")

            expected_args = [
                '/igloo/utils/test_ioctl_interaction', '0x89F0', 'eth0', '0x1338c0de']
            assert args == expected_args, f"Expected {expected_args}, got {args}"

            env = yield from plugins.portal.get_proc_env()
            self.logger.info(f"Found env: {env}")

            assert env[
                "PROJ_NAME"] == "test_target", f"Expected test_target, got {env['PROJ_NAME']}"

            pid = yield from plugins.portal.get_proc().pid
            self.logger.info(f"Found pid: {pid}")
            syscall.retval = 2
        elif op == 0x89f1:
            interface = yield from plugins.portal.read_str(arg)
            self.logger.info(f"Interface: {interface}")
            esw_reg_ptr = yield from plugins.portal.read_ptr(arg + IFNAMSIZ)
            off = yield from plugins.portal.read_int(esw_reg_ptr)
            self.logger.info(f"Code: {off:#x}")
            if off == 0x34:
                esw_reg_val = 0x12345678
                val_ptr = esw_reg_ptr+4

                # we overwrite the interface name, read it back, and assert it matches
                yield from plugins.portal.write_int(val_ptr, 0x12345678)
                val = yield from plugins.portal.read_int(val_ptr)
                assert val == esw_reg_val, f"Expected {esw_reg_val:#x}, got {val:#x}"
            syscall.retval = 1
