#!/usr/bin/env python3
from penguin import Plugin, plugins

kffi = plugins.kffi
portal = plugins.portal


class KFFITest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        plugins.syscalls.syscall(
            "on_sys_ioctl_return", arg_filters=[0x14, 0x15, 0x16])(self.kffi)

    @plugins.portal.wrap
    def kffi(self, cpu, proto, syscall, fd, op, arg):
        args = [3, 8, 9, 0x1338c0de, 12, 13, 14, 15]
        val = yield from kffi.call_kernel_function("igloo_test_function", *args)
        assert val == sum(args), f"Expected {sum(args)}, got {val}, r/w failed"

        buf = yield from kffi.kmalloc(100)
        level = b"\x01\x03"
        yield from portal.write_bytes(buf, level + b"test printk %d %d %d %d\x00")

        yield from kffi.call_kernel_function("igloo_printk", buf, 1, 2, 3, 4)

        yield from kffi.kfree(buf)
