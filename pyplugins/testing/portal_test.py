#!/usr/bin/env python3
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins

class PortalTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.ioctl_interaction_test")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.panda.hsyscall(
            "on_sys_ioctl_return",arg_filter=[None, 0x89f3])(self.ioctl_val)

    @plugins.portal.wrap
    def ioctl_val(self, cpu, proto, syscall, hook, fd, op, arg):
        callstack = []

        current_proc =None

        while True:
            p = yield from plugins.portal.get_proc(pid=current_proc)
            if not p:
                break
            args = yield from plugins.portal.get_proc_args(pid=p.pid)
            callstack.insert(0, args)
            current_proc = p.ppid
            if p.pid == 1:
                break
        
        expected_callstack = [
            ['/igloo/utils/sh', '/run_tests.sh'], 
            ['/igloo/utils/sh', '/tests/portal.sh'], 
            ['/igloo/utils/send_syscall', 'ioctl', '0x0', '0x89f3']
            ]
        assert callstack == expected_callstack, f"Expected {expected_callstack}, got {callstack}"
        
        test = yield from plugins.portal.read_file("/tmp/portal_test")
        expected = b"test read value\n"
        assert test == expected, f"Expected '{expected}', got {test}"

        # Test process mapping functionality
        maps = yield from plugins.portal.get_proc_mappings()
        self.logger.info(f"Found {len(maps)} mappings total")

        omaps = maps.get_mappings_by_name("send_syscall")

        for m in omaps:
            a = maps.get_mapping_by_addr(m.start)
            b = maps.get_mapping_by_addr(m.start + 1)
            c = maps.get_mapping_by_addr(m.end)

            assert a == b == c == m, f"Expected {m}, got {a}, {b}, {c}"
        
        breakpoint()
