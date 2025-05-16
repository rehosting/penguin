"""
This plugin verifies that hypercalls are being made correctly.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from os.path import join

uprobes = plugins.uprobes
portal = plugins.portal

class UprobeTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.syscall_test")
        malloc_offset = 428476
        # _IO_puts: 360288
        puts_offset = 360288
        uprobes.uretprobe("*libc-*", "malloc")(self.uprobe_malloc)
        self.done_once = False
    
    # def syscall_test(self, *args):
        # if not self.done_once:
            # self.done_once = True

    @portal.wrap
    def uprobe_malloc(self, pt_regs):
        retval = pt_regs.get_retval()
        m = yield from portal.get_mapping_by_addr(retval)
        breakpoint()
        print("asdf")