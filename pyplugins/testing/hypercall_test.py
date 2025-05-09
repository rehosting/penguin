"""
This plugin verifies that hypercalls are being made correctly.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger
from os.path import join

HYPERCALL_MAGIC = 0xcafebabe
HYPERCALL_ARG1 = 0xdeadbeeff1f1f1f1
HYPERCALL_ARG2 = 0x1337c0defeedc0de
HYPERCALL_ARG3 = 0xdeadbeeff1f1f1f2
HYPERCALL_ARG4 = 0x1337c0def2f2f2f2


class HypercallTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.portalercall_test")
        self.panda.hypercall(HYPERCALL_MAGIC)(self.hypercall_test)
        self.success = None
        self.reported = False

    def hypercall_test(self, cpu):
        if self.reported:
            return
        constants = [HYPERCALL_ARG1, HYPERCALL_ARG2,
                     HYPERCALL_ARG3, HYPERCALL_ARG4]
        success = True
        for i, constant in enumerate(constants):
            arg = self.panda.arch.get_arg(cpu, i + 1, convention="syscall")
            mask = 0xFFFFFFFFFFFFFFFF
            if self.panda.bits == 32:
                mask = 0xFFFFFFFF
            if arg != constant & mask:
                self.logger.error(
                    f"Hypercall test failed: arg{i + 1} = {arg:#x}, expected {constant:#x}")
                success = False

        self.panda.arch.set_retval(cpu, 13, convention="syscall")

        if success:
            self.success = success
            self.report()

    def report(self):
        if self.reported:
            return
        self.reported = True

        with open(join(self.outdir, "hypercall_test.txt"), "w") as f:
            result = "passed" if self.success else "failed"
            self.logger.info(f"Hypercall test: {result}")
            f.write(f"Hypercall test: {result}\n")

    def uninit(self):
        self.report()
