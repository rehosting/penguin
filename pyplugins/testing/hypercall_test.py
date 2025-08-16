"""
This plugin verifies that hypercalls are being made correctly.
"""

from penguin import Plugin
from os.path import join

HYPERCALL_MAGIC = 0xcafebabe
HYPERCALL_MAGIC_32B = 0xcafebab3
HYPERCALL_ARG1 = 0xdeadbeeff1f1f1f1
HYPERCALL_ARG2 = 0x1337c0defeedc0de
HYPERCALL_ARG3 = 0xdeadbeeff1f1f1f2
HYPERCALL_ARG4 = 0x1337c0def2f2f2f2


class HypercallTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.panda.hypercall(HYPERCALL_MAGIC)(self.hypercall_test)
        self.panda.hypercall(HYPERCALL_MAGIC_32B)(self.hypercall_test_32b)
        self.reported = False
        self.reported_32b = False

    def hypercall_test_32b(self, cpu):
        if self.reported_32b:
            return
        constants = [HYPERCALL_ARG1, HYPERCALL_ARG2,
                     HYPERCALL_ARG3, HYPERCALL_ARG4]
        success = True
        for i, constant in enumerate(constants):
            arg = self.panda.arch.get_arg(cpu, i + 1, convention="syscall")
            mask = 0xFFFFFFFF
            if arg != constant & mask:
                self.logger.error(
                    f"Hypercall test failed: arg{i + 1} = {arg:#x}, expected {constant:#x}")
                success = False

        self.panda.arch.set_retval(cpu, 13, convention="syscall")

        if success:
            self.report_32b(success)

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
            self.report(success)

    def report(self, result):
        if self.reported:
            return
        self.reported = True

        with open(join(self.outdir, "hypercall_test.txt"), "w") as f:
            res = "passed" if result else "failed"
            self.logger.info(f"Hypercall test: {res}")
            f.write(f"Hypercall test: {res}\n")

    def report_32b(self, result):
        if self.reported_32b:
            return
        self.reported_32b = True

        with open(join(self.outdir, "hypercall_test.txt"), "a") as f:
            res = "passed" if result else "failed"
            self.logger.info(f"Hypercall test 32b: {res}")
            f.write(f"Hypercall test 32b: {res}\n")

    def uninit(self):
        self.report(False)
        self.report_32b(False)
