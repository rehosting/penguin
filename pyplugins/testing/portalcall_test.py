"""
This plugin verifies that portalcalls are being made correctly.
"""

from penguin import Plugin, plugins
from os.path import join

PORTALCALL_MAGIC = 0xcafebabe
PORTALCALL_MAGIC_32B = 0xcafebab3
PORTALCALL_ARG1 = 0xdeadbeeff1f1f1f1
PORTALCALL_ARG2 = 0x1337c0defeedc0de
PORTALCALL_ARG3 = 0xdeadbeeff1f1f1f2
PORTALCALL_ARG4 = 0x1337c0def2f2f2f2


class PortalcallTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.reported = False
        self.reported_32b = False

    @plugins.portalcall.portalcall(PORTALCALL_MAGIC_32B)
    def portalcall_test_32b(self, a1, a2, a3, a4):
        if self.reported_32b:
            return
        constants = [PORTALCALL_ARG1, PORTALCALL_ARG2,
                     PORTALCALL_ARG3, PORTALCALL_ARG4]
        values = [a1, a2, a3, a4]
        success = True
        for i, constant in enumerate(constants):
            arg = values[i]
            if arg != constant:
                self.logger.error(
                    f"PORTALCALL test failed: arg{i + 1} = {arg:#x}, expected {constant:#x}")
                success = False

        if success:
            self.report_32b(success)
        return 13

    @plugins.portalcall.portalcall(PORTALCALL_MAGIC)
    def portalcall_test(self, a1, a2, a3, a4):
        if self.reported:
            return
        constants = [PORTALCALL_ARG1, PORTALCALL_ARG2,
                     PORTALCALL_ARG3, PORTALCALL_ARG4]
        values = [a1, a2, a3, a4]
        success = True
        for i, constant in enumerate(constants):
            arg = values[i]
            if arg != constant:
                self.logger.error(
                    f"PORTALCALL test failed: arg{i + 1} = {arg:#x}, expected {constant:#x}")
                success = False

        if success:
            self.report(success)
        return 13

    def report(self, result):
        if self.reported:
            return
        self.reported = True

        with open(join(self.outdir, "portalcall_test.txt"), "w") as f:
            res = "passed" if result else "failed"
            self.logger.info(f"PORTALCALL test: {res}")
            f.write(f"PORTALCALL test: {res}\n")

    def report_32b(self, result):
        if self.reported_32b:
            return
        self.reported_32b = True

        with open(join(self.outdir, "portalcall_test.txt"), "a") as f:
            res = "passed" if result else "failed"
            self.logger.info(f"PORTALCALL test 32b: {res}")
            f.write(f"PORTALCALL test 32b: {res}\n")

    def uninit(self):
        self.report(False)
        self.report_32b(False)
