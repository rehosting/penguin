"""
This plugin verifies that hypercalls are being made correctly.
"""

from penguin import Plugin, plugins
from os.path import join, realpath, basename
from glob import glob
import functools

kprobes = plugins.kprobes
mem = plugins.mem
osi = plugins.osi


class KprobesTest(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

    @kprobes.kprobe(
        symbol="do_execveat_common",
        on_enter=True,
    )
    def do_execvat_common(self, pt_regs):
        """
        static int do_execveat_common(int fd, struct filename *filename,
            struct user_arg_ptr argv,
            struct user_arg_ptr envp,
            int flags)
        """
        args = pt_regs.get_args(5)
        struct_filename = yield from plugins.kffi.read_type(args[1], "struct filename")
        filename = yield from plugins.mem.read_str(struct_filename.name.address)
        if "/tests/kprobes_test.sh" in filename:
            with open(join(self.outdir, "kprobe_exec_test.txt"), "w") as f:
                f.write(
                    f"kprobe exec entry test passed: do_execveat_common called with filename={filename}\n"
                )
