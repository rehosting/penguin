"""
This plugin verifies that hypercalls are being made correctly.
"""

from penguin import Plugin, plugins
from os.path import join

kprobes = plugins.kprobes
mem = plugins.mem
osi = plugins.osi


class KprobesTest(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.open_ret_pid = None

        # names can be like `do_execveat_common.isra.15`
        for sym in plugins.kffi.ffi.search_symbols("do_execveat_common"):
            if sym.name.startswith("do_execveat_common"):
                plugins.kprobes.kprobe(symbol=sym.name, on_enter=True, on_return=False)(self.kprobe_do_execvat_common)
                break

    def kprobe_do_execvat_common(self, pt_regs):
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

    # This tests aggregate probes as well as kretprobes
    @kprobes.kprobe(
        symbol="do_filp_open",
        on_enter=True,
        on_return=True,
    )
    def kprobe_do_filp_open(self, pt_regs):
        """
        extern struct file *do_filp_open(int dfd, struct filename *pathname,
        const struct open_flags *op);
        """
        current = yield from plugins.osi.get_proc()
        if not pt_regs.is_enter:
            if self.open_ret_pid == current.pid:
                rval = int(self.panda.ffi.cast("target_long", pt_regs.get_return_value()))
                if rval == -2:  # -ENOENT
                    with open(join(self.outdir, "kprobe_open_test.txt"), "w") as f:
                        f.write(
                            f"kprobe open return test passed: do_filp_open called with pathname={self.filp_open_pathname} and rval={rval}\n"
                        )
                else:
                    self.logger.error(f"do_filp_open returned unexpected value: {rval}, expected -2 (-ENOENT) for /doesnotexist")
        else:
            struct_filename = yield from plugins.kffi.read_type(pt_regs.get_args(5)[1], "struct filename")
            pathname = yield from plugins.mem.read_str(struct_filename.name.address)
            if pt_regs.is_enter and "/doesnotexist" in pathname:
                self.filp_open_pathname = pathname
                self.open_ret_pid = current.pid
