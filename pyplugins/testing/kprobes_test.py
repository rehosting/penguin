"""
This plugin verifies that kernel-space kprobes are being made correctly.

Coverage:
  * entry kprobe on do_execveat_common (symbol-suffix resolution via search_symbols)
  * aggregate entry+return kprobe (kretprobe) on do_filp_open (-ENOENT return)
  * unregister by wrapper handle and by function name (probe must fire exactly once)
  * process_filter and pid_filter (only matching tasks are delivered to the handler)
  * state modification: a kretprobe rewrites do_filp_open's return value to
    ERR_PTR(-ENOENT) for an existing file, and the guest's control flow branches
    on the (now-failed) open — proving the guest acts on the modified register.
"""

from penguin import Plugin, plugins
from os.path import join

kprobes = plugins.kprobes
mem = plugins.mem
osi = plugins.osi

# Sentinel paths the test script opens to drive the unregister tests.
UNREG_HANDLE_PATH = "/kprobe_unreg_handle"
UNREG_NAME_PATH = "/kprobe_unreg_name"

# State-modification test: this file EXISTS, but a kretprobe forces its open to
# fail; the guest then opens WRITE_APPLIED_PATH, which the plugin watches for.
WRITE_TARGET_PATH = "/kprobe_write_target"
WRITE_APPLIED_PATH = "/kprobe_write_applied"


class KprobesTest(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.test_results = {
            "exec_entry": False,
            "open_return": False,
            "write_modify": False,
        }

        # State shared between do_filp_open enter and return.
        self._open_pid = None
        # State for the write/state-modification test.
        self._write_pid = None

        # --- Unregister test state ---
        self.unreg_handle_count = 0
        self.unreg_name_count = 0

        # --- Filter test state ---
        # process_filter: every delivered hit must have comm == "busybox".
        self.pfilter_count = 0
        self.pfilter_bad = 0
        # pid_filter: every delivered hit must have pid == 1 (init / run_tests.sh).
        self.pidfilter_count = 0
        self.pidfilter_bad = 0

        # Entry probe on do_execveat_common. The real kernel symbol often has a
        # compiler-generated suffix (e.g. ".isra.N"), so resolve it at init time
        # via kallsyms/symbol search and register on the concrete name.
        for name in plugins.kffi.ffi.search_symbols("do_execveat_common*"):
            kprobes.kprobe(
                symbol=name,
                on_enter=True,
                on_return=False,
            )(self.kprobe_do_execveat_common)
            break

        # Unregister-by-handle: keep the returned wrapper so we can unregister it.
        self.unreg_handle = kprobes.kprobe(
            symbol="do_filp_open",
            on_enter=True,
            process_filter="busybox",
        )(self.kprobe_unreg_by_handle)

        # Unregister-by-name: unregister via the handler's function name string.
        kprobes.kprobe(
            symbol="do_filp_open",
            on_enter=True,
            process_filter="busybox",
        )(self.kprobe_unreg_by_name)

        # process_filter: only "busybox" tasks should be delivered.
        kprobes.kprobe(
            symbol="do_filp_open",
            on_enter=True,
            process_filter="busybox",
        )(self.kprobe_pfilter)

        # pid_filter: only pid 1 (init / run_tests.sh) should be delivered.
        kprobes.kprobe(
            symbol="do_filp_open",
            on_enter=True,
            pid_filter=1,
        )(self.kprobe_pidfilter)

        # State-modification: force do_filp_open to fail for WRITE_TARGET_PATH by
        # rewriting its return value in the kretprobe.
        kprobes.kprobe(
            symbol="do_filp_open",
            on_enter=True,
            on_return=True,
        )(self.kprobe_write_force_enoent)

    def kprobe_do_execveat_common(self, pt_regs):
        # do_execveat_common(int fd, struct filename *filename, ...)
        # arg index 1 is the struct filename *.
        args = pt_regs.get_args(5)
        filename_ptr = args[1]
        if not filename_ptr:
            return

        struct_filename = yield from plugins.kffi.read_type(
            filename_ptr, "struct filename")
        if struct_filename is None:
            return

        filename = yield from plugins.mem.read_str(struct_filename.name.address)
        self.logger.info(f"do_execveat_common: {filename}")

        if "/tests/kprobes_test.sh" in filename:
            self.test_results["exec_entry"] = True
            with open(join(self.outdir, "kprobe_exec_test.txt"), "w") as f:
                f.write("kprobe exec entry test passed\n")

    @plugins.kprobes.kprobe(
        symbol="do_filp_open",
        on_enter=True,
        on_return=True,
    )
    def kprobe_do_filp_open(self, pt_regs, is_enter):
        # do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
        if is_enter:
            args = pt_regs.get_args(5)
            pathname_ptr = args[1]
            if not pathname_ptr:
                return

            struct_filename = yield from plugins.kffi.read_type(
                pathname_ptr, "struct filename")
            if struct_filename is None:
                return

            pathname = yield from plugins.mem.read_str(
                struct_filename.name.address)
            self.logger.info(f"do_filp_open: {pathname}")

            if "/doesnotexist" in pathname:
                proc = yield from plugins.osi.get_proc()
                self._open_pid = proc.pid

            # The guest only reaches WRITE_APPLIED_PATH if our kretprobe forced
            # the (existing) WRITE_TARGET_PATH open to fail — i.e. the state
            # modification took effect and the guest acted on it.
            if WRITE_APPLIED_PATH in pathname and not self.test_results["write_modify"]:
                self.test_results["write_modify"] = True
                with open(join(self.outdir, "kprobe_write_test.txt"), "w") as f:
                    f.write("kprobe write test passed: forced open failure observed by guest\n")
        else:
            if self._open_pid is None:
                return

            proc = yield from plugins.osi.get_proc()
            if proc.pid != self._open_pid:
                return

            retval = int(self.panda.ffi.cast(
                "target_long", pt_regs.get_return_value()))
            self.logger.info(f"do_filp_open returned {retval}")

            # -ENOENT == -2 for a missing path.
            if retval == -2:
                self.test_results["open_return"] = True
                self._open_pid = None
                with open(join(self.outdir, "kprobe_open_test.txt"), "w") as f:
                    f.write("kprobe open return test passed\n")

    # --- State-modification test ---
    # WRITE_TARGET_PATH exists, so its open normally succeeds. On enter we record
    # the opening task; on return we overwrite the return register with
    # ERR_PTR(-ENOENT) so the kernel hands -ENOENT back to userspace. The guest
    # script branches on the failed open and opens WRITE_APPLIED_PATH, which the
    # do_filp_open enter handler above watches for.

    def kprobe_write_force_enoent(self, pt_regs, is_enter):
        if is_enter:
            name = yield from self._read_filp_path(pt_regs)
            if name and WRITE_TARGET_PATH in name:
                proc = yield from plugins.osi.get_proc()
                self._write_pid = proc.pid
        else:
            if self._write_pid is None:
                return
            proc = yield from plugins.osi.get_proc()
            if proc.pid != self._write_pid:
                return
            self._write_pid = None
            # ERR_PTR(-ENOENT): width-correct unsigned two's complement of -2
            # (0xFFFFFFFE on 32-bit, 0xFFFF...FE on 64-bit). The wrapper writes
            # it into the return register and _kprobe_event pushes pt_regs back
            # to the guest, so the kretprobe trampoline restores the new value.
            err = int(self.panda.ffi.cast("target_ulong", -2))
            pt_regs.set_retval(err)
            self.logger.info(
                f"forced do_filp_open({WRITE_TARGET_PATH}) return -> -ENOENT")

    # --- Unregister tests ---
    # Each fires on a unique sentinel path, counts the hit, then unregisters
    # itself. The test script opens the sentinel once, sleeps so the (async,
    # workqueue-deferred) unregister settles, then opens it several more times.
    # A working unregister means the probe fired exactly once.

    def _read_filp_path(self, pt_regs):
        args = pt_regs.get_args(5)
        ptr = args[1]
        if not ptr:
            return None
        sf = yield from plugins.kffi.read_type(ptr, "struct filename")
        if sf is None:
            return None
        name = yield from plugins.mem.read_str(sf.name.address)
        return name

    def kprobe_unreg_by_handle(self, pt_regs):
        name = yield from self._read_filp_path(pt_regs)
        if name and UNREG_HANDLE_PATH in name:
            self.unreg_handle_count += 1
            self.logger.info(f"unreg_by_handle hit #{self.unreg_handle_count}")
            kprobes.unregister(self.unreg_handle)

    def kprobe_unreg_by_name(self, pt_regs):
        name = yield from self._read_filp_path(pt_regs)
        if name and UNREG_NAME_PATH in name:
            self.unreg_name_count += 1
            self.logger.info(f"unreg_by_name hit #{self.unreg_name_count}")
            kprobes.unregister("kprobe_unreg_by_name")

    # --- Filter tests ---

    def kprobe_pfilter(self, pt_regs):
        proc = yield from plugins.osi.get_proc()
        comm = getattr(proc, "name", "") or ""
        self.pfilter_count += 1
        # The kernel comm filter is a prefix-bounded TASK_COMM_LEN compare; the
        # delivered task's comm must be "busybox".
        if "busybox" not in comm:
            self.pfilter_bad += 1
            self.logger.error(f"process_filter leak: comm={comm!r}")

    def kprobe_pidfilter(self, pt_regs):
        proc = yield from plugins.osi.get_proc()
        self.pidfilter_count += 1
        if proc.pid != 1:
            self.pidfilter_bad += 1
            self.logger.error(f"pid_filter leak: pid={proc.pid}")

    def uninit(self):
        """Write a summary of all test results to a file when the plugin is unloaded"""
        with open(join(self.outdir, "kprobe_tests_summary.txt"), "w") as f:
            all_passed = True
            for name, result in self.test_results.items():
                status = "PASSED" if result else "FAILED"
                f.write(f"{name}: {status}\n")
                if not result:
                    all_passed = False

            if all_passed:
                f.write("\nAll kprobe tests PASSED!\n")
            else:
                f.write("\nSome kprobe tests FAILED!\n")

        # Unregister results: probe must have fired exactly once.
        with open(join(self.outdir, "kprobe_unregister_test.txt"), "w") as f:
            f.write(
                f"handle count: {self.unreg_handle_count} "
                f"({'PASSED' if self.unreg_handle_count == 1 else 'FAILED'})\n")
            f.write(
                f"name count: {self.unreg_name_count} "
                f"({'PASSED' if self.unreg_name_count == 1 else 'FAILED'})\n")

        # Filter results: hits were delivered and none leaked from a
        # non-matching task.
        with open(join(self.outdir, "kprobe_filter_test.txt"), "w") as f:
            pf_ok = self.pfilter_count > 0 and self.pfilter_bad == 0
            f.write(
                f"process_filter: hits={self.pfilter_count} leaks={self.pfilter_bad} "
                f"({'PASSED' if pf_ok else 'FAILED'})\n")
            pid_ok = self.pidfilter_count > 0 and self.pidfilter_bad == 0
            f.write(
                f"pid_filter: hits={self.pidfilter_count} leaks={self.pidfilter_bad} "
                f"({'PASSED' if pid_ok else 'FAILED'})\n")
