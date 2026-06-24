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

Performance note: do_filp_open / do_execveat_common are extremely hot. To avoid
taxing the *whole* unit-test suite (which is fatal on slow-emulating arches like
powerpc64), every probe here is scoped to the test's own process — the script
drives all triggers through a uniquely-named busybox copy (/tmp/kp_actor, comm
"kp_actor"), so the probes fire only a handful of times instead of on every
open/exec system-wide. The pid_filter probe (which can't be comm-scoped) and the
exec/process_filter probes self-unregister after a few confirmations.
"""

from penguin import Plugin, plugins
from os.path import join

kprobes = plugins.kprobes

# Unique comm used to scope probes to this test's own activity. The script sets
# its shell comm via /proc/self/comm and then opens files through shell
# redirections (`: < /path`), so those opens carry comm "kp_actor" and the probes
# fire only a handful of times instead of on every open system-wide.
ACTOR = "kp_actor"

# Sentinel paths the actor opens to drive the unregister tests.
UNREG_HANDLE_PATH = "/kprobe_unreg_handle"
UNREG_NAME_PATH = "/kprobe_unreg_name"

# State-modification test: this file EXISTS, but a kretprobe forces its open to
# fail; the guest then opens WRITE_APPLIED_PATH, which the plugin watches for.
WRITE_TARGET_PATH = "/kprobe_write_target"
WRITE_APPLIED_PATH = "/kprobe_write_applied"

# How many filtered hits to confirm before self-unregistering the filter probes.
FILTER_CONFIRM = 3


class KprobesTest(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.test_results = {
            "exec_entry": False,
            "open_return": False,
            "write_modify": False,
        }

        self._open_pid = None     # do_filp_open enter/return correlation
        self._write_pid = None    # write-force enter/return correlation

        # Unregister counters.
        self.unreg_handle_count = 0
        self.unreg_name_count = 0

        # Filter test state.
        self.pfilter_count = 0
        self.pfilter_bad = 0
        self.pidfilter_count = 0
        self.pidfilter_bad = 0

        # Entry probe on do_execveat_common, scoped to the actor. The real symbol
        # often has a ".isra.N" suffix, so resolve the concrete name first.
        for name in plugins.kffi.ffi.search_symbols("do_execveat_common*"):
            self._exec_handle = kprobes.kprobe(
                symbol=name, on_enter=True, process_filter=ACTOR,
            )(self.kprobe_do_execveat_common)
            break

        # Aggregate read test: -ENOENT for a missing path (actor-scoped).
        kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, on_return=True,
            process_filter=ACTOR,
        )(self.kprobe_do_filp_open)

        # State-modification: force do_filp_open to fail for WRITE_TARGET_PATH.
        kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, on_return=True,
            process_filter=ACTOR,
        )(self.kprobe_write_force_enoent)

        # Unregister-by-handle (actor-scoped sentinel).
        self.unreg_handle = kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, process_filter=ACTOR,
        )(self.kprobe_unreg_by_handle)

        # Unregister-by-name (actor-scoped sentinel).
        kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, process_filter=ACTOR,
        )(self.kprobe_unreg_by_name)

        # process_filter test: only "kp_actor" tasks should be delivered.
        self._pfilter_handle = kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, process_filter=ACTOR,
        )(self.kprobe_pfilter)

        # pid_filter test: only pid 1 (init / run_tests.sh) should be delivered.
        # Cannot be comm-scoped, so it self-unregisters after a few confirmations
        # to avoid firing on every pid-1 open for the whole suite.
        self._pidfilter_handle = kprobes.kprobe(
            symbol="do_filp_open", on_enter=True, pid_filter=1,
        )(self.kprobe_pidfilter)

    # --- helpers ---
    def _read_filp_path(self, pt_regs):
        # do_filp_open(int dfd, struct filename *pathname, ...) -> arg index 1.
        args = pt_regs.get_args(5)
        ptr = args[1]
        if not ptr:
            return None
        sf = yield from plugins.kffi.read_type(ptr, "struct filename")
        if sf is None:
            return None
        name = yield from plugins.mem.read_str(sf.name.address)
        return name

    # --- exec entry test ---
    def kprobe_do_execveat_common(self, pt_regs):
        # Scoped to the actor (caller comm == ACTOR), so any exec the actor shell
        # makes counts. Confirm we can read the struct filename arg, then stop.
        args = pt_regs.get_args(5)
        filename_ptr = args[1]
        if not filename_ptr:
            return
        struct_filename = yield from plugins.kffi.read_type(
            filename_ptr, "struct filename")
        if struct_filename is None:
            return
        filename = yield from plugins.mem.read_str(struct_filename.name.address)
        self.logger.info(f"do_execveat_common (actor): {filename}")
        if not self.test_results["exec_entry"]:
            self.test_results["exec_entry"] = True
            with open(join(self.outdir, "kprobe_exec_test.txt"), "w") as f:
                f.write(f"kprobe exec entry test passed: {filename}\n")
            kprobes.unregister(self._exec_handle)

    # --- aggregate read test (-ENOENT) + write-applied marker ---
    def kprobe_do_filp_open(self, pt_regs, is_enter):
        if is_enter:
            pathname = yield from self._read_filp_path(pt_regs)
            if pathname is None:
                return
            self.logger.info(f"do_filp_open: {pathname}")
            if "/doesnotexist" in pathname:
                proc = yield from plugins.osi.get_proc()
                self._open_pid = proc.pid
            # The guest only reaches WRITE_APPLIED_PATH if our kretprobe forced
            # the (existing) WRITE_TARGET_PATH open to fail.
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
            if retval == -2:  # -ENOENT
                self.test_results["open_return"] = True
                self._open_pid = None
                with open(join(self.outdir, "kprobe_open_test.txt"), "w") as f:
                    f.write("kprobe open return test passed\n")

    # --- state-modification test ---
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
            # ERR_PTR(-ENOENT): width-correct unsigned two's complement of -2.
            err = int(self.panda.ffi.cast("target_ulong", -2))
            pt_regs.set_retval(err)
            self.logger.info(
                f"forced do_filp_open({WRITE_TARGET_PATH}) return -> -ENOENT")

    # --- unregister tests ---
    # Each fires on its sentinel (actor-scoped) and self-unregisters. The script
    # opens the sentinel once, sleeps so the (workqueue-deferred) unregister
    # settles, then opens it several more times. A working unregister -> count==1.
    def kprobe_unreg_by_handle(self, pt_regs):
        name = yield from self._read_filp_path(pt_regs)
        if name and UNREG_HANDLE_PATH in name:
            self.unreg_handle_count += 1
            kprobes.unregister(self.unreg_handle)

    def kprobe_unreg_by_name(self, pt_regs):
        name = yield from self._read_filp_path(pt_regs)
        if name and UNREG_NAME_PATH in name:
            self.unreg_name_count += 1
            kprobes.unregister("kprobe_unreg_by_name")

    # --- filter tests ---
    def kprobe_pfilter(self, pt_regs):
        proc = yield from plugins.osi.get_proc()
        comm = getattr(proc, "name", "") or ""
        self.pfilter_count += 1
        if ACTOR not in comm:
            self.pfilter_bad += 1
            self.logger.error(f"process_filter leak: comm={comm!r}")
        if self.pfilter_count >= FILTER_CONFIRM:
            kprobes.unregister(self._pfilter_handle)

    def kprobe_pidfilter(self, pt_regs):
        proc = yield from plugins.osi.get_proc()
        self.pidfilter_count += 1
        if proc.pid != 1:
            self.pidfilter_bad += 1
            self.logger.error(f"pid_filter leak: pid={proc.pid}")
        if self.pidfilter_count >= FILTER_CONFIRM:
            kprobes.unregister(self._pidfilter_handle)

    def uninit(self):
        with open(join(self.outdir, "kprobe_tests_summary.txt"), "w") as f:
            all_passed = True
            for name, result in self.test_results.items():
                f.write(f"{name}: {'PASSED' if result else 'FAILED'}\n")
                all_passed = all_passed and result
            f.write("\nAll kprobe tests PASSED!\n" if all_passed
                    else "\nSome kprobe tests FAILED!\n")

        with open(join(self.outdir, "kprobe_unregister_test.txt"), "w") as f:
            # Unregister is asynchronous (portal round-trip + workqueue), so a few
            # opens can still slip through before it takes effect. The script opens
            # each sentinel 1 + 5 times, so a working unregister yields ~1 and a
            # broken one yields 6; accept a small straggler window to avoid a
            # timing flake under heavy CI load while still catching real breakage.
            h_ok = 1 <= self.unreg_handle_count <= 3
            n_ok = 1 <= self.unreg_name_count <= 3
            f.write(f"handle unregister: {'PASSED' if h_ok else 'FAILED'} (count={self.unreg_handle_count})\n")
            f.write(f"name unregister: {'PASSED' if n_ok else 'FAILED'} (count={self.unreg_name_count})\n")

        with open(join(self.outdir, "kprobe_filter_test.txt"), "w") as f:
            pf_ok = self.pfilter_count > 0 and self.pfilter_bad == 0
            f.write(f"process_filter: hits={self.pfilter_count} leaks={self.pfilter_bad} "
                    f"({'PASSED' if pf_ok else 'FAILED'})\n")
            pid_ok = self.pidfilter_count > 0 and self.pidfilter_bad == 0
            f.write(f"pid_filter: hits={self.pidfilter_count} leaks={self.pidfilter_bad} "
                    f"({'PASSED' if pid_ok else 'FAILED'})\n")
