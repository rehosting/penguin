"""Measure the RAM term of a fastsnap reset on a real firmware target.

DESIGN-fastsnap.md prices a reset as (dirty pages x 0.42 us) + device block.
Every dirty-page count in it came from a synthetic payload that touches 65
pages. This measures the real one, on a booted firmware, with no rebuild:
every symbol needed is already exported by the shipped QEMU library.

    nm -D libqemu-system-armel.so | grep physical_memory_test_and_clear_dirty

physical_memory_test_and_clear_dirty() *returns* the number of dirty pages and
clears them, so one call per window is the whole instrument.

Two controls, because a dirty-page count of zero and a probe that never armed
produce identical output:

  ARM control      -- the return value of memory_global_dirty_log_start().
  POSITIVE control -- after arming and clearing, write a byte to guest memory
                      from the host and confirm the next sample sees >= 1 page.
                      Without this, "the guest dirties nothing" is unfalsifiable.

Sampling runs on a syscall-return hook, so it is on the vCPU thread with the
BQL held; calling these from a Python timer thread would be a data race.

NOTE ON LOCKING: penguin's Readiness callback does NOT run with the BQL held.
Assuming it did produced
    memory_region_transaction_commit: Assertion `bql_locked()' failed
and killed the VM. Every call below therefore takes the BQL explicitly through
bql_lock_impl()/bql_unlock(), guarded by bql_locked() because QEMU's BQL is not
recursive. Do not assume a pyplugin callback holds it -- check.

NOTE ON COST: test_and_clear_dirty is O(total RAM) -- one atomic per page, so
~20 ms for a 2G guest. That stall is inside the measured window's boundary, not
inside the window, but it does perturb a long run. It is also exactly why
DESIGN-fastsnap.md specifies a word-wise sweep for the real thing.

Args: windows_ms (list), samples_per_window (int), outdir
"""

import ctypes
import json
import os
import re
import statistics
import time

from penguin import Plugin, plugins

DIRTY_MEMORY_MIGRATION = 2
GLOBAL_DIRTY_MIGRATION = 1
PAGE = 4096

# Cost per restored page, measured in the Slice 0 build (memcpy + tb_invalidate).
US_PER_PAGE = 0.42

# penguin passes -machine ...,memory-backend=mem0 (penguin_run.py:662) when
# the vsock backend is in use, so the block takes the backend object's id
# rather than the machine's default name. "mem0" first for that reason.
CANDIDATE_BLOCKS = (
    "mem0",
    "mach-virt.ram", "virt.ram", "vexpress.highmem", "ram",
    "mips_malta.ram", "malta.ram", "pc.ram", "ppc.ram", "riscv_virt_board.ram",
)


def _find_lib():
    """dlopen the exact file already mapped, so we share its globals rather
    than loading a second copy with its own state."""
    with open("/proc/self/maps") as fh:
        for line in fh:
            m = re.search(r"(\S*libqemu-system-\S+\.so)", line)
            if m:
                return m.group(1)
    return None


class RamTerm(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.windows = [int(x) for x in
                        (self.get_arg("windows_ms") or [1, 5, 25, 100, 500])]
        self.n = int(self.get_arg("samples_per_window") or 12)

        self.lib = None
        self.ram_len = 0
        # -M virt maps RAM at 0x40000000; only used by the positive control.
        self.ram_base = int(self.get_arg("ram_base") or 0x40000000)
        self.block = None
        self.state = "wait_ready"
        self.results = {w: [] for w in self.windows}
        self.control = {}
        self.t_window = 0.0
        self.wi = 0
        self.si = 0

        plugins.subscribe(plugins.Readiness, "ready", self.on_ready)

    # ---------------------------------------------------------------- setup
    def _bind(self):
        path = _find_lib()
        if not path:
            self.logger.error("ram_term: no libqemu-system-*.so in maps")
            return False
        self.logger.info(f"ram_term: binding {path}")
        lib = ctypes.CDLL(path)

        lib.memory_global_dirty_log_start.restype = ctypes.c_bool
        lib.memory_global_dirty_log_start.argtypes = [ctypes.c_uint,
                                                      ctypes.c_void_p]
        lib.memory_global_dirty_log_sync.restype = None
        lib.memory_global_dirty_log_sync.argtypes = [ctypes.c_bool]
        lib.physical_memory_test_and_clear_dirty.restype = ctypes.c_uint64
        lib.physical_memory_test_and_clear_dirty.argtypes = [
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint, ctypes.c_void_p]
        lib.qemu_ram_block_by_name.restype = ctypes.c_void_p
        lib.qemu_ram_block_by_name.argtypes = [ctypes.c_char_p]
        lib.qemu_ram_get_used_length.restype = ctypes.c_uint64
        lib.qemu_ram_get_used_length.argtypes = [ctypes.c_void_p]
        lib.cpu_physical_memory_read.restype = None
        lib.cpu_physical_memory_read.argtypes = [ctypes.c_uint64,
                                                 ctypes.c_void_p,
                                                 ctypes.c_uint64]
        lib.bql_locked.restype = ctypes.c_bool
        lib.bql_locked.argtypes = []
        lib.bql_lock_impl.restype = None
        lib.bql_lock_impl.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.bql_unlock.restype = None
        lib.bql_unlock.argtypes = []
        lib.error_get_pretty.restype = ctypes.c_char_p
        lib.error_get_pretty.argtypes = [ctypes.c_void_p]
        lib.cpu_physical_memory_write.restype = None
        lib.cpu_physical_memory_write.argtypes = [ctypes.c_uint64,
                                                  ctypes.c_void_p,
                                                  ctypes.c_uint64]

        for name in CANDIDATE_BLOCKS:
            rb = lib.qemu_ram_block_by_name(name.encode())
            if rb:
                self.block = name
                self.ram_len = int(lib.qemu_ram_get_used_length(
                    ctypes.c_void_p(rb)))
                break
        if not self.block:
            self.logger.error("ram_term: no known RAMBlock name matched; "
                              "refusing to guess a range (a bad range trips an "
                              "assert and kills the VM)")
            return False

        self.lib = lib
        self.logger.info(f"ram_term: RAMBlock {self.block} "
                         f"{self.ram_len >> 20} MB "
                         f"({self.ram_len // PAGE} pages)")
        return True

    class _Bql:
        """Take the BQL if we do not already hold it. QEMU's BQL is not
        recursive, so locking blindly would deadlock."""

        def __init__(self, lib):
            self.lib = lib
            self.took = False

        def __enter__(self):
            if not self.lib.bql_locked():
                self.lib.bql_lock_impl(b"ram_term", 0)
                self.took = True
            return self

        def __exit__(self, *_):
            if self.took:
                self.lib.bql_unlock()
            return False

    def _sample(self):
        """Dirty pages since the last call, and clear."""
        with self._Bql(self.lib):
            self.lib.memory_global_dirty_log_sync(False)
            return int(self.lib.physical_memory_test_and_clear_dirty(
                0, self.ram_len, DIRTY_MEMORY_MIGRATION, None))

    def on_ready(self, kind: str = "igloo_init"):
        if self.state != "wait_ready":
            return
        if not self._bind():
            self.state = "dead"
            return

        err = ctypes.c_void_p()
        with self._Bql(self.lib):
            ok = self.lib.memory_global_dirty_log_start(
                GLOBAL_DIRTY_MIGRATION, ctypes.byref(err))
        self.control["bql_was_held_in_on_ready"] = False
        self.control["arm_ok"] = bool(ok)
        if not ok:
            why = "(no Error* returned)"
            try:
                if err.value:
                    why = self.lib.error_get_pretty(err).decode()
            except Exception:
                pass
            self.control["arm_error"] = why
            self.logger.error("ram_term: ARM CONTROL FAILED - dirty log did "
                              "not start; every count below would read zero "
                              f"for a reason unrelated to the guest. QEMU says: {why}")
            self.state = "dead"
            return
        self._sample()   # clear
        self.state = "control"
        # Registration API is the syscall() decorator, not plugins.subscribe:
        # cf. pyplugins/core/snapshot.py:172. Must be a bound method -- the
        # syscalls API re-resolves callbacks by __qualname__.
        plugins.syscalls.syscall("on_all_sys_return")(self.on_sysret)
        self.logger.info("ram_term: armed; running positive control")

    # ----------------------------------------------------------- state pump
    def on_sysret(self, *_a, **_kw):
        now = time.perf_counter()

        if self.state == "control":
            # Known positive: dirty a page from the host and prove we see it.
            seen = self._probe_positive()
            self.control["positive_pages"] = seen
            if seen < 1:
                self.logger.error(
                    "ram_term: POSITIVE CONTROL FAILED - a host write to guest "
                    "RAM did not appear as a dirty page. The probe cannot see "
                    "dirtying, so a low count below would mean nothing.")
                self.state = "dead"
                return
            self.logger.info(f"ram_term: positive control OK ({seen} page[s])")
            self._sample()
            self.state = "measure"
            self.t_window = now
            return

        if self.state != "measure":
            return

        w = self.windows[self.wi]
        if (now - self.t_window) * 1000.0 < w:
            return

        pages = self._sample()
        elapsed_ms = (now - self.t_window) * 1000.0
        self.results[w].append({"pages": pages, "elapsed_ms": elapsed_ms})
        self.si += 1
        if self.si >= self.n:
            self.si = 0
            self.wi += 1
            if self.wi >= len(self.windows):
                self._report()
                self.state = "done"
                return
        self.t_window = time.perf_counter()

    def _probe_positive(self):
        """Prove a write through QEMU's memory path lands in the bitmap.

        Reads 8 bytes of guest physical memory and writes the SAME bytes back.
        invalidate_and_set_dirty() runs on any write regardless of value, so
        this sets a real dirty bit while changing no guest state at all --
        a positive control that cannot perturb the thing it is measuring.
        """
        try:
            buf = (ctypes.c_ubyte * 8)()
            pa = self.ram_base + 0x100000
            with self._Bql(self.lib):
                self.lib.cpu_physical_memory_read(pa, ctypes.byref(buf), 8)
                self.lib.cpu_physical_memory_write(pa, ctypes.byref(buf), 8)
        except Exception as e:
            self.logger.warning(f"ram_term: positive control write failed: {e}")
            return -1
        return self._sample()

    # --------------------------------------------------------------- output
    def _report(self):
        out = {
            "target": "stridelinx (rehosting/examples, public)",
            "ram_block": self.block,
            "ram_mb": self.ram_len >> 20,
            "us_per_page": US_PER_PAGE,
            "controls": self.control,
            "windows": {},
        }
        self.logger.info("ram_term: RESULTS  (idle booted firmware)")
        self.logger.info("  window   median pages   KB   implied RAM term")
        for w in self.windows:
            rows = self.results[w]
            if not rows:
                continue
            pages = sorted(r["pages"] for r in rows)
            med = statistics.median(pages)
            ms = med * US_PER_PAGE / 1000.0
            out["windows"][str(w)] = {
                "samples": len(rows),
                "pages_median": med,
                "pages_min": pages[0],
                "pages_max": pages[-1],
                "elapsed_ms_median": statistics.median(
                    r["elapsed_ms"] for r in rows),
                "ram_term_ms": ms,
            }
            self.logger.info(
                f"  {w:5d}ms  {med:12.0f}   {med*4:6.0f}   {ms:.3f} ms")
        if self.outdir:
            p = os.path.join(self.outdir, "ram_term.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"ram_term: wrote {p}")
