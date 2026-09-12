"""How many guest pages one fuzzing iteration dirties, on a real firmware target.

THE NUMBER THIS EXISTS FOR. A dirty-page reset costs O(dirty pages). RESET.md's
host-side sweep puts the same 256 MB guest at 79 us to restore a 1 MB dirty
set, 373 us for 4 MB and 2,136 us for 16 MB -- and the projected exec/s, and
the claim that eight instances fit inside memory bandwidth, both rest on the
4 MB column. Nothing had asked a guest which column it lands in.

`ram_term.py` asked a related question and got 51 pages per millisecond on an
IDLE booted firmware. That is not this number, for two reasons:

  1. Idle is the wrong workload. A fuzzing iteration is the guest doing the
     thing being fuzzed.
  2. A millisecond is the wrong denominator. An iteration is delimited by
     guest control flow, not by the host clock, and the whole point of the
     fast path is that an iteration gets shorter -- so a per-millisecond rate
     cannot be multiplied out into a per-iteration figure without assuming the
     answer.

So the interval here is the ITERATION ITSELF: a uprobe on the target's parse
entry point is both the boundary and the clock. Two boundaries are available
and they measure different things:

  laps=0   consecutive natural entries -- one whole request: socket read,
           parse, response writev, back round the event loop. The iteration a
           naive snapshot fuzzer would reset.
  laps=N   persist.py's rewind: the probe sends the parser back into itself,
           so consecutive entries bracket ONE PARSE and nothing else. This is
           the iteration the fast-reset design is shaped for -- DRAFT's
           "restore to a point inside the parser and re-run only the parse".

THE INSTRUMENT is QEMU's own migration dirty bitmap, read through
physical_memory_test_and_clear_dirty(), which returns the count and clears it
in one call. The clear is not bookkeeping: TCG marks a page's TLB entry
TLB_NOTDIRTY only while its dirty bits are clear, so clearing is what re-arms
the trap, via physical_memory_dirty_bits_cleared() -> tlb_reset_dirty_range_all().

WHY EVERY BLOCK, NOT JUST MAIN RAM. ram_term.py measured one RAMBlock chosen
by name from a candidate list, and passed start=0 rather than the block's own
ram_addr offset -- which happens to be right only while the named block is the
one at ram_addr 0. This walks qemu_ram_foreach_block() and uses each block's
own offset and length, so nothing is silently outside the measurement and a
count that is really pflash cannot be reported as a working set.

THE CONTROLS, three, because both failure modes of a dirty-page counter are
readable as an answer. A counter stuck at zero says "tiny working set, the
design is cheap"; one that reports everything says "huge working set, the
design is dead". Neither can be caught by looking at the log.

  A  POKE       -- write N known pages through QEMU's own write path, and
                   require the counter to report at least N AND to NAME those
                   N pages. A count alone is passed by anything that returns a
                   large number.
  B  CONSUMED   -- the next interval, with nothing poked, must fall back to
                   baseline. A counter that never clears passes A.
  C  RE-ARM     -- poke the SAME N pages in a LATER interval and require N
                   again. This is the one that is easy to omit and the only
                   one that fails if the clear does not walk the vCPU TLBs:
                   in that world the first interval is right and every
                   interval after it silently under-counts, which is exactly
                   what a believable wrong number looks like.

The poke reads eight bytes of guest memory and writes the SAME eight bytes
back. invalidate_and_set_dirty() runs on any write regardless of value, so
this sets real dirty bits while changing no guest state -- a positive control
that cannot perturb what it measures.

The same controls, on the same primitive, are gated in CI against -M virt by
qemu_builder's src/fastsnap/selftest.c phase 5 (8 poked, 8 counted, all named,
baseline 0, re-arm proven). This module is the host-side twin of that, and the
two are independent implementations of the same measurement.

LOCKING. QEMU's BQL is not recursive and a pyplugin callback does not
necessarily hold it, so every call takes it through bql_lock_impl() guarded by
bql_locked(). Assuming a callback held it produced
`memory_region_transaction_commit: Assertion bql_locked() failed` and killed
the VM.

Args: path, symbol, laps, warmup, samples, ram_base, pokes, outdir, tag
"""

import ctypes
import json
import os
import re
import statistics
import time

from penguin import Plugin, plugins

uprobes = plugins.uprobes

DIRTY_MEMORY_MIGRATION = 2
GLOBAL_DIRTY_MIGRATION = 1
PAGE = 4096
LONG_BITS = 64
ARG_REGS = ("r0", "r1", "r2", "r3")

# Cost per restored page from the Slice 0 build (memcpy + tb_invalidate), kept
# only to render the measured page count as a reset cost. It is an input, not
# a result of this run.
US_PER_PAGE = 0.42


class MemTxAttrs(ctypes.Structure):
    """MEMTXATTRS_UNSPECIFIED.

    include/exec/memattrs.h packs 31 bits of flags, then `bool unspecified`,
    then two reserved fields, to exactly 8 bytes -- QEMU asserts the size. So
    one 64-bit word with bit 32 set is that constant, and an 8-byte struct is
    passed in a register, which is what libffi will do with this.
    """
    _fields_ = [("raw", ctypes.c_uint64)]


MEMTXATTRS_UNSPECIFIED = MemTxAttrs(1 << 32)

RAM_ITER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)


def _find_lib():
    """dlopen the file already mapped, so we share its globals rather than
    loading a second copy with its own dirty bitmap."""
    with open("/proc/self/maps") as fh:
        for line in fh:
            m = re.search(r"(\S*libqemu-system-\S+\.so)", line)
            if m:
                return m.group(1)
    return None


class DirtyIter(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.tag = self.get_arg("tag") or "dirtyiter"
        self.path = self.get_arg("path") or "/usr/sbin/lighttpd"
        self.symbol = self.get_arg("symbol") or "http_request_parse"
        self.laps_per_entry = int(self.get_arg("laps") or 0)
        self.warmup = int(self.get_arg("warmup") or 20)
        self.want = int(self.get_arg("samples") or 300)
        self.ram_base = int(self.get_arg("ram_base") or 0x40000000)
        self.pokes = int(self.get_arg("pokes") or 8)
        self.poke_stride = int(self.get_arg("poke_stride") or 0x10000)
        self.poke_off = int(self.get_arg("poke_off") or 0x200000)
        # Phase 2: the same measurement taken by the in-QEMU implementation.
        self.cops_iters = int(self.get_arg("cops_iters") or 0)
        self.cops_rounds = int(self.get_arg("cops_rounds") or 6)

        self.lib = None
        self.blocks = []          # (idstr, offset, used_length, migratable)
        self.total_pages = 0
        self.control = {}
        self.errors = []
        self.state = "wait_ready"

        self.samples = []          # pages per iteration
        self.per_block = {}        # idstr -> total pages over the run
        self.iter_ms = []
        self.t_prev = None
        self.n_entries = 0
        self.n_fresh = 0
        self.n_rewinds = 0

        # persist.py's rewind, verbatim in shape: LR at entry still holds the
        # caller's return address, so overwriting it with the function's own
        # entry makes the epilogue return into the function.
        self.entry_pc = None
        self.real_lr = None
        self.saved_args = None
        self.remaining = 0

        self.resolved = None
        self.cops = None            # bound ABI, or None if the build lacks it
        self.cops_rows = []
        self.cops_round = 0
        self.cops_seq = 0
        self.cops_boundaries = 0
        plugins.subscribe(plugins.Readiness, "ready", self.on_ready)

    # ------------------------------------------------------------- binding
    def _bind(self):
        path = _find_lib()
        if not path:
            self.logger.error("dirtyiter: no libqemu-system-*.so in maps")
            return False
        lib = ctypes.CDLL(path)

        lib.memory_global_dirty_log_start.restype = ctypes.c_bool
        lib.memory_global_dirty_log_start.argtypes = [ctypes.c_uint,
                                                      ctypes.c_void_p]
        lib.memory_global_dirty_log_sync.restype = None
        lib.memory_global_dirty_log_sync.argtypes = [ctypes.c_bool]
        lib.physical_memory_test_and_clear_dirty.restype = ctypes.c_uint64
        lib.physical_memory_test_and_clear_dirty.argtypes = [
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint, ctypes.c_void_p]
        lib.qemu_ram_foreach_block.restype = ctypes.c_int
        lib.qemu_ram_foreach_block.argtypes = [RAM_ITER, ctypes.c_void_p]
        lib.qemu_ram_get_idstr.restype = ctypes.c_char_p
        lib.qemu_ram_get_idstr.argtypes = [ctypes.c_void_p]
        lib.qemu_ram_get_offset.restype = ctypes.c_uint64
        lib.qemu_ram_get_offset.argtypes = [ctypes.c_void_p]
        lib.qemu_ram_get_used_length.restype = ctypes.c_uint64
        lib.qemu_ram_get_used_length.argtypes = [ctypes.c_void_p]
        lib.qemu_ram_is_migratable.restype = ctypes.c_bool
        lib.qemu_ram_is_migratable.argtypes = [ctypes.c_void_p]
        lib.qemu_ram_get_host_addr.restype = ctypes.c_void_p
        lib.qemu_ram_get_host_addr.argtypes = [ctypes.c_void_p]
        lib.address_space_rw.restype = ctypes.c_int
        lib.address_space_rw.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                         MemTxAttrs, ctypes.c_void_p,
                                         ctypes.c_uint64, ctypes.c_bool]
        lib.bql_locked.restype = ctypes.c_bool
        lib.bql_locked.argtypes = []
        lib.bql_lock_impl.restype = None
        lib.bql_lock_impl.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.bql_unlock.restype = None
        lib.bql_unlock.argtypes = []
        lib.error_get_pretty.restype = ctypes.c_char_p
        lib.error_get_pretty.argtypes = [ctypes.c_void_p]

        self.as_memory = ctypes.addressof(
            ctypes.c_char.in_dll(lib, "address_space_memory"))

        # The in-QEMU twin of everything below, if this build has it. Same
        # bitmap, same primitive, but read from a main-loop bottom half with
        # the vCPUs stopped rather than from a probe callback holding the BQL.
        # Two implementations of one measurement; phase 2 runs them against the
        # same booted guest so a disagreement has somewhere to show up.
        try:
            lib.penguin_fastsnap_schedule.restype = None
            lib.penguin_fastsnap_schedule.argtypes = [ctypes.c_int]
            lib.penguin_fastsnap_seq.restype = ctypes.c_uint64
            lib.penguin_fastsnap_seq.argtypes = []
            lib.penguin_fastsnap_last_rc.restype = ctypes.c_int
            lib.penguin_fastsnap_last_rc.argtypes = []
            lib.penguin_fastsnap_last_us.restype = ctypes.c_int64
            lib.penguin_fastsnap_last_us.argtypes = []
            lib.penguin_fastsnap_dirty_pages.restype = ctypes.c_uint64
            lib.penguin_fastsnap_dirty_pages.argtypes = []
            lib.penguin_fastsnap_dirty_pages_scanned.restype = ctypes.c_uint64
            lib.penguin_fastsnap_dirty_pages_scanned.argtypes = []
            lib.penguin_fastsnap_dirty_blocks.restype = ctypes.c_char_p
            lib.penguin_fastsnap_dirty_blocks.argtypes = []
            self.cops = lib
        except AttributeError:
            self.cops = None
            self.logger.info("dirtyiter: this QEMU has no penguin_fastsnap "
                             "dirty ABI; phase 2 (in-QEMU cross-check) skipped")

        found = []

        def _iter(rb, _opaque):
            try:
                if not lib.qemu_ram_get_host_addr(rb):
                    return 0
                found.append((
                    lib.qemu_ram_get_idstr(rb).decode("utf-8", "replace"),
                    int(lib.qemu_ram_get_offset(rb)),
                    int(lib.qemu_ram_get_used_length(rb)),
                    bool(lib.qemu_ram_is_migratable(rb)),
                ))
            except Exception as e:                      # noqa: BLE001
                self.errors.append(f"ramblock iter: {e!r}")
            return 0

        self._iter_cb = RAM_ITER(_iter)      # keep alive
        lib.qemu_ram_foreach_block(self._iter_cb, None)

        if not found:
            self.logger.error("dirtyiter: qemu_ram_foreach_block enumerated no "
                              "blocks; nothing would be measured")
            return False

        self.blocks = [b for b in found if b[2] > 0]
        self.total_pages = sum((b[2] + PAGE - 1) // PAGE for b in self.blocks)
        self.lib = lib
        self.logger.info(
            "dirtyiter: %d RAM blocks, %d pages (%d MB): %s",
            len(self.blocks), self.total_pages, (self.total_pages * PAGE) >> 20,
            ", ".join(f"{n}{'' if mig else '!'}@{off:#x}+{ln >> 10}K"
                      for n, off, ln, mig in self.blocks))
        return True

    class _Bql:
        def __init__(self, lib):
            self.lib = lib
            self.took = False

        def __enter__(self):
            if not self.lib.bql_locked():
                self.lib.bql_lock_impl(b"dirtyiter", 0)
                self.took = True
            return self

        def __exit__(self, *_):
            if self.took:
                self.lib.bql_unlock()
            return False

    # ------------------------------------------------------------ sampling
    def _sample(self, want_names=False):
        """Pages dirtied since the last call, cleared. Per block, every block.

        Returns (total, {idstr: count}, [names]) where names is populated only
        when asked -- scanning the returned bitmap costs more than the count.
        """
        total = 0
        by_block = {}
        names = []
        with self._Bql(self.lib):
            self.lib.memory_global_dirty_log_sync(False)
            for idstr, off, ln, _mig in self.blocks:
                npages = (ln + PAGE - 1) // PAGE
                nwords = (npages + LONG_BITS - 1) // LONG_BITS
                bmap = (ctypes.c_uint64 * nwords)() if want_names else None
                n = int(self.lib.physical_memory_test_and_clear_dirty(
                    off, ln, DIRTY_MEMORY_MIGRATION,
                    ctypes.byref(bmap) if bmap is not None else None))
                if n:
                    total += n
                    by_block[idstr] = by_block.get(idstr, 0) + n
                    if bmap is not None:
                        for w in range(nwords):
                            word = bmap[w]
                            if not word:
                                continue
                            for b in range(LONG_BITS):
                                if word & (1 << b):
                                    names.append(
                                        f"{idstr}+{(w * LONG_BITS + b) * PAGE:#x}")
        return total, by_block, names

    def _poke(self):
        """Write N known pages through QEMU's write path, changing nothing.

        Reads eight bytes and writes the same eight back: the dirty bit is set
        by invalidate_and_set_dirty() on any write, so the guest's state is
        untouched and the control cannot perturb the measurement.
        """
        buf = (ctypes.c_ubyte * 8)()
        with self._Bql(self.lib):
            for i in range(self.pokes):
                pa = self.ram_base + self.poke_off + i * self.poke_stride
                self.lib.address_space_rw(
                    ctypes.c_void_p(self.as_memory), pa,
                    MEMTXATTRS_UNSPECIFIED, ctypes.byref(buf), 8, False)
                self.lib.address_space_rw(
                    ctypes.c_void_p(self.as_memory), pa,
                    MEMTXATTRS_UNSPECIFIED, ctypes.byref(buf), 8, True)

    def _expected_names(self):
        return [f"{self.poke_off + i * self.poke_stride:#x}"
                for i in range(self.pokes)]

    # ------------------------------------------------------------- controls
    def _run_controls(self):
        err = ctypes.c_void_p()
        with self._Bql(self.lib):
            ok = bool(self.lib.memory_global_dirty_log_start(
                GLOBAL_DIRTY_MIGRATION, ctypes.byref(err)))
        self.control["arm_ok"] = ok
        if not ok:
            why = "(no Error* returned)"
            try:
                if err.value:
                    why = self.lib.error_get_pretty(err).decode()
            except Exception:                            # noqa: BLE001
                pass
            self.control["arm_error"] = why
            self.logger.error(
                "dirtyiter: ARM CONTROL FAILED - dirty logging did not start "
                "(%s). Every count below would read zero for a reason that has "
                "nothing to do with the guest.", why)
            return False

        cleared, _, _ = self._sample()
        self.control["arm_cleared_pages"] = cleared
        self.control["total_pages"] = self.total_pages
        if cleared == 0:
            self.logger.error(
                "dirtyiter: FAILED - arming cleared no dirty bits, but RAM "
                "blocks are created with all of them set. The bitmap was not "
                "found, so every count after this reads zero.")
            return False

        # A: a known perturbation, counted AND named.
        self._poke()
        c1, blocks1, names1 = self._sample(want_names=True)
        want = self._expected_names()
        got = set(names1)
        missing = [w for w in want
                   if not any(n.endswith(w) for n in got)]
        self.control["poke_pages"] = self.pokes
        self.control["poke_counted"] = c1
        self.control["poke_named_missing"] = missing
        self.control["poke_blocks"] = blocks1
        if c1 < self.pokes or missing:
            self.logger.error(
                "dirtyiter: POSITIVE CONTROL FAILED - %d known pages were "
                "written; the counter reported %d and did not name %s. A count "
                "that does not see, or cannot name, a write it was handed is "
                "not a measurement of this guest's working set. (named: %s)",
                self.pokes, c1, missing, sorted(got)[:16])
            return False
        self.logger.info(
            "dirtyiter: control A OK - %d poked, %d counted, all named (%s)",
            self.pokes, c1, blocks1)

        # B: the set is consumed, not merely read.
        c2, _, _ = self._sample()
        self.control["quiet_after_poke"] = c2

        # C: the same pages again, in a LATER interval.
        self._poke()
        c3, _, names3 = self._sample(want_names=True)
        got3 = set(names3)
        missing3 = [w for w in want if not any(n.endswith(w) for n in got3)]
        self.control["repoke_counted"] = c3
        self.control["repoke_named_missing"] = missing3
        if c3 < self.pokes or missing3:
            self.logger.error(
                "dirtyiter: RE-ARM CONTROL FAILED - writing the same %d pages "
                "in a second interval reported %d, missing %s. Tracking does "
                "not re-arm after a count, so every interval but the first "
                "under-counts.", self.pokes, c3, missing3)
            return False
        self.logger.info(
            "dirtyiter: control C OK - re-arms; second interval counts %d for "
            "the same %d pages (quiet interval between: %d)",
            c3, self.pokes, c2)
        self._sample()
        return True

    # ----------------------------------------------------------- lifecycle
    def on_ready(self, kind: str = "igloo_init"):
        if self.state != "wait_ready":
            return
        if not self._bind() or not self._run_controls():
            self.state = "dead"
            return

        lib, off = plugins.symbols.lookup(self.path, self.symbol)
        if off is None:
            self.logger.error(
                "dirtyiter: SYMBOL RESOLUTION FAILED for %s in %s; no probe "
                "placed, this run measures nothing.", self.symbol, self.path)
            self.state = "dead"
            return
        self.resolved = f"{lib}+{off:#x}"
        uprobes.uprobe(path=self.path, symbol=self.symbol, on_enter=True,
                       fail_register_ok=False)(self.on_entry)
        self.state = "measure"
        mode = "whole request" if self.laps_per_entry == 0 else \
            f"one parse (rewind, laps={self.laps_per_entry})"
        self.logger.info("dirtyiter: measuring per-iteration dirty set, "
                         "boundary = %s @ %s, iteration = %s",
                         self.symbol, self.resolved, mode)

    # ------------------------------------------------- phase 2: the C twin
    OP_DIRTY_ARM = 9
    OP_DIRTY_COUNT = 10

    def _cops_step(self):
        """One boundary of the in-QEMU cross-check.

        The ops are scheduled onto the main loop and run in a bottom half, so
        neither the arm nor the count happens at the boundary that asked for
        it -- it lands somewhere in the following iteration. The interval is
        therefore K iterations give or take one at each end, which is recorded
        rather than papered over: the comparison is an order-of-magnitude
        agreement between two implementations, not an identity.
        """
        st = self.state
        if st == "cops_arm":
            self.cops_seq = int(self.cops.penguin_fastsnap_seq())
            self.cops.penguin_fastsnap_schedule(self.OP_DIRTY_ARM)
            self.state = "cops_armwait"
        elif st == "cops_armwait":
            if int(self.cops.penguin_fastsnap_seq()) <= self.cops_seq:
                return
            if int(self.cops.penguin_fastsnap_last_rc()) != 0:
                self.logger.error("dirtyiter: in-QEMU DIRTY_ARM failed (rc %d)",
                                  self.cops.penguin_fastsnap_last_rc())
                self.state = "done"
                return
            self.cops_boundaries = 0
            self.state = "cops_run"
        elif st == "cops_run":
            self.cops_boundaries += 1
            if self.cops_boundaries >= self.cops_iters:
                self.cops_seq = int(self.cops.penguin_fastsnap_seq())
                self.cops.penguin_fastsnap_schedule(self.OP_DIRTY_COUNT)
                self.state = "cops_countwait"
        elif st == "cops_countwait":
            self.cops_boundaries += 1
            if int(self.cops.penguin_fastsnap_seq()) <= self.cops_seq:
                return
            pages = int(self.cops.penguin_fastsnap_dirty_pages())
            self.cops_rows.append({
                "iterations": self.cops_boundaries,
                "pages": pages,
                "scanned": int(self.cops.penguin_fastsnap_dirty_pages_scanned()),
                "blocks": self.cops.penguin_fastsnap_dirty_blocks()
                          .decode("utf-8", "replace"),
                "count_us": int(self.cops.penguin_fastsnap_last_us()),
            })
            self.cops_round += 1
            if self.cops_round >= self.cops_rounds:
                self._report_cops()
                self.state = "done"
            else:
                self.state = "cops_arm"

    def _report_cops(self):
        if not self.cops_rows:
            return
        per_iter = [r["pages"] / max(1, r["iterations"]) for r in self.cops_rows]
        self.cops_summary = {
            "rounds": self.cops_rows,
            "pages_per_iteration_median": statistics.median(per_iter),
            "pages_per_iteration_min": min(per_iter),
            "pages_per_iteration_max": max(per_iter),
        }
        self.logger.info(
            "dirtyiter: PHASE 2 (in-QEMU op, vCPUs stopped) -- %s; "
            "pages per iteration median %.1f (min %.1f max %.1f). "
            "Phase 1 host-side median was %s.",
            [(r["iterations"], r["pages"]) for r in self.cops_rows],
            self.cops_summary["pages_per_iteration_median"],
            self.cops_summary["pages_per_iteration_min"],
            self.cops_summary["pages_per_iteration_max"],
            statistics.median(self.samples) if self.samples else None)
        if self.outdir:
            p = os.path.join(self.outdir, f"dirtyiter_{self.tag}_cops.json")
            with open(p, "w") as fh:
                json.dump(self.cops_summary, fh, indent=2)

    def on_entry(self, regs, *args, **kwargs):
        now = time.time()
        self.n_entries += 1
        try:
            if self.state.startswith("cops"):
                self._cops_step()
            elif self.state == "measure":
                pages, by_block, _ = self._sample()
                if self.n_entries > self.warmup and self.t_prev is not None:
                    self.samples.append(pages)
                    self.iter_ms.append((now - self.t_prev) * 1000.0)
                    for k, v in by_block.items():
                        self.per_block[k] = self.per_block.get(k, 0) + v
                    if len(self.samples) >= self.want:
                        self._report()
                        # Phase 2 must not overlap phase 1: both consume the
                        # same dirty bitmap, so a sample taken by one is a
                        # sample the other will never see.
                        if self.cops is not None and self.cops_iters > 0:
                            self.state = "cops_arm"
                        else:
                            self.state = "done"
                self.t_prev = now

            if self.laps_per_entry > 0:
                if self.remaining > 0:
                    self.remaining -= 1
                    self.n_rewinds += 1
                    for name, val in zip(ARG_REGS, self.saved_args):
                        regs.set_register(name, val)
                    regs.lr = self.entry_pc if self.remaining > 0 \
                        else self.real_lr
                else:
                    self.n_fresh += 1
                    self.entry_pc = regs.pc
                    self.real_lr = regs.lr
                    self.saved_args = [regs.get_register(n) for n in ARG_REGS]
                    if self.state in ("measure", "done"):
                        self.remaining = self.laps_per_entry
                        regs.lr = self.entry_pc
            else:
                self.n_fresh += 1
        except Exception as e:                           # noqa: BLE001
            if len(self.errors) < 8:
                self.errors.append(repr(e))
        return
        yield

    # --------------------------------------------------------------- output
    def _report(self):
        if not self.samples:
            self.logger.warning("dirtyiter: no samples")
            return
        v = sorted(self.samples)
        med = statistics.median(v)
        out = {
            "tag": self.tag,
            "boundary_symbol": self.symbol,
            "boundary_path": self.path,
            "resolved": self.resolved,
            "iteration": "whole_request" if self.laps_per_entry == 0
                         else "one_parse_rewind",
            "laps_per_entry": self.laps_per_entry,
            "controls": self.control,
            "blocks": [{"id": n, "offset": off, "bytes": ln,
                        "migratable": mig}
                       for n, off, ln, mig in self.blocks],
            "guest_pages_total": self.total_pages,
            "guest_mb": (self.total_pages * PAGE) >> 20,
            "samples": len(v),
            "pages": {
                "median": med,
                "mean": statistics.fmean(v),
                "p10": v[max(0, len(v) // 10)],
                "p90": v[min(len(v) - 1, 9 * len(v) // 10)],
                "min": v[0],
                "max": v[-1],
            },
            "kb_median": med * PAGE / 1024.0,
            "implied_ram_restore_ms_at_%.2fus_per_page" % US_PER_PAGE:
                med * US_PER_PAGE / 1000.0,
            "iteration_ms": {
                "median": statistics.median(self.iter_ms) if self.iter_ms
                          else None,
            },
            "entries": self.n_entries,
            "fresh": self.n_fresh,
            "rewinds": self.n_rewinds,
            "per_block_total_pages": self.per_block,
            "errors": self.errors,
        }
        self.logger.info(
            "dirtyiter: RESULT %s -- median %s pages (%.0f KB) per iteration "
            "of %s; p10 %s p90 %s max %s over %d samples; iteration %.3f ms; "
            "blocks %s",
            self.tag, med, med * 4, out["iteration"], out["pages"]["p10"],
            out["pages"]["p90"], out["pages"]["max"], len(v),
            out["iteration_ms"]["median"] or float("nan"), self.per_block)
        if self.outdir:
            p = os.path.join(self.outdir, f"dirtyiter_{self.tag}.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info("dirtyiter: wrote %s", p)
        self._written = True

    def uninit(self) -> None:
        if self.state == "measure" and self.samples and \
                not getattr(self, "_written", False):
            self.logger.info("dirtyiter: run ended with %d/%d samples; "
                             "reporting what there is", len(self.samples),
                             self.want)
            self._report()
        elif self.state == "dead":
            self.logger.error("dirtyiter: NO RESULT -- a control failed: %s",
                              self.control)
