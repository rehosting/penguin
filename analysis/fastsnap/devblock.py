"""The device block on real firmware: does the fast reset survive a real target?

Every fastsnap number so far was taken on a synthetic `-M virt` machine: 17
sections, 63 KB, 0.043 ms for a {cpu,timer} allowlist. This asks the question
those numbers cannot answer -- what happens on a booted firmware image, where
the device set is whatever the board actually instantiates and the guest has a
real working set.

THREE THINGS IT MEASURES, and the third is the one that matters.

1. Shape. How many device sections, how many bytes. If a real board's block is
   megabytes rather than kilobytes, the whole approach prices differently.

2. Restore cost, taken INSIDE QEMU (penguin_fastsnap_last_us). A pyplugin round
   trip is hundreds of microseconds and so is the operation, so timing it from
   Python would be measuring the instrument, not the thing.

3. Whether the post-restore re-translation cliff is gone. This is the actual
   claim. penguin's current reset goes through vm_stop(RUN_STATE_RESTORE_VM),
   which accel/tcg turns into a full tb_flush; the guest then re-translates
   everything it runs, and on this target that cost MORE than the restore. It
   shows up as throughput afterwards, not latency during, so a restore-latency
   benchmark is blind to it. A device-only restore changes no RAM, so no
   translated block can go stale and the flush is skipped -- which should mean
   no cliff at all.

   Measured as adjacent syscall-rate windows: N hits before the restore, N
   after. A tb_flush shows up as the "after" window being slower.

CONTROLS, because an instrument that can report "no cliff" has to be shown
reporting one first:

  mode=fast     device block only        -- expect no cliff
  mode=loadvm   full savevm/loadvm       -- POSITIVE CONTROL, expect a cliff
  mode=noop     identical window cadence, restore replaced by nothing --
                THE NOISE FLOOR. Without it a small ratio in `fast` cannot be
                told from variance, and this workload's absolute rate moves a
                lot between runs (5.8 to 10.6 ms/hit observed), so only an
                in-run paired comparison is fair.
  mode=none     take a block, never restore -- isolates a failure to the take
                path rather than the restore loop

Run all three against the same target before believing any of them.
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls


class DevBlock(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.mode = (self.get_arg("mode") or "fast").lower()
        self.tag = self.get_arg("tag") or "devblock"
        self.want = int(self.get_arg("restores") or 20)
        self.warmup = int(self.get_arg("warmup") or 40)
        self.window = int(self.get_arg("window") or 40)
        self.detector = self.get_arg("detector") or "writev"

        if self.mode not in ("fast", "loadvm", "none", "noop", "sectiondiff"):
            raise ValueError(f"devblock: unknown mode {self.mode!r}")

        self.hits = 0
        self.state = "warmup"        # warmup -> taking -> loop -> done
        self.errors = []
        self.n_restores = 0

        self.shape = None            # sections/bytes, once taken
        self.digests = {}            # A/B/C positive control
        self.control = None          # its verdict
        self.abc_gap = int(self.get_arg("abc_gap") or 20)
        self._gap = 0
        self.all_sections = []
        self.denied = []

        # mode=sectiondiff: which sections move, and which the restore puts
        # back. The whole-block A/B/C says only that C != A; it cannot say
        # whether that is a defective restore or a section whose serialised
        # form legitimately depends on when it was serialised. Probing ONE
        # section at a time answers that, and needs no new C: the denylist
        # already takes a CSV, so denying every section but one makes the
        # existing PROBE a single-section probe.
        self.sweeps = {}             # "A" | "B" | "C" -> {section: digest}
        self.probe_order = []
        self.sweep_label = None
        self.sweep_i = -1
        self.section_report = None
        self.restore_us = []         # from inside QEMU
        self.sched_t = None
        self.seq_at_sched = None

        # adjacent-window throughput, to see a re-translation cliff
        self.win_before = []         # inter-hit intervals, ms
        self.win_after = []
        self.win_mode = None         # None | "before" | "after"
        self.t_prev = None
        self.before_all = []
        self.after_all = []

        # Sections to leave out. Default is every virtio device, and that is a
        # correctness requirement rather than a preference: a virtio device's
        # state is split between the device model and the vring in GUEST RAM, so
        # a device-only restore puts back one half and leaves the other as the
        # guest has since made it. virtio_load() rejects the result outright
        # ("VQ 1 size 0x100 < last_avail_idx 0x9 - used_idx 0x11"). This is the
        # announced trade for the fast path: it gives up the network backend.
        self.deny = self.get_arg("deny")
        if self.deny is None:
            self.deny = "auto"
        # Denied ON TOP of whatever `deny` selects. Exists to test the
        # mechanism behind the guest damage the fast arm does on real
        # firmware: the `cpu` section carries the ARM CP15 registers,
        # TTBR0/TTBR1 and CONTEXTIDR among them, so restoring it rewinds the
        # MMU's page-table base while guest RAM stays where the guest has since
        # taken it. The CPU then walks page tables RAM no longer holds. Denying
        # cpu,cpu_common leaves peripheral state rewound and the MMU alone; if
        # the guest survives that and dies without it, the mechanism is named.
        extra = self.get_arg("deny_extra")
        self.deny_extra = ([x.strip() for x in extra.split(",") if x.strip()]
                           if extra else [])

        self.have_api = bool(getattr(self.panda, "fastsnap_available", None)
                             and self.panda.fastsnap_available())
        if self.mode == "fast" and not self.have_api:
            self.logger.error(
                "devblock: this QEMU build does not export the fastsnap ABI, "
                "so mode=fast cannot run. Build penguin with "
                "--override-input penguin-qemu <qemu_builder>.")
            self.state = "done"

        # fastsnap_available() only proves the QEMU library has the ABI. The
        # PYTHON side lives inside the penguin image, and the two are versioned
        # independently -- an image built before a binding was added answers
        # True here and then raises AttributeError several minutes later, in a
        # vCPU callback, after a boot and a warmup.
        #
        # DERIVED FROM USAGE, not from a hand-kept list. The first version of
        # this check enumerated the names by hand; the very next change added
        # FASTSNAP_RESTORE_VERIFY to the code below and not to the list, and
        # three more runs were lost to the identical AttributeError the check
        # exists to prevent. A list that must be updated in lockstep with the
        # code it guards will fall out of lockstep. So read what this class
        # actually reaches for out of its own source, and require that.
        used = self._api_names_used()
        if not used:
            # Nothing found means the introspection broke, not that the plugin
            # uses no API. Say so: a check that quietly finds nothing is the
            # failure mode this whole guard exists to stop.
            self.logger.error(
                "devblock: the API preflight found no fastsnap names to check "
                "-- it is inert, and a stale image will not be caught")
            self.errors.append("api preflight inert")
        absent = sorted(used - set(dir(self.panda)))
        # Every mode but loadvm reaches the fastsnap API, and they all run from
        # this one file against one image, so require the whole set rather than
        # reasoning per-mode about which subset a given run will touch.
        if self.mode != "loadvm" and absent:
            self.logger.error(
                f"devblock: the penguin image's QemuCompat is missing "
                f"{absent} -- it predates these bindings. Rebuild the image "
                f"from this tree; mode={self.mode} cannot run.")
            self.errors.append(f"stale image, missing: {absent}")
            self.state = "done"

        syscalls.syscall(f"on_sys_{self.detector}_enter",
                         comm_filter=self.comm)(self.on_hit)
        self.logger.info(
            f"devblock: mode={self.mode} detector={self.detector} "
            f"comm={self.comm} warmup={self.warmup} restores={self.want} "
            f"window={self.window} fastsnap_api={self.have_api}")

    @classmethod
    def _api_names_used(cls):
        """Every `FASTSNAP_*` / `fastsnap_*` name this class reaches for.

        Read from the compiled code objects, not from source. Penguin execs a
        plugin into a synthetic `plugin_file` module, so inspect.getsource()
        raises TypeError -- and the first version of this caught only OSError
        and fell back to an empty set, which would have made the check silently
        inert. An attribute access compiles its name into co_names, so the
        bytecode has what is needed and cannot go stale.
        """
        import re
        import types
        pat = re.compile(r"^(FASTSNAP_\w+|fastsnap_\w+)$")
        seen, out = set(), set()

        def walk(code):
            if id(code) in seen:
                return
            seen.add(id(code))
            out.update(n for n in code.co_names if pat.match(n))
            for c in code.co_consts:
                if isinstance(c, types.CodeType):
                    walk(c)

        for v in vars(cls).values():
            fn = getattr(v, "__func__", v)
            code = getattr(fn, "__code__", None)
            if code is not None:
                walk(code)
        return out

    # ---- the throughput windows ----------------------------------------
    def _tick(self, now):
        if self.t_prev is not None and self.win_mode:
            dt = (now - self.t_prev) * 1000.0
            (self.win_before if self.win_mode == "before"
             else self.win_after).append(dt)
        self.t_prev = now

    def _close_windows(self):
        # Only count a pair where BOTH sides have samples; a truncated pair
        # compares a full window against a partial one.
        if len(self.win_before) >= 5 and len(self.win_after) >= 5:
            self.before_all.append(statistics.median(self.win_before))
            self.after_all.append(statistics.median(self.win_after))
        self.win_before, self.win_after = [], []

    def _apply_denylist(self):
        try:
            names = self.panda.fastsnap_section_names()
            self.all_sections = names
            self.logger.info(f"devblock: {len(names)} sections on this machine: "
                             f"{names}")
            if self.deny == "auto":
                # Everything virtio, by section id. Matching on the id rather
                # than a device type because that is what device-save.c
                # compares.
                chosen = [n for n in names if "virtio" in n.lower()]
            elif self.deny:
                chosen = [x.strip() for x in self.deny.split(",") if x.strip()]
            else:
                chosen = []
            chosen = chosen + [n for n in self.deny_extra
                               if n in names and n not in chosen]
            self.denied = chosen
            if chosen:
                self.panda.fastsnap_set_denylist(chosen)
                self.logger.info(f"devblock: excluding {len(chosen)}: {chosen}")
        except Exception as e:                           # noqa: BLE001
            self.errors.append(f"denylist: {e!r}")

    def _abc(self, now):
        """A/B/C: show the restore moves device state before believing timing.

        A restore that silently restored nothing produces the same duration and
        the same absence of a re-translation cliff as a correct one. On -M virt
        the selftest pokes a PL011 register; on real firmware there is nothing
        safe to poke, so watch the device state itself instead. Driven across
        successive detector hits because each hit means the guest ran, which
        means the main loop got a turn and the bottom half has had a chance.

        A and C are BOTH sampled inside a bottom half, with the vCPUs stopped:
        A is the digest TAKE leaves of the block it captured, and C is the one
        RESTORE_VERIFY leaves by re-serialising immediately after restoring.
        An earlier version probed separately after each, and could never have
        passed -- the earliest a probe can be scheduled is from the next
        detector hit, and by then the guest has executed and cpu/timer state
        has moved. It duly reported C != A, which said nothing about the
        restore. Only B is a free-running probe, and B is the leg that WANTS
        the guest to have run.
        """
        st = self.state
        if st == "abc_a":
            # A is the digest the TAKE itself left: the hash of the block, as
            # captured. Not a probe -- see the note in _abc's docstring.
            self.digests["A"] = self.panda.fastsnap_last_digest()
            self._gap = 0
            self.state = "abc_gap"
        elif st == "abc_gap":
            # Let the guest run, so its device state has a chance to move.
            self._gap += 1
            if self._gap >= self.abc_gap:
                self._sched(self.panda.FASTSNAP_PROBE)
                self.state = "abc_b"
        elif st == "abc_b":
            if not self._bh_done():
                return
            self.digests["B"] = self.panda.fastsnap_last_digest()
            self._sched(self.panda.FASTSNAP_RESTORE_VERIFY)
            self.state = "abc_c"
        elif st == "abc_c":
            if not self._bh_done():
                return
            self.digests["C"] = self.panda.fastsnap_last_digest()
            a, b, c = (self.digests.get(k) for k in "ABC")
            moved = (a != b)
            restored = (c == a)
            not_noop = (c != b)
            self.control = {"A": a, "B": b, "C": c,
                            "B_differs_from_A": moved,
                            "C_equals_A": restored,
                            "C_differs_from_B": not_noop,
                            "ok": bool(moved and restored and not_noop)}
            if not moved:
                self.logger.error(
                    "devblock: CONTROL FAILED - device state did not change "
                    "while the guest ran, so the probe is blind and nothing "
                    "below is evidence of anything")
            elif not restored or not not_noop:
                self.logger.error(
                    f"devblock: CONTROL FAILED - restore did not reproduce A "
                    f"(C==A {restored}, C!=B {not_noop})")
            else:
                self.logger.info(
                    "devblock: control OK - state moved, and the restore put "
                    "it back")
            self.state = "loop"
            self.win_mode = "before"
            self.t_prev = now

    # ---- mode=sectiondiff ------------------------------------------------
    def _probe_one(self, name):
        """Make the next PROBE cover exactly `name`, by denying the rest."""
        others = [n for n in self.all_sections if n != name]
        self.panda.fastsnap_set_denylist(others)
        self._sched(self.panda.FASTSNAP_PROBE)

    def _sweep(self, label, nxt):
        """One section per detector hit; `nxt` is the state to enter after."""
        if not self._bh_done():
            return
        if self.sweep_i >= 0:
            name = self.probe_order[self.sweep_i]
            self.sweeps[label][name] = self.panda.fastsnap_last_digest()
        self.sweep_i += 1
        if self.sweep_i >= len(self.probe_order):
            self.sweep_i = -1
            # Put the working denylist back before anything is taken or
            # restored; leaving an all-but-one denylist in place would make the
            # next restore a single-section restore.
            self.panda.fastsnap_set_denylist(self.denied)
            self.state = nxt
            self.logger.info(
                f"devblock: sweep {label} done "
                f"({len(self.sweeps[label])} sections)")
            return
        self._probe_one(self.probe_order[self.sweep_i])

    def _section_verdict(self):
        a, b, c = self.sweeps["A"], self.sweeps["B"], self.sweeps["C"]
        moved, not_restored, untouched = [], [], []
        for n in self.probe_order:
            if a.get(n) != b.get(n):
                moved.append(n)
            if a.get(n) != c.get(n):
                not_restored.append(n)
            if b.get(n) == c.get(n) and a.get(n) != b.get(n):
                untouched.append(n)
        self.section_report = {
            "probed": self.probe_order,
            "moved_A_to_B": moved,
            "not_restored_C_ne_A": not_restored,
            "restore_left_alone": untouched,
        }
        self.logger.info(
            f"devblock: sections that moved while the guest ran "
            f"({len(moved)}): {moved}")
        self.logger.info(
            f"devblock: sections the restore did NOT put back "
            f"({len(not_restored)}): {not_restored}")
        self.logger.info(
            f"devblock: of those, untouched by the restore "
            f"({len(untouched)}): {untouched}")

    def _sectiondiff(self, now):
        """A/B/C again, but per section, so a failure has an address.

        Same three points as the whole-block control -- after the take, after
        the guest has run, after the restore -- with a full per-section sweep
        at each. A section in `moved_A_to_B` but not in `not_restored_C_ne_A`
        is one the restore handled. A section in both is either broken or
        time-derived, and `restore_left_alone` separates those: if C still
        equals B, the restore wrote nothing back.
        """
        st = self.state
        if st == "sweep_a":
            self._sweep("A", "sd_gap")
            if self.state == "sd_gap":
                self._gap = 0
        elif st == "sd_gap":
            self._gap += 1
            if self._gap >= self.abc_gap:
                self.sweep_i = -1
                self.state = "sweep_b"
                self._sched(self.panda.FASTSNAP_PROBE)
        elif st == "sweep_b":
            self._sweep("B", "sd_restore")
            if self.state == "sd_restore":
                self._sched(self.panda.FASTSNAP_RESTORE)
        elif st == "sd_restore":
            if not self._bh_done():
                return
            if self.panda.fastsnap_last_rc() != 0:
                self.errors.append("sectiondiff: restore rc != 0")
            self.sweep_i = -1
            self.state = "sweep_c"
            self._sched(self.panda.FASTSNAP_PROBE)
        elif st == "sweep_c":
            self._sweep("C", "sd_done")
            if self.state == "sd_done":
                self._section_verdict()
                self.state = "done"

    def _record_shape(self):
        try:
            # section_count() is a property of the MACHINE (device_list_all
            # walks every handler), not of the block. Reporting it as the
            # block's paired it with a byte count that excludes the denied
            # sections, so `{'sections': 20, 'bytes': 16019}` described a
            # 17-section block with a 20 next to it. Report both, named.
            on_machine = self.panda.fastsnap_section_count()
            self.shape = {
                "sections_in_block": on_machine - len(self.denied),
                "sections_on_machine": on_machine,
                "bytes": self.panda.fastsnap_block_size(),
            }
            self.logger.info(f"devblock: block {self.shape}")
        except Exception as e:                           # noqa: BLE001
            self.errors.append(f"shape: {e!r}")

    def _sched(self, op):
        self.seq_at_sched = self.panda.fastsnap_seq()
        return self.panda.fastsnap_schedule(op)

    def _bh_done(self):
        """Has the scheduled bottom half run? This callback is on a vCPU
        thread and the BH is on the main loop, so blocking here would deadlock;
        the state machine just re-checks on the next detector hit."""
        return self.panda.fastsnap_seq() > self.seq_at_sched

    def _do_restore(self):
        self.sched_t = time.perf_counter()
        if self.mode == "noop":
            return                      # the noise floor: same cadence, no work
        if self.mode == "loadvm":
            self.panda.schedule_snapshot(self.tag, load=True)
        else:
            self._sched(self.panda.FASTSNAP_RESTORE)

    def on_hit(self, *args, **kwargs):
        now = time.perf_counter()
        self.hits += 1
        try:
            self._tick(now)

            if self.state == "warmup":
                if self.hits >= self.warmup:
                    self.state = "taking"
                    if self.mode == "loadvm":
                        self.panda.schedule_snapshot(self.tag, load=False)
                    else:
                        self._apply_denylist()
                        self.panda.fastsnap_schedule(self.panda.FASTSNAP_TAKE)

            elif self.state == "taking":
                # First hit after the bottom half ran: the guest is executing
                # again, so the take is complete.
                if self.mode != "loadvm":
                    self._record_shape()
                    if self.panda.fastsnap_last_rc() != 0:
                        self.errors.append("take returned rc != 0")
                        self.state = "done"
                        return
                    self.logger.info(
                        f"devblock: take {self.panda.fastsnap_last_us()} us")
                if self.mode == "sectiondiff":
                    self.probe_order = [n for n in self.all_sections
                                        if n not in self.denied]
                    for k in ("A", "B", "C"):
                        self.sweeps[k] = {}
                    self.sweep_i = -1
                    self.state = "sweep_a"
                    self._sched(self.panda.FASTSNAP_PROBE)
                elif self.mode == "none" or self.want <= 0:
                    self.state = "done"
                    self.logger.info("devblock: CONTROL - not restoring")
                elif self.mode == "fast":
                    # No probe here: A is the digest the TAKE just left, and
                    # scheduling a probe would overwrite it with a reading
                    # taken after the guest had run again.
                    self.state = "abc_a"        # positive control first
                else:
                    self.state = "loop"
                    self.win_mode = "before"

            elif self.state.startswith("abc_"):
                self._abc(now)

            elif self.state.startswith("sweep_") or self.state in (
                    "sd_gap", "sd_restore", "sd_done"):
                self._sectiondiff(now)

            elif self.state == "loop":
                if self.win_mode == "before" and len(self.win_before) >= self.window:
                    self._do_restore()
                    self.win_mode = "pending"
                elif self.win_mode == "pending":
                    # first hit after the restore's bottom half
                    if self.mode == "fast":
                        if self._bh_done():
                            if self.panda.fastsnap_last_rc() == 0:
                                self.restore_us.append(
                                    self.panda.fastsnap_last_us())
                            else:
                                self.errors.append("restore rc != 0")
                        else:
                            return  # bottom half has not run yet
                    self.n_restores += 1
                    self.win_mode = "after"
                    self.t_prev = now
                elif self.win_mode == "after" and len(self.win_after) >= self.window:
                    self._close_windows()
                    if self.n_restores >= self.want:
                        self.state = "done"
                        self.logger.info("devblock: loop finished")
                    else:
                        self.win_mode = "before"
        except Exception as e:                           # noqa: BLE001
            if len(self.errors) < 5:
                self.errors.append(repr(e))
            self.state = "done"
        return
        yield

    def uninit(self) -> None:
        def stats(v):
            if not v:
                return None
            v = sorted(v)
            return {"n": len(v), "median": statistics.median(v),
                    "min": v[0], "max": v[-1],
                    "p10": v[max(0, len(v) // 10)],
                    "p90": v[min(len(v) - 1, 9 * len(v) // 10)]}

        cliff = None
        if self.before_all and self.after_all:
            b = statistics.median(self.before_all)
            a = statistics.median(self.after_all)
            # >1 means the guest got SLOWER after the restore, i.e. a cliff.
            cliff = {"before_ms": b, "after_ms": a, "ratio": (a / b) if b else None}

        out = {
            "mode": self.mode, "detector": self.detector, "comm": self.comm,
            "state": self.state, "hits": self.hits,
            "fastsnap_api": self.have_api,
            "block": self.shape,
            "control": self.control,
            "section_report": self.section_report,
            "all_sections": self.all_sections,
            "denied": self.denied,
            "restores": self.n_restores,
            "restore_us_in_qemu": stats(self.restore_us),
            "throughput_cliff": cliff,
            "window_pairs": len(self.before_all),
            "errors": self.errors,
        }
        self.logger.info(f"devblock: RESULTS {json.dumps(out)}")

        if self.state != "done":
            self.logger.error(
                f"devblock: did not finish (state={self.state}, "
                f"hits={self.hits}); the run ended first or the guest stopped "
                "reaching the detector")
        if self.outdir:
            os.makedirs(self.outdir, exist_ok=True)
            with open(os.path.join(self.outdir,
                                   f"devblock_{self.mode}.json"), "w") as f:
                json.dump(out, f, indent=1)
