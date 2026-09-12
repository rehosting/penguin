"""The complete reset, closed into a loop on real firmware -- and what it costs.

This is the measurement the rest of the lane has been arithmetic about. Every
exec/s figure quoted so far (1,760 / 2,390 / 3,200 / 5,525) was a sum of
independently measured parts, and the one time that sum was checked against a
closed loop it was out by 3.7x -- predicted 0.456 ms, measured 1.69 ms. So the
number this plugin produces is not "reset + G"; it is the wall-clock interval
between successive iterations of a guest that is actually being reset.

WHAT AN ITERATION IS HERE. LOOP_ARM takes the device block, snapshots RAM, arms
dirty tracking and forks the oracle reference -- all in one bottom half, at one
instant. Every LOOP_RESET afterwards returns the guest to exactly that instant:
device state from the block, and the pages dirtied since copied back. So the
guest re-executes the SAME span of work every iteration, which is the shape a
snapshot fuzzer runs in. The measured interval is the cost of one lap of that.

THREE ARMS, because a single number for "the loop" is not attributable:

  mode=loop    arm once, reset every iteration                -- the product
  mode=armed   arm once, never reset                          -- isolates what
               holding the snapshot costs. This control is not optional and it
               is not obvious: arming turns on QEMU's global dirty log, and
               every first store to a clean page then traps through
               notdirty_write(). That slows the guest whether or not anything
               is ever restored, and without this arm that slowdown would be
               attributed to the reset.
  mode=bare    neither                                        -- the floor

  loop - armed  = the reset
  armed - bare  = the tracking
  bare          = guest work + the portal round trip

THE ORACLE, and why it needs its own op. A reset that silently restored nothing
produces the same timing as a correct one, and on this target the only channel
that could notice -- crashes.yaml -- is blind to kernel damage by construction
(it hooks userspace fatal signals; a panic is not one). So correctness comes
from the fork oracle: a child forked at the arm instant, read back with
process_vm_readv() and compared page by page. It shares no code with the
restore, which reads an in-process copy.

It has to run in the SAME bottom half as the reset. Scheduled as a separate op
the guest executes in the gap and dirties pages of ordinary kernel work, so a
perfectly correct reset reports hundreds of differing pages. That is not a
hypothetical -- this plugin measures it, as a control: `split_diff` runs the
oracle the wrong way round on purpose, and a run where the split form reports
zero would mean the oracle is not looking at a running guest at all.
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

FATAL_SIGNALS = ["SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"]


def _stats(v):
    if not v:
        return None
    v = sorted(v)
    return {
        "n": len(v),
        "median": statistics.median(v),
        "mean": statistics.fmean(v),
        "min": v[0],
        "max": v[-1],
        "p10": v[max(0, len(v) // 10)],
        "p90": v[min(len(v) - 1, 9 * len(v) // 10)],
    }


class FastLoop(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.detector = self.get_arg("detector") or "writev"
        self.mode = (self.get_arg("mode") or "loop").lower()
        self.warmup = int(self.get_arg("warmup") or 40)
        # Wall-clock floor on the arm, on top of the hit count. The first run
        # of this plugin armed after 40 detector hits, which fell 72 s into
        # boot -- in the middle of the guest generating SSH host keys. Every
        # lap then replayed that key generation, and the loop measured 20
        # SECONDS per iteration. Nothing was wrong with the reset; the console
        # shows the same "Creating SSH2 RSA key" line repeating, which is the
        # guest deterministically re-executing the span it was rewound to. The
        # iteration cost is the span from the armed instant to the next
        # detector hit, so WHERE the arm lands is the measurement.
        self.arm_after_s = float(self.get_arg("arm_after_s") or 0)
        self.reset_on_signal = bool(self.get_arg("reset_on_signal"))
        self.signal_laps = 0
        self._closed_by_signal = False
        self.crash_iter_ms = []    # laps a crash ended
        self.t_sched = None
        self.t_sched_mono = None
        # Wall time from scheduling a reset to first SEEING it finished.
        #
        # READ IT AS A COMPOSITE, not as bottom-half latency. The observation
        # point is the next detector hit, so this is
        #     max(time for the bottom half to run, time to the next detector)
        # and which term dominates depends on the target. Where the detector
        # fires thousands of times a second it approximates the first, and the
        # throttling experiment on bugbench used it that way: removing host-side
        # YAML writes from the signal callback dropped crash-lap latency 309 ms
        # -> 57 ms, which only the bottom-half term can explain. On a target
        # whose detector fires twelve times a second it is the second term, and
        # says nothing about the reset.
        #
        # The in-QEMU `reset_us` measures neither -- its clock starts when the
        # bottom half is already running.
        self.bh_wall_ms = []
        self.bh_wall_crash_ms = []
        # The two halves of bh_wall, which it could not previously separate.
        # sched_ms is scheduling to the bottom half completing (main-loop
        # latency plus the reset); obs_ms is that completion to the next
        # detector hit noticing (guest execution plus this plugin's own cost).
        # "The reset is slow" and "the round trip is slow" have opposite fixes
        # and bh_wall alone cannot tell them apart.
        self.sched_ms = []
        self.obs_ms = []
        self.sched_crash_ms = []
        self.obs_crash_ms = []
        self.sched_verify_ms = []
        self.obs_verify_ms = []
        self._have_bh_clock = True
        self.t0 = time.perf_counter()
        self.want = int(self.get_arg("iters") or 200)
        self.verify_every = int(self.get_arg("verify_every") or 50)
        self.tag = self.get_arg("tag") or "fastloop"

        if self.mode not in ("loop", "armed", "bare"):
            raise ValueError(f"fastloop: unknown mode {self.mode!r}")

        # Keep ONLY these device sections in the block. The largest single
        # lever on reset cost -- measured, 17 sections restore in 0.752 ms and
        # {cpu, timer} in 0.043 ms -- and the only setting here whose failure
        # mode is silence rather than an error. Paired with dev_diff below;
        # see _apply_scoping().
        self.allow = self.get_arg("allow")
        self.deny = self.get_arg("deny")
        if self.allow and self.deny:
            # Refused here, in __init__, so it costs nothing: the two are
            # answers to the same question and the C side takes exactly one.
            # A precedence rule would make the block's scope depend on
            # argument order, which nothing downstream reports.
            raise ValueError(
                f"fastloop: allow={self.allow!r} and deny={self.deny!r} are "
                f"mutually exclusive")
        if self.deny is None and not self.allow:
            # The default, and it is a correctness default rather than a
            # tuning one -- see _apply_scoping(). An explicit allowlist is
            # already narrower than any denylist, so it does not get one
            # layered underneath it.
            self.deny = "auto"
        extra = self.get_arg("deny_extra")
        self.deny_extra = ([x.strip() for x in extra.split(",") if x.strip()]
                           if extra else [])

        self.state = "warmup"
        self.hits = 0
        self.errors = []
        self.n_iters = 0
        self.all_sections = []
        self.denied = []
        self.arm_us = None
        self.t_arm_s = None
        self.arm_digest = None
        self.snapshot_bytes = None

        self.reset_us = []          # from inside QEMU, per reset
        self.iter_ms = []           # host wall clock, per iteration
        self.verify_iter_ms = []    # laps that also ran the oracle
        self.restored = []          # dirty pages copied back, per reset
        self.verifies = []          # {iter, diff_pages, bytes, diff_us, dev_*}
        self.allowed = None
        self.split_diff = None      # the deliberately-wrong-order control
        self.t_iter = None
        self.seq_at_sched = None
        self.t_loop0 = None
        self.t_loopN = None
        self.pending_reset = False
        self._pending_verify = None

        self.have_api = bool(getattr(self.panda, "fastsnap_available", None)
                             and self.panda.fastsnap_available())
        if not self.have_api:
            self.logger.error(
                "fastloop: this QEMU build does not export the fastsnap ABI. "
                "Build penguin with --override-input penguin-qemu <qemu_builder>.")
            self.state = "done"

        # The image's Python bindings and the QEMU library are versioned
        # independently, and an image built before a binding was added answers
        # fastsnap_available() True and then raises AttributeError several
        # minutes later inside a vCPU callback, after a boot and a warmup.
        # Three runs were lost to exactly that in this lane. Check the names
        # this class actually reaches for, read out of its own bytecode rather
        # than from a hand-kept list -- a list that has to be updated in
        # lockstep with the code it guards will fall out of lockstep.
        need = self._api_names_used()
        if not need:
            self.logger.error("fastloop: the API preflight found no fastsnap "
                              "names -- it is inert and will not catch a stale "
                              "image")
            self.errors.append("api preflight inert")
        absent = sorted(need - set(dir(self.panda)))
        if absent and self.state != "done":
            self.logger.error(
                f"fastloop: the image's QemuCompat is missing {absent} -- it "
                f"predates these bindings. Rebuild the image from this tree.")
            self.errors.append(f"stale image, missing: {absent}")
            self.state = "done"

        # AND ask the LIBRARY, which is a different question. The check above
        # is about Python attributes; a binding can exist as a method and still
        # be uncallable because the generated cffi header never declared the C
        # symbol. That is not hypothetical -- it is what the first run of this
        # plugin did: every fastsnap accessor was present in Python, none of
        # the new ones was declared to cffi, and the run reported a 256 MB RAM
        # snapshot as "0 bytes" and a fork diff as "-1 pages" without raising
        # anything. It produced a complete, plausible, entirely fictional
        # result set. An absent symbol has to stop the run, not decorate it.
        if self.state != "done" and hasattr(self.panda, "fastsnap_missing_symbols"):
            missing = self.panda.fastsnap_missing_symbols()
            if missing:
                self.logger.error(
                    f"fastloop: this QEMU build does not expose {missing}. "
                    f"Every accessor behind those would return a made-up "
                    f"number, so the run is refused rather than reported.")
                self.errors.append(f"ABI symbols absent: {missing}")
                self.state = "done"
        elif self.state != "done":
            self.logger.error(
                "fastloop: the image's QemuCompat has no "
                "fastsnap_missing_symbols(), so the C-symbol preflight cannot "
                "run and a silently incomplete ABI would not be caught. "
                "Rebuild the image from this tree.")
            self.errors.append("no symbol-level preflight available")
            self.state = "done"

        syscalls.syscall(f"on_sys_{self.detector}_enter",
                         comm_filter=self.comm)(self.on_hit)

        # A fatal signal is an iteration boundary too. Registered here rather
        # than left to the detector because a crashed victim makes no more
        # syscalls: see on_fatal_signal.
        self.fatal_signos = set()
        if self.reset_on_signal and self.state != "done":
            try:
                for name in FATAL_SIGNALS:
                    num = plugins.signals.signal_name_to_num(name)
                    if num is not None:
                        self.fatal_signos.add(int(num))
                plugins.subscribe(plugins.signal_monitor, "signal_deliver",
                                  self.on_fatal_signal)
                for num in self.fatal_signos:
                    plugins.signal_monitor.register_hook(sig=num)
            except Exception as e:                          # noqa: BLE001
                # Not a warning. The caller asked for crash-driven laps, and a
                # loop that silently waits for the guest to restart its victim
                # would still produce a rate -- a much worse one -- with no
                # sign that the thing being measured was not what was asked
                # for.
                self.logger.error(
                    f"fastloop: reset_on_signal was requested and could not be "
                    f"armed ({e!r}); refusing to report a rate for a loop that "
                    f"is not the one asked for")
                self.errors.append(f"signal hook: {e!r}")
                self.state = "done"
        if not self.reset_on_signal:
            self.logger.info(
                "fastloop: reset_on_signal is OFF -- a crashing input will "
                "stall the loop until the guest restarts the victim, which is "
                "the cost this design exists to remove. Correct for a pure "
                "rate measurement with no injector; wrong with one.")
        self.logger.info(
            f"fastloop: mode={self.mode} comm={self.comm} "
            f"detector={self.detector} warmup={self.warmup} iters={self.want} "
            f"verify_every={self.verify_every}")

    @classmethod
    def _api_names_used(cls):
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

        # The MRO, not just vars(cls): a subclass -- which is how the host-side
        # test drives this -- has only its own overrides in vars(), so walking
        # one class found nothing and the preflight reported itself inert.
        # That is the exact failure this check exists to prevent, one level up.
        for klass in cls.__mro__:
            for v in vars(klass).values():
                fn = getattr(v, "__func__", v)
                code = getattr(fn, "__code__", None)
                if code is not None:
                    walk(code)
        return out

    # ---- plumbing ---------------------------------------------------------

    def _sched(self, op):
        self.seq_at_sched = self.panda.fastsnap_seq()
        self.t_sched = time.perf_counter()
        self.t_sched_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
        self.panda.fastsnap_schedule(op)

    def _bh_done(self):
        """Has the scheduled bottom half run yet? This runs on a vCPU thread
        and the bottom half is on the main loop, so blocking would deadlock;
        the state machine re-checks on the next detector hit instead."""
        return self.panda.fastsnap_seq() > self.seq_at_sched

    def _apply_scoping(self):
        """Choose which device sections the block covers.

        An allowlist and a denylist answer the same question two ways and the
        C side takes exactly one, so naming both is refused here rather than
        silently resolved -- a precedence rule would make the scoping depend on
        argument order in a way nothing reports.
        """
        try:
            names = self.panda.fastsnap_section_names()
            self.all_sections = names
            self.logger.info(f"fastloop: device sections on this machine: "
                             f"{names}")
            if self.allow and self.deny:
                raise ValueError(
                    "fastloop: allow= and deny= are mutually exclusive; they "
                    "are two answers to 'is this section in the block' and "
                    "only one can be in force")
            if self.allow:
                wanted = [x.strip() for x in self.allow.split(",") if x.strip()]
                unknown = [w for w in wanted if w not in names]
                if unknown:
                    # Not a warning. An allowlist of names that match nothing
                    # produces an empty block that restores nothing, very
                    # quickly, and every number from the run would be a
                    # measurement of doing no work.
                    raise ValueError(
                        f"fastloop: allow= names {unknown}, which are not "
                        f"sections on this machine. Available: {names}")
                self.allowed = wanted
                self.panda.fastsnap_set_allowlist(wanted)
                self.logger.info(
                    f"fastloop: {len(names)} sections, allowing "
                    f"{len(wanted)}: {wanted}")
                return
            if self.deny == "auto":
                # Every virtio device, by section id. A virtio device's state
                # is split between the model and a vring in GUEST RAM. The RAM
                # half IS restored now, but virtio_load() validates against
                # indices the host-side backend has moved on from, and the
                # backend is not part of the guest, so the block still cannot
                # carry it.
                chosen = [n for n in names if "virtio" in n.lower()]
            elif self.deny:
                chosen = [x.strip() for x in self.deny.split(",") if x.strip()]
            else:
                chosen = []
            chosen += [n for n in self.deny_extra
                       if n in names and n not in chosen]
            self.denied = chosen
            if chosen:
                self.panda.fastsnap_set_denylist(chosen)
            self.logger.info(f"fastloop: {len(names)} sections, denying "
                             f"{len(chosen)}: {chosen}")
        except Exception as e:                              # noqa: BLE001
            # FATAL, where this used to warn and carry on. The scope of the
            # block is not a detail of the run, it IS what the run measures: a
            # failed allowlist silently falls back to a full block, and the
            # resulting numbers describe a configuration nobody asked for while
            # carrying the label of the one they did. Better no result.
            self.errors.append(f"scoping: {e!r}")
            self.logger.error(
                f"fastloop: REFUSING THE RUN - could not apply the requested "
                f"device scope ({e!r}). Falling back to a different scope "
                f"would produce numbers for a configuration you did not ask "
                f"for.")
            raise

    # ---- the loop ---------------------------------------------------------

    def on_hit(self, *args, **kwargs):
        """The syscall hook. penguin's machinery drives this with `yield from`,
        so it must stay a generator even though nothing in it yields."""
        self.hits += 1
        self._step(time.perf_counter())
        return
        yield

    def on_fatal_signal(self, cpu, event):
        """A crash also ends an iteration -- and this is the whole point.

        Without it the loop stalls exactly when fuzzing gets interesting. The
        detector is the victim's next read(), and a victim that just took a
        SIGSEGV never makes one: the loop waits for the guest's own restart
        machinery, which is the per-execution process teardown and setup that
        snapshot fuzzing exists to delete. Measured on this very target, that
        cost is not a rounding error -- under random input the victim died
        almost every restart and the run delivered 5,212 inputs where the
        crash-free oracle run delivered 237,575, a 45x collapse that cost the
        run a trivial-tier bug it should have found.

        So a fatal signal is an iteration boundary like any other. The reset
        rewinds past the crash to a live victim, and the next input goes in
        without a process ever being created.
        """
        if self.state != "loop" or self.mode == "bare":
            return
        try:
            if int(event.sig) not in self.fatal_signos or event.drop:
                return
        except Exception:                                   # noqa: BLE001
            return
        self.signal_laps += 1
        self._closed_by_signal = True
        self._step(time.perf_counter())

    def _step(self, now):
        try:
            if self.state == "warmup":
                if (self.hits >= self.warmup
                        and (now - self.t0) >= self.arm_after_s):
                    if self.mode == "bare":
                        self.state = "loop"
                        self.t_iter = now
                        self.t_loop0 = now
                    else:
                        self._apply_scoping()
                        self.state = "arming"
                        self._sched(self.panda.FASTSNAP_LOOP_ARM)

            elif self.state == "arming":
                if not self._bh_done():
                    return
                if self.panda.fastsnap_last_rc() != 0:
                    self.errors.append("LOOP_ARM returned rc != 0")
                    self.state = "done"
                    return
                self.arm_us = self.panda.fastsnap_last_us()
                self.t_arm_s = round(now - self.t0, 1)
                self.arm_digest = self.panda.fastsnap_last_digest()
                self.snapshot_bytes = self.panda.fastsnap_ram_snapshot_bytes()
                self.logger.info(
                    f"fastloop: armed in {self.arm_us} us, "
                    f"{self.snapshot_bytes} bytes of RAM snapshotted")
                if self.mode == "armed":
                    self.state = "loop"
                    self.t_iter = now
                    self.t_loop0 = now
                else:
                    # THE CONTROL FIRST. Run the oracle the wrong way round --
                    # as its own bottom half, with the guest free to run in
                    # between -- before trusting any zero from the right way
                    # round. If this reports zero too, the oracle is not
                    # looking at a running guest and every later zero is
                    # worthless.
                    self.state = "split_control"
                    self._sched(self.panda.FASTSNAP_LOOP_RESET)

            elif self.state == "split_control":
                if not self._bh_done():
                    return
                self.state = "split_control_diff"
                self._sched(self.panda.FASTSNAP_FORK_DIFF)

            elif self.state == "split_control_diff":
                if not self._bh_done():
                    return
                self.split_diff = self.panda.fastsnap_diff_pages()
                # <= 0, not == 0. A negative value means the comparison itself
                # failed -- process_vm_readv could not read the child -- and
                # the first run of this plugin reported exactly that as
                # "control OK - the oracle sees -1 pages the guest dirtied".
                # A broken oracle passing its own control is the precise shape
                # of failure the control exists to prevent.
                if self.split_diff <= 0:
                    why = ("could not read the forked reference at all"
                           if self.split_diff < 0 else
                           "reports zero differing pages")
                    self.logger.error(
                        f"fastloop: CONTROL FAILED - the oracle run as a "
                        f"separate bottom half {why}. On a running guest it "
                        f"should see the pages written between the two bottom "
                        f"halves, so a zero from the combined op would prove "
                        f"nothing.")
                    self.errors.append(
                        f"split-order control failed (diff_pages="
                        f"{self.split_diff})")
                else:
                    self.logger.info(
                        f"fastloop: control OK - split-order oracle sees "
                        f"{self.split_diff} pages the guest dirtied between "
                        f"the reset and the diff; the combined op has "
                        f"something to be right about")
                self.state = "loop"
                self.t_iter = now
                self.t_loop0 = now

            elif self.state == "loop":
                if self.mode in ("bare", "armed"):
                    # No reset outstanding, so every detector hit closes an
                    # iteration directly. These arms exist to price what the
                    # loop arm carries BESIDES the reset, so they must take
                    # their interval from the same event.
                    self._mark(now)
                    return

                if self.pending_reset:
                    if not self._bh_done():
                        return          # bottom half has not run yet
                    if self.panda.fastsnap_last_rc() != 0:
                        self.errors.append("reset returned rc != 0")
                        self.state = "done"
                        return
                    # Read the reset's own clock BEFORE _mark, which consumes
                    # the verification bookkeeping from the same op.
                    if self.t_sched is not None:
                        w = (now - self.t_sched) * 1000.0
                        (self.bh_wall_crash_ms if self._closed_by_signal
                         else self.bh_wall_ms).append(w)
                        self._split_wall(now)
                    self.reset_us.append(self.panda.fastsnap_last_us())
                    self.restored.append(
                        self.panda.fastsnap_ram_restored_pages())
                    self.pending_reset = False
                    self._mark(now)
                    if self.state != "loop":
                        return
                else:
                    # First lap: nothing outstanding, just start the clock so
                    # the first interval is a real one rather than the gap
                    # since the control finished.
                    self.t_iter = now
                    self.t_loop0 = now

                # Verify on a schedule, not every lap: the oracle reads all of
                # guest RAM back through process_vm_readv() and costs ~80x the
                # reset, so verifying every lap would report the oracle's rate
                # as the loop's.
                if (self.verify_every
                        and self.n_iters % self.verify_every == 0):
                    self._pending_verify = self.n_iters
                    self._sched(self.panda.FASTSNAP_LOOP_RESET_VERIFY)
                else:
                    self._pending_verify = None
                    self._sched(self.panda.FASTSNAP_LOOP_RESET)
                self.pending_reset = True
        except Exception as e:                              # noqa: BLE001
            if len(self.errors) < 5:
                self.errors.append(repr(e))
            self.state = "done"

    @staticmethod
    def _self_sha256():
        try:
            import hashlib
            return hashlib.sha256(
                open(__file__, "rb").read()).hexdigest()[:16]
        except Exception:                                   # noqa: BLE001
            return None

    def _split_wall(self, now):
        """Split the schedule-to-observed span at the bottom half.

        CLOCK_MONOTONIC on both sides, taken explicitly rather than through
        perf_counter(): both are that clock on Linux, but only the explicit
        form is documented to be, and a mismatched epoch would arrive as a
        plausible latency rather than as an error. A build without the
        timestamp is recorded as absent, never as zero.
        """
        if not self._have_bh_clock or self.t_sched_mono is None:
            return
        try:
            bh = self.panda.fastsnap_bh_done_us() / 1e6
        except Exception:                                   # noqa: BLE001
            self._have_bh_clock = False
            return
        now_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
        sched = (bh - self.t_sched_mono) * 1000.0
        obs = (now_mono - bh) * 1000.0
        # A negative half means the two clocks are not the same clock. Dropping
        # the sample is right: a negative latency reported as a small positive
        # one is exactly the kind of number that gets quoted.
        if sched < 0 or obs < 0:
            self._have_bh_clock = False
            self.errors.append(
                f"bh clock mismatch (sched={sched:.3f} ms, obs={obs:.3f} ms); "
                f"the split is unavailable for this run")
            return
        if self._closed_by_signal:
            self.sched_crash_ms.append(sched)
            self.obs_crash_ms.append(obs)
        elif self._pending_verify is not None:
            # A verified lap's bottom half carries the oracle's ~50 ms, which
            # lands wholly inside sched_to_bh. Left in the ordinary bucket it
            # moved that bucket's MEAN from 0.12 ms to 2.54 ms on a run where
            # 4% of laps were verified -- the median survived, so the number
            # was quotable and the number beside it was not. Same separation
            # iter_ms already makes, one level down.
            self.sched_verify_ms.append(sched)
            self.obs_verify_ms.append(obs)
        else:
            self.sched_ms.append(sched)
            self.obs_ms.append(obs)

    def _mark(self, now):
        """Close one iteration."""
        was_crash = self._closed_by_signal
        self._closed_by_signal = False
        was_verify = self._pending_verify is not None
        if was_verify:
            d = self.panda.fastsnap_diff_pages()
            # The device oracle, read in the same breath as the RAM one. They
            # answer different questions and a scoped block needs both: the
            # fork reference cannot see a device section that was never
            # restored, only the guest damage it eventually causes -- which is
            # a slower, weaker and much later signal.
            try:
                dev_n = self.panda.fastsnap_dev_diff_sections()
                dev_report = self.panda.fastsnap_dev_diff_report()
            except Exception as e:                          # noqa: BLE001
                dev_n, dev_report = -1, repr(e)
            self.verifies.append({
                "iter": self._pending_verify,
                "diff_pages": d,
                "bytes_checked": self.panda.fastsnap_diff_bytes_checked(),
                "diff_us": self.panda.fastsnap_diff_us(),
                "report": self.panda.fastsnap_diff_report() if d else "",
                "dev_diff_sections": dev_n,
                "dev_diff_report": dev_report if dev_n else "",
            })
            if dev_n > 0:
                self.logger.error(
                    f"fastloop: DEVICE STATE NOT RESTORED - iteration "
                    f"{self._pending_verify} left {dev_n} device sections "
                    f"differing from the arm-time reference ({dev_report}). "
                    f"RAM can be byte-perfect and this still be wrong.")
            elif dev_n < 0:
                self.logger.warning(
                    f"fastloop: the device oracle could not compare at "
                    f"iteration {self._pending_verify}; a scoped block is "
                    f"unscored for this lap")
            if d < 0:
                self.logger.error(
                    f"fastloop: THE ORACLE IS BLIND - iteration "
                    f"{self._pending_verify} could not read the forked "
                    f"reference. Nothing about the reset follows from this "
                    f"lap, in either direction.")
            elif d > 0:
                self.logger.error(
                    f"fastloop: RESET IS NOT SOUND - iteration "
                    f"{self._pending_verify} left {d} pages differing from the "
                    f"forked reference (at {self.panda.fastsnap_diff_report()})")
            self._pending_verify = None

        if self.t_iter is not None:
            dt = (now - self.t_iter) * 1000.0
            # A verified lap carries the oracle's ~48 ms as well as the reset,
            # so it belongs in its own bucket. Folding it into iter_ms would
            # drag the median toward the cost of the instrument -- the same
            # mistake, one level up, that keeping diff_us out of last_us()
            # avoids inside QEMU.
            if was_verify:
                self.verify_iter_ms.append(dt)
            elif was_crash:
                # Separated because a crash-closed lap is a DIFFERENT
                # measurement, not an outlier to be smoothed away. Measured on
                # the first combined run: median lap 1.15 ms, mean 5.64 ms,
                # max 784 ms, and 533 crash-closed laps of 38,858 accounted for
                # very nearly all 220 s of wall clock. A single iter_ms bucket
                # hides that behind a healthy-looking median, and the median is
                # the number that gets quoted.
                self.crash_iter_ms.append(dt)
            else:
                self.iter_ms.append(dt)
        self.t_iter = now
        self.n_iters += 1
        self.t_loopN = now
        if self.n_iters >= self.want:
            self.state = "done"
            self.logger.info(f"fastloop: finished {self.n_iters} iterations")
            if self.mode != "bare":
                self.panda.fastsnap_schedule(self.panda.FASTSNAP_FORK_DROP)

    # ---- report -----------------------------------------------------------

    def uninit(self) -> None:
        it = _stats(self.iter_ms)
        out = {
            "mode": self.mode,
            "comm": self.comm,
            "detector": self.detector,
            "state": self.state,
            "hits": self.hits,
            "iterations": self.n_iters,
            "signal_laps": self.signal_laps,
            "reset_on_signal": self.reset_on_signal,
            "arm_us": self.arm_us,
            "arm_after_s": self.arm_after_s,
            "armed_at_s": self.t_arm_s,
            "ram_snapshot_bytes": self.snapshot_bytes,
            "sections_on_machine": len(self.all_sections),
            # The names, not just the count. Choosing an allowlist requires
            # knowing what is on the machine, and a run that recorded only a
            # count made the next run's configuration a guess.
            "sections": list(self.all_sections),
            # This plugin's own source hash. The project directories hold
            # COPIES of fastloop.py (the container cannot see the analysis
            # tree), so a run can silently measure a version older than the one
            # in git. Recording the hash makes a result traceable to a source
            # rather than to a filename.
            "plugin_sha256": self._self_sha256(),
            "denied": self.denied,
            "iter_ms": it,
            "verify_iter_ms": _stats(self.verify_iter_ms),
            "crash_iter_ms": _stats(self.crash_iter_ms),
            "bh_wall_ms": _stats(self.bh_wall_ms),
            "bh_wall_crash_ms": _stats(self.bh_wall_crash_ms),
            "sched_to_bh_ms": _stats(self.sched_ms),
            "bh_to_observed_ms": _stats(self.obs_ms),
            "sched_to_bh_crash_ms": _stats(self.sched_crash_ms),
            "bh_to_observed_crash_ms": _stats(self.obs_crash_ms),
            "sched_to_bh_verify_ms": _stats(self.sched_verify_ms),
            "bh_to_observed_verify_ms": _stats(self.obs_verify_ms),
            "reset_us": _stats(self.reset_us),
            "restored_pages": _stats(self.restored),
            "verifies": self.verifies,
            "split_order_control_diff_pages": self.split_diff,
            "errors": self.errors,
        }
        # exec/s from the MEDIAN interval, not from total/elapsed: the tail
        # includes whatever the guest does when the driver pauses, and a mean
        # over that reports the driver's duty cycle rather than the loop's rate.
        out["exec_per_s_median"] = (1000.0 / it["median"]) if it else None
        if self.t_loop0 and self.t_loopN and self.n_iters > 1:
            # Includes the verified laps, so it is BELOW the loop's rate by
            # however much the oracle cost. Reported as a cross-check on the
            # median rather than as the headline: if the two disagree by more
            # than the verify laps can account for, the median is hiding a tail.
            span = self.t_loopN - self.t_loop0
            out["exec_per_s_wall_incl_oracle"] = (
                (self.n_iters - 1) / span if span else None)
            out["loop_wall_s"] = span

        # A negative diff means the oracle could not look. That is neither a
        # pass nor an ordinary failure, and lumping it in with "pages differ"
        # would report a broken instrument as a broken reset.
        blind = [v for v in self.verifies if v["diff_pages"] < 0]
        bad = [v for v in self.verifies if v["diff_pages"] > 0]
        dev_bad = [v for v in self.verifies
                   if v.get("dev_diff_sections", 0) > 0]
        dev_blind = [v for v in self.verifies
                     if v.get("dev_diff_sections", 0) < 0]
        out["device_scope"] = ("allow", self.allowed) if self.allowed else (
            ("deny", self.denied) if self.denied else ("all", []))
        out["dev_diff_clean"] = len(self.verifies) - len(dev_bad) - len(dev_blind)
        if self.mode == "loop":
            if not self.verifies:
                out["verdict"] = ("UNVERIFIED: the loop ran but the oracle "
                                  "never did, so nothing here says the reset "
                                  "was correct")
            elif self.split_diff is None or self.split_diff <= 0:
                out["verdict"] = (
                    f"INVALID: the split-order control returned "
                    f"{self.split_diff}, so the oracle either cannot see a "
                    f"running guest or cannot read the reference at all; a "
                    f"clean verify would prove nothing about the reset")
            elif blind:
                out["verdict"] = (
                    f"INVALID: {len(blind)} of {len(self.verifies)} "
                    f"verifications could not read the forked reference. This "
                    f"is a broken oracle, not a broken reset, and the run says "
                    f"nothing either way.")
            elif bad:
                out["verdict"] = (f"FAILED: {len(bad)} of {len(self.verifies)} "
                                  f"verifications found the guest differing "
                                  f"from the reference after a reset")
            elif dev_bad:
                # Reported as a failure of the RUN, not a caveat on it. A
                # scoped block that leaves device state behind is the exact
                # thing the allowlist was supposed to be checked for, and a
                # clean RAM result sitting next to it is what would make this
                # easy to wave through.
                names = sorted({n for v in dev_bad
                                for n in v["dev_diff_report"].split(",") if n})
                out["verdict"] = (
                    f"FAILED: RAM came back clean on all "
                    f"{len(self.verifies)} verifications, but {len(dev_bad)} "
                    f"of them left device sections unrestored ({names}). The "
                    f"device scope in force does not cover what this workload "
                    f"touches.")
            elif self.allowed and dev_blind and not out.get("dev_diff_clean"):
                out["verdict"] = (
                    f"INVALID: an allowlist was in force and the device "
                    f"oracle could not compare on any of "
                    f"{len(self.verifies)} verifications, so nothing scored "
                    f"the sections it dropped")
            else:
                out["verdict"] = (
                    f"VALID: {len(self.verifies)} verifications, every one "
                    f"byte-identical to an independently forked reference "
                    f"across {self.verifies[0]['bytes_checked']} bytes, with "
                    f"{out['dev_diff_clean']} of them also finding every "
                    f"device section back where the arm left it")
            self.logger.info(f"fastloop: {out['verdict']}")

        path = os.path.join(self.outdir, "fastloop.json")
        with open(path, "w") as fh:
            json.dump(out, fh, indent=2)
        self.logger.info(
            f"fastloop: RESULTS mode={self.mode} iters={self.n_iters} "
            f"iter_median_ms={it['median'] if it else None} "
            f"exec_per_s={out['exec_per_s_median']} "
            f"reset_us_median="
            f"{out['reset_us']['median'] if out['reset_us'] else None} "
            f"restored_pages_median="
            f"{out['restored_pages']['median'] if out['restored_pages'] else None}"
        )
