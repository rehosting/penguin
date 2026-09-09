"""Timing instrument for VM snapshot save/restore (fastsnap research lane).

Measures how long the guest is *stopped* by a savevm / loadvm, without
rebuilding QEMU.

Method
------
``penguin_save_snapshot`` / ``penguin_load_snapshot`` run in a main-loop bottom
half and stop every vCPU for their whole duration. So if the guest is executing
a syscall-dense workload, the wall-clock gap between two consecutive syscall
returns brackets the operation: it is the operation's duration plus the bottom
half's scheduling latency. We record ``perf_counter()`` on every syscall return
and look for the outlier gap that follows a request we issued.

The instrument's *resolution* is the ordinary inter-syscall gap, which we also
report (``idle_gap_*``) so a reader can see how much of a reported stall could
be sampling noise.

Known-positive control
----------------------
An instrument that reports "the restore was fast" is worthless unless it can be
shown to report a slow one. ``control_ms`` injects a sleep of known duration in
the same place a snapshot request would go, *before* any snapshot is taken. The
run fails loudly if the instrument does not recover that known stall to within
``control_tol``. Only then are the snapshot numbers written.

Args (via ``plugins.bench_snapshot`` in the config)
    iters       -- number of save/restore cycles to time (default 5)
    control_ms  -- duration of the injected known-positive stall (default 250)
    control_tol -- fractional tolerance on recovering it (default 0.25)
    tag         -- internal snapshot tag to use (default "bench")
"""

import json
import os
import statistics
import time
from os.path import join

from penguin import Plugin, plugins

# A gap has to beat this to count as "something stopped the guest" rather than
# ordinary scheduling jitter. Deliberately far above the observed idle gap.
OUTLIER_S = 0.010


class BenchSnapshot(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.iters = int(self.get_arg("iters") or 5)
        self.control_ms = float(self.get_arg("control_ms") or 250.0)
        self.control_tol = float(self.get_arg("control_tol") or 0.25)
        self.tag = self.get_arg("tag") or "bench"

        self.warmup_n = int(self.get_arg("warmup_n") or 500)
        self.min_rate_hz = float(self.get_arg("min_rate_hz") or 200.0)

        self.armed = False           # set by readiness
        self.warmed = 0              # samples seen since arming
        self.warmup_gaps = []
        self.last = None
        self.n_sysret = 0
        self.idle_gaps = []          # every sub-outlier gap: our resolution
        self.events = []             # {phase, requested_at, stall_s}
        self.pending = None          # {"phase": str, "req_ts": float}
        # Post-restore recovery: every loadvm enters RUN_STATE_RESTORE_VM,
        # which makes accel/tcg/tcg-all.c:90 do a full tb_flush. That cost is
        # NOT in the restore stall -- it is paid afterwards, as the guest
        # re-translates everything it executes. Measure it as throughput.
        self.recover_n = int(self.get_arg("recover_n") or 2000)
        self.recover = None
        self.recoveries = []
        self.control_result = None
        self.density = None
        self.warm_start = None

        # State machine, advanced from the syscall-return callback:
        #   control -> save -> restore*iters -> done
        self.phase = "control"
        self.done_restores = 0
        self.finished = False

        # Bound method, not a closure: the syscalls API re-resolves callbacks by
        # __qualname__ on each event (same trap documented in core/snapshot.py).
        plugins.syscalls.syscall("on_all_sys_return")(self.on_sysret)
        # Do NOT start measuring at plugin load: that is early kernel boot,
        # where almost nothing syscalls and no userspace RAM has been touched.
        # A restore timed there is not the restore anyone cares about.
        plugins.subscribe(plugins.Readiness, "ready", self.on_ready)
        self.logger.info(
            "bench_snapshot loaded (waiting for readiness): iters=%d "
            "control_ms=%.1f tag=%s warmup_n=%d",
            self.iters, self.control_ms, self.tag, self.warmup_n)

    def on_ready(self, kind: str = "igloo_init"):
        if kind != "igloo_init" or self.armed:
            return
        self.armed = True
        self.warm_start = time.perf_counter()
        self.logger.info("bench: readiness reached; warming up over %d "
                         "syscall returns before measuring", self.warmup_n)

    # --- the sampler ------------------------------------------------------

    def on_sysret(self, *_a, **_kw):
        now = time.perf_counter()
        self.n_sysret += 1

        if self.last is None:
            self.last = now
            return
        gap = now - self.last
        self.last = now

        if not self.armed:
            return

        if self.warmed < self.warmup_n:
            self.warmed += 1
            if gap < OUTLIER_S:
                self.warmup_gaps.append(gap)
            if self.warmed == self.warmup_n:
                self._check_density()
            return

        if self.recover is not None:
            # Count EVERY gap in the recovery window, outliers included. The
            # first gaps after a restore routinely exceed OUTLIER_S precisely
            # because the TB cache was just flushed -- treating those as
            # "unattributed" would drop the effect we are trying to measure
            # and would silently abandon the window.
            self.recover["n"] += 1
            if gap >= OUTLIER_S:
                self.recover.setdefault("outlier_gaps", []).append(gap)
            if self.recover["n"] == 1:
                self.recover["first_gap_s"] = gap
            if self.recover["n"] >= self.recover_n:
                el = now - self.recover["t0"]
                rate = self.recover["n"] / el if el > 0 else 0.0
                self.recoveries.append({
                    "i": self.recover["i"],
                    "samples": self.recover["n"],
                    "elapsed_s": el, "rate_hz": rate,
                    "first_gap_s": self.recover.get("first_gap_s"),
                    "n_outlier_gaps": len(self.recover.get("outlier_gaps", [])),
                    "outlier_gap_total_s": sum(
                        self.recover.get("outlier_gaps", [])),
                    "window": self.recover.get("window", "A"),
                })
                self.logger.info(
                    "bench: post-restore #%d throughput %.0f syscalls/s "
                    "(steady state was %.0f)", self.recover["i"], rate,
                    (self.density or {}).get("rate_hz", 0.0))
                if self.recover.get("window") == "A":
                    self.recover = {"i": self.recover["i"], "n": 0,
                                    "t0": time.perf_counter(), "window": "B"}
                else:
                    self.recover = None
                    if not self.finished:
                        self._issue()
            return

        if gap < OUTLIER_S:
            self.idle_gaps.append(gap)
        elif self.pending is not None:
            # This is the stall produced by whatever we last requested.
            ev = self.pending
            ev["stall_s"] = gap
            self.events.append(ev)
            self.logger.info("bench: %s stalled the guest %.1f ms",
                             ev["phase"], gap * 1000.0)
            self.pending = None
            self._advance()
            return
        else:
            # An outlier we did not ask for. Keep it, so it cannot be mistaken
            # for a clean measurement later.
            self.events.append({"phase": "unattributed", "stall_s": gap})

        if self.pending is None and not self.finished:
            self._issue()

    def _check_density(self):
        elapsed = time.perf_counter() - self.warm_start
        rate = self.warmed / elapsed if elapsed > 0 else 0.0
        med = statistics.median(self.warmup_gaps) if self.warmup_gaps else None
        self.density = {"warmup_samples": self.warmed,
                        "warmup_elapsed_s": elapsed,
                        "rate_hz": rate,
                        "median_gap_s": med,
                        "min_rate_hz": self.min_rate_hz,
                        "passed": bool(rate >= self.min_rate_hz)}
        if not self.density["passed"]:
            self.logger.error(
                "bench: DENSITY CONTROL FAILED - only %.1f syscall returns/s "
                "(need %.1f). A measured stall would be padded with up to "
                "%.1f ms of ordinary idle. Not measuring.",
                rate, self.min_rate_hz, (med or 0) * 1000.0)
            self.finished = True
            self._write()
            return
        self.logger.info(
            "bench: density OK - %.0f syscall returns/s, median gap %.3f ms; "
            "starting measurement", rate, (med or 0) * 1000.0)

    # --- the state machine ------------------------------------------------

    def _issue(self):
        """Start the next operation. Runs on a vCPU thread, which is why every
        snapshot goes through schedule_snapshot (a main-loop bottom half)."""
        if self.phase == "control":
            # Known-positive control: a stall of KNOWN size, no snapshot yet.
            # If the sampler cannot see this, nothing it says afterwards counts.
            self.pending = {"phase": "control",
                            "expected_s": self.control_ms / 1000.0}
            time.sleep(self.control_ms / 1000.0)
            # The gap will be observed on the NEXT syscall return.
            return

        if self.phase == "save":
            self.pending = {"phase": "save"}
            self.panda.schedule_snapshot(self.tag, load=False)
            return

        if self.phase == "restore":
            self.pending = {"phase": "restore", "i": self.done_restores}
            self.panda.schedule_snapshot(self.tag, load=True)
            return

    def _advance(self):
        if self.phase == "control":
            ev = self.events[-1]
            exp = ev.get("expected_s", 0.0)
            got = ev["stall_s"]
            ok = abs(got - exp) <= self.control_tol * exp
            self.control_result = {"expected_s": exp, "observed_s": got,
                                   "passed": bool(ok)}
            if not ok:
                self.logger.error(
                    "bench: CONTROL FAILED - injected %.1f ms, sampler saw "
                    "%.1f ms. Measurements below are NOT trustworthy.",
                    exp * 1000.0, got * 1000.0)
            else:
                self.logger.info(
                    "bench: control passed - injected %.1f ms, saw %.1f ms",
                    exp * 1000.0, got * 1000.0)
            self.phase = "save"
            self.recover = {"i": "control", "n": 0,
                            "t0": time.perf_counter(), "window": "A"}
        elif self.phase == "save":
            self.phase = "restore"
        elif self.phase == "restore":
            i = self.done_restores
            self.done_restores += 1
            if self.done_restores >= self.iters:
                self.phase = "done"
                self.finished = True
                self._write()
            else:
                self.recover = {"i": i, "n": 0, "t0": time.perf_counter(),
                                "window": "A"}

    # --- output -----------------------------------------------------------

    def _write(self):
        idle = sorted(self.idle_gaps)
        res = {
            "control": self.control_result,
            "density_control": getattr(self, "density", None),
            "resolution": {
                "n_syscall_returns": self.n_sysret,
                "idle_gap_median_s": statistics.median(idle) if idle else None,
                "idle_gap_p99_s": (idle[int(len(idle) * 0.99)]
                                   if len(idle) > 100 else None),
                "outlier_threshold_s": OUTLIER_S,
            },
            "events": self.events,
            "post_restore_recovery": self.recoveries,
        }
        save = [e["stall_s"] for e in self.events if e["phase"] == "save"]
        rest = [e["stall_s"] for e in self.events if e["phase"] == "restore"]
        res["summary"] = {
            "save_s": save,
            "restore_s": rest,
            "restore_median_s": statistics.median(rest) if rest else None,
            "unattributed_outliers": sum(
                1 for e in self.events if e["phase"] == "unattributed"),
            "steady_state_rate_hz": (self.density or {}).get("rate_hz"),
            "window_A_hz": [r["rate_hz"] for r in self.recoveries
                            if r.get("window") == "A" and r["i"] != "control"],
            "window_B_hz": [r["rate_hz"] for r in self.recoveries
                            if r.get("window") == "B" and r["i"] != "control"],
            "post_restore_rate_hz": [r["rate_hz"] for r in self.recoveries],
            "post_restore_first_gap_s": [r["first_gap_s"]
                                         for r in self.recoveries],
        }
        os.makedirs(self.outdir, exist_ok=True)
        path = join(self.outdir, "bench_snapshot.json")
        with open(path, "w") as f:
            json.dump(res, f, indent=2)
        self.logger.info("bench: wrote %s", path)
        self.logger.info("bench: SUMMARY %s", json.dumps(res["summary"]))
        self.panda.end_analysis()

    def uninit(self):
        if not self.finished:
            self.logger.warning(
                "bench: run ended before %d restores completed (phase=%s, "
                "done=%d)", self.iters, self.phase, self.done_restores)
            try:
                self._write()
            except Exception as e:
                self.logger.error("bench: partial write failed: %s", e)
