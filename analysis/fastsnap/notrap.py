"""No trap at all: how fast can the guest be reset by snapshot restore?

Every iteration measured so far pays a guest trap -- 252 us at a uprobe, 133 us
at a syscall boundary. A fastsnap iteration is supposed to pay neither: the
restore puts the CPU back with PC already at the injection point, so the guest
resumes inside the target with no breakpoint, no kernel handler and no
hypercall. This measures what that costs today, with the machinery penguin
already ships (full savevm/loadvm), which is the baseline the fast-reset work
has to beat.

WHY IT IS DRIVEN THIS WAY. panda.load_snapshot() is synchronous but must be
called from the main loop, and there is no main-loop Python context: pyplugin
callbacks arrive on vCPU threads via hypercall, which is why even
Snapshot._do_save_now uses schedule_snapshot(). So the loop is asynchronous --
schedule a restore, then detect that the guest is running again -- and the
detector is one syscall hook whose cost (133 us, measured) is subtracted.

WHERE THE SNAPSHOT IS TAKEN MATTERS. Saved while lighttpd idles in epoll_wait,
every restore would resume into a blocking wait and the detector latency would
be the idle timeout rather than the restore. So the save is triggered from a
syscall the server only makes while actively serving a request, and the same
syscall is the detector: on resume the guest is mid-request and reaches it
again quickly.

CONTROL. `restores: 0` arms everything and takes the snapshot but never
restores, so a run that wedges can be attributed to the save path rather than
the restore loop.
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls


class NoTrap(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.tag = self.get_arg("tag") or "notrap"
        self.want = int(self.get_arg("restores") or 25)
        self.warmup = int(self.get_arg("warmup") or 40)
        self.detector = self.get_arg("detector") or "writev"
        # Measured cost of the detector hook itself (syscall boundary), ms.
        self.detector_ms = float(self.get_arg("detector_ms") or 0.133)

        self.hits = 0
        self.state = "warmup"          # warmup -> saving -> loop -> done
        self.save_sched_t = None
        self.save_ms = None
        self.restore_sched_t = None
        self.cycles = []
        self.errors = []
        self.n_restores = 0

        syscalls.syscall(f"on_sys_{self.detector}_enter",
                         comm_filter=self.comm)(self.on_hit)
        self.logger.info(
            f"notrap: armed on {self.detector} (comm={self.comm}); will save "
            f"'{self.tag}' after {self.warmup} hits, then {self.want} restores")

    def on_hit(self, *args, **kwargs):
        now = time.perf_counter()
        self.hits += 1
        try:
            if self.state == "warmup":
                if self.hits >= self.warmup:
                    self.state = "saving"
                    self.save_sched_t = now
                    ok = self.panda.schedule_snapshot(self.tag, load=False)
                    self.logger.info(f"notrap: save scheduled ok={ok}")
                    if not ok:
                        self.state = "done"
                        self.errors.append("schedule_snapshot(save) returned False")

            elif self.state == "saving":
                # First hit after the save bottom-half ran: the guest is
                # executing again, so the save is complete.
                self.save_ms = (now - self.save_sched_t) * 1000.0
                self.logger.info(
                    f"notrap: save observed complete after "
                    f"{self.save_ms:.2f} ms (includes detector latency)")
                if self.want <= 0:
                    self.state = "done"
                    self.logger.info("notrap: CONTROL (restores=0) - not looping")
                else:
                    self.state = "loop"
                    self.restore_sched_t = time.perf_counter()
                    self.panda.schedule_snapshot(self.tag, load=True)

            elif self.state == "loop":
                if self.restore_sched_t is not None:
                    self.cycles.append((now - self.restore_sched_t) * 1000.0)
                    self.n_restores += 1
                    if self.n_restores % 5 == 0:
                        self.logger.info(
                            f"notrap: {self.n_restores}/{self.want} restores, "
                            f"last {self.cycles[-1]:.2f} ms")
                if self.n_restores >= self.want:
                    self.state = "done"
                    self.logger.info("notrap: restore loop finished")
                else:
                    self.restore_sched_t = time.perf_counter()
                    self.panda.schedule_snapshot(self.tag, load=True)
        except Exception as e:                          # noqa: BLE001
            if len(self.errors) < 5:
                self.errors.append(repr(e))
            self.state = "done"
        return
        yield

    def uninit(self) -> None:
        st = None
        if self.cycles:
            v = sorted(self.cycles)
            st = {"n": len(v), "median_ms": statistics.median(v),
                  "min_ms": v[0], "p10_ms": v[max(0, len(v) // 10)],
                  "p90_ms": v[min(len(v) - 1, 9 * len(v) // 10)]}

        out = {"tag": self.tag, "detector": self.detector, "comm": self.comm,
               "hits": self.hits, "state": self.state,
               "save_observed_ms": self.save_ms,
               "restores": self.n_restores, "cycle": st,
               "detector_ms_subtracted": self.detector_ms,
               "restore_ms_est": (st["median_ms"] - self.detector_ms)
               if st else None,
               "restores_per_s_est": (1000.0 / st["median_ms"]) if st else None,
               "errors": self.errors}

        self.logger.info(f"notrap: RESULTS {out}")
        if self.state != "done":
            self.logger.error(
                f"notrap: loop did not finish (state={self.state}, "
                f"hits={self.hits}) - the run ended first or the guest stopped "
                "reaching the detector.")
        if not self.cycles and self.want > 0:
            self.logger.error(
                "notrap: no restore cycles recorded - no-data, not zero-cost.")

        if self.outdir:
            p = os.path.join(self.outdir, "notrap.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"notrap: wrote {p}")
