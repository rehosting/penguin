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
  mode=none     take a block, never restore -- NEGATIVE CONTROL, expect no
                cliff, and isolates any cliff in `fast` to the restore rather
                than to the take or to the measurement itself

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

        if self.mode not in ("fast", "loadvm", "none"):
            raise ValueError(f"devblock: unknown mode {self.mode!r}")

        self.hits = 0
        self.state = "warmup"        # warmup -> taking -> loop -> done
        self.errors = []
        self.n_restores = 0

        self.shape = None            # sections/bytes, once taken
        self.all_sections = []
        self.denied = []
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

        self.have_api = bool(getattr(self.panda, "fastsnap_available", None)
                             and self.panda.fastsnap_available())
        if self.mode == "fast" and not self.have_api:
            self.logger.error(
                "devblock: this QEMU build does not export the fastsnap ABI, "
                "so mode=fast cannot run. Build penguin with "
                "--override-input penguin-qemu <qemu_builder>.")
            self.state = "done"

        syscalls.syscall(f"on_sys_{self.detector}_enter",
                         comm_filter=self.comm)(self.on_hit)
        self.logger.info(
            f"devblock: mode={self.mode} detector={self.detector} "
            f"comm={self.comm} warmup={self.warmup} restores={self.want} "
            f"window={self.window} fastsnap_api={self.have_api}")

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
            self.denied = chosen
            if chosen:
                self.panda.fastsnap_set_denylist(chosen)
                self.logger.info(f"devblock: excluding {len(chosen)}: {chosen}")
        except Exception as e:                           # noqa: BLE001
            self.errors.append(f"denylist: {e!r}")

    def _record_shape(self):
        try:
            self.shape = {
                "sections": self.panda.fastsnap_section_count(),
                "bytes": self.panda.fastsnap_block_size(),
            }
            self.logger.info(f"devblock: block {self.shape}")
        except Exception as e:                           # noqa: BLE001
            self.errors.append(f"shape: {e!r}")

    def _do_restore(self):
        self.sched_t = time.perf_counter()
        if self.mode == "loadvm":
            self.panda.schedule_snapshot(self.tag, load=True)
        else:
            self.seq_at_sched = self.panda.fastsnap_seq()
            self.panda.fastsnap_schedule(self.panda.FASTSNAP_RESTORE)

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
                if self.mode == "none" or self.want <= 0:
                    self.state = "done"
                    self.logger.info("devblock: CONTROL - not restoring")
                else:
                    self.state = "loop"
                    self.win_mode = "before"

            elif self.state == "loop":
                if self.win_mode == "before" and len(self.win_before) >= self.window:
                    self._do_restore()
                    self.win_mode = "pending"
                elif self.win_mode == "pending":
                    # first hit after the restore's bottom half
                    if self.mode != "loadvm":
                        if self.panda.fastsnap_seq() > self.seq_at_sched:
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
