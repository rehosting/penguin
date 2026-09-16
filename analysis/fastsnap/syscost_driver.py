"""Read the driver-side per-syscall portal cost -- and prove it measures time.

`speedscheme.py` prices a hooked syscall at 95.880 us and an unhooked one at
1.161 us from a HOST clock. That says what the round trip costs but not where
inside it the time goes, and a host-side observer structurally cannot see the
guest half: it learns whether the HOST was told, never whether the guest
trapped. The scoped experiment built to separate them could not, because the
clock is delivered by a hooked marker syscall and analysis_scope gates hooks
off -- the instrument gated away its own clock.

igloo_driver now brackets `do_hyp()` with ktime and accumulates
{count, total_ns, max_ns} per syscall name. This reads that back.

THE CONTROL IS THE POINT OF THIS FILE. Guest ktime across a hypercall is not
obviously meaningful: the guest is stopped while the host works, and whether
its clock advances over that gap depends on the timekeeping the emulator
presents. A plausible-looking table of nanoseconds proves nothing on its own.

So this burns a KNOWN amount of host time inside the hooked callback and
checks that it comes back out of the driver's own numbers:

    host burns BURN_MS per call, n calls
    ==> driver must report total_ns ~= n * BURN_MS

If it does, guest ktime spans the hypercall and every other number the
accumulator produces is trustworthy. If it comes back near zero, the guest's
clock does NOT advance while the host works, the instrument is measuring the
guest-side entry and exit only, and no conclusion about the 94.7 us split may
be drawn from it. Either way the answer is reported; the failing case is the
one this exists to catch, so it is never silently skipped.
"""
import json
import time

from penguin import Plugin, plugins

# Sub-commands; must match enum igloo_syscost_cmd in syscost_stats.h.
CMD_READ = 0
CMD_ENABLE = 1
CMD_DISABLE = 2


class SyscostDriver(Plugin):
    def __init__(self):
        self.comm = self.get_arg("comm") or "speedprobe"
        self.outdir = self.get_arg("outdir")
        # Milliseconds of host time to burn per marker call. Large enough that
        # it cannot hide in noise: at 95.880 us a natural round trip, a 5 ms
        # burn is ~50x the thing it has to be distinguished from.
        self.burn_ms = float(self.get_arg("burn_ms") or 5.0)
        # Marker calls to burn on. The control needs enough to average, and
        # each one costs burn_ms of wall clock.
        self.burn_calls = int(self.get_arg("burn_calls") or 200)
        self.n_marks = 0
        self.n_burned = 0
        self.burn_wall_s = 0.0
        self.report = None
        self.enabled_ok = False

        from hyper.consts import HYPER_OP as hop
        self.hop = hop
        # An older driver has no such op. Say so rather than calling whatever
        # op happens to sit at that number: the enum is read from DWARF, so a
        # matched pair is fine and a mismatched pair would quietly call
        # something else and report whatever it returned.
        if not hasattr(hop, "HYPER_OP_SYSCALL_COST_STATS"):
            self.logger.error(
                "syscost_driver: this igloo_driver has no SYSCALL_COST_STATS "
                "op -- rebuild the module from this branch. Reporting "
                "nothing rather than guessing an op number.")
            self.op = None
        else:
            self.op = hop.HYPER_OP_SYSCALL_COST_STATS

        plugins.syscalls.syscall("on_sys_getppid_enter",
                                 comm_filter=self.comm,
                                 scope_filter=False)(self.on_burn)

    # ---- the control -------------------------------------------------
    def on_burn(self, regs, proto, syscall, *a):
        """Drive the whole experiment from inside the marker hook.

        Everything here needs a coroutine context, because enabling and
        reading the accumulator are portal calls. The marker syscall is the
        only place that reliably has one while the guest is alive, so the
        sequence is a state machine over marker call number:

            call 1                  enable + reset the accumulator
            calls 2 .. N+1          burn a known BURN_MS of HOST time
            call N+2                read it back and form the verdict

        The guest is stopped for the whole of each burn. If guest ktime spans
        the hypercall, the driver's bracket around do_hyp() must see it; if it
        does not, the accumulator is measuring something other than the round
        trip and this is what says so.
        """
        self.n_marks += 1
        if self.n_marks == 1:
            yield from self.enable()
            return
        if self.n_marks <= self.burn_calls + 1:
            t0 = time.perf_counter()
            deadline = t0 + self.burn_ms / 1000.0
            # A spin, not time.sleep(): sleep yields and the emulator may run
            # the guest again, which would put guest execution inside the very
            # window being measured. A spin holds the portal thread and keeps
            # the guest stopped, which is the condition under test.
            while time.perf_counter() < deadline:
                pass
            self.burn_wall_s += time.perf_counter() - t0
            self.n_burned += 1
            return
        if self.n_marks == self.burn_calls + 2:
            yield from self.read()
            v = self.verdict()
            self.logger.info(f"syscost_driver verdict: {v.get('status')}")
            for k in ("driver_marker_s", "host_burn_total_s",
                      "ratio_seen_over_burned", "driver_n_calls"):
                if k in v:
                    self.logger.info(f"  {k} = {v[k]}")

    # ---- reading the accumulator -------------------------------------
    def _call(self, cmd):
        from hyper.portal import PortalCmd
        from hyper.ffi import kffi
        raw = yield PortalCmd(self.op, addr=cmd)
        if not raw:
            return None
        r = kffi.from_buffer("igloo_syscost_report", raw)
        out = {"enabled": int(r.enabled), "n_calls": int(r.n_calls),
               "total_ns": int(r.total_ns), "dropped": int(r.dropped),
               "names_seen": int(r.names_seen), "entries": []}
        for i in range(int(r.n_entries)):
            e = r.entries[i]
            nm = bytes(e.name)
            nm = nm.split(b"\0", 1)[0].decode("latin-1", "replace")
            out["entries"].append({"name": nm, "count": int(e.count),
                                   "total_ns": int(e.total_ns),
                                   "max_ns": int(e.max_ns)})
        return out

    def enable(self):
        if self.op is None:
            return None
        r = yield from self._call(CMD_ENABLE)
        self.enabled_ok = bool(r and r["enabled"])
        return r

    def read(self):
        if self.op is None:
            return None
        self.report = yield from self._call(CMD_READ)
        return self.report

    # ---- the verdict --------------------------------------------------
    def verdict(self):
        """Did the driver's clock see the host burn? Returns a dict."""
        r = self.report
        v = {"burn_calls_done": self.n_burned,
             "burn_ms_each": self.burn_ms,
             "host_burn_total_s": round(self.burn_wall_s, 6)}
        if not r:
            v["status"] = "NO REPORT -- op missing or portal read failed"
            return v
        marker = next((e for e in r["entries"] if e["name"].endswith("getppid")),
                      None)
        v["driver_total_ns"] = r["total_ns"]
        v["driver_n_calls"] = r["n_calls"]
        v["marker"] = marker
        if not marker or not marker["count"]:
            v["status"] = ("NO MARKER ROWS -- the driver bracketed no getppid "
                           "hypercall, so the control could not run")
            return v
        seen_s = marker["total_ns"] / 1e9
        v["driver_marker_s"] = round(seen_s, 6)
        # The burn is a floor, not an equality: the round trip costs its own
        # time on top, so seeing MORE than the burn is expected and seeing
        # much less is the failure.
        ratio = seen_s / self.burn_wall_s if self.burn_wall_s else 0.0
        v["ratio_seen_over_burned"] = round(ratio, 4)
        if ratio >= 0.8:
            v["status"] = "OK -- guest ktime spans the hypercall"
            v["trustworthy"] = True
        elif ratio <= 0.2:
            v["status"] = ("BROKEN -- the driver saw ~none of the host burn, "
                           "so guest ktime does NOT advance while the host "
                           "works. Every per-syscall number from this "
                           "accumulator measures only the guest-side entry "
                           "and exit and must NOT be read as round-trip cost.")
            v["trustworthy"] = False
        else:
            v["status"] = ("AMBIGUOUS -- the driver saw part of the burn. "
                           "Neither reading is safe; do not use the numbers.")
            v["trustworthy"] = False
        return v

    def uninit(self):
        if not self.outdir:
            return
        import os
        os.makedirs(self.outdir, exist_ok=True)
        with open(os.path.join(self.outdir, "syscost_driver.json"), "w") as f:
            json.dump({"report": self.report, "verdict": self.verdict()},
                      f, indent=2)
