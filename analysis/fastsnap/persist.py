"""Persistent-mode rewind at the parser: measure the guest-work ceiling.

The 8.7 ms currently spent per HTTP request is almost all *not* parsing. It is
guest TCP loopback, socket read, the response writev, and a trip through
lighttpd's event loop. A fastsnap iteration pays none of that -- it restores to
a point inside the parser and re-runs only the parse. So the question that
sizes the whole target is: how fast can the parse alone be driven?

This answers it without any snapshot machinery, using AFL's persistent-mode
trick (`__AFL_LOOP`) implemented entirely in a pyplugin.

MECHANISM. A uprobe fires at `http_request_parse` entry, and uprobes.py writes
modified pt_regs back to the guest (apis/uprobes.py:221-223). At entry, *before
the prologue has run*, LR still holds the caller's return address. Overwrite it
with the function's own entry address and the standard ARM epilogue
(`pop {r4-r11, pc}`) will pop our value instead -- the function returns into
itself, re-triggering this same uprobe. No uretprobe, so none of the return-
trampoline bookkeeping can be corrupted by re-entry.

r0-r3 are restored from the entry snapshot on every lap; without that the
parser re-runs on whatever pointers it happened to leave in the argument
registers, which is a fast SIGSEGV. r4-r11 are callee-saved and the epilogue
restores them; SP is push/pop balanced.

WHAT THIS IS NOT. State is not reset between laps, so lap 2 parses a buffer
lap 1 may have already consumed or mutated. That is precisely AFL persistent
mode's known unsoundness and it is why this measures a *ceiling*, not a usable
fuzzer. The number it produces is the rate an iteration could reach if reset
were free -- which is the number worth knowing before building reset.

CONTROL: `laps: 0` installs the identical probe and does no rewinding. Both
modes therefore pay the same per-entry probe cost, so the difference between
them is attributable to the rewind and not to instrumentation.
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

uprobes = plugins.uprobes

ARG_REGS = ("r0", "r1", "r2", "r3")


class Persist(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.path = self.get_arg("path") or "/usr/sbin/lighttpd"
        self.symbol = self.get_arg("symbol") or "http_request_parse"
        self.laps_per_entry = int(self.get_arg("laps") or 0)
        self.max_total = int(self.get_arg("max_total") or 200000)

        self.entry_pc = None
        self.real_lr = None
        self.saved_args = None
        self.remaining = 0
        self.n_entries = 0      # every probe hit, rewound or not
        self.n_fresh = 0        # hits that arrived from a real caller
        self.n_rewinds = 0
        self.t_first = None
        self.t_last = None
        self.t_prev = None
        # Intervals between consecutive entries WITHIN a burst. The overall
        # span is useless as a rate: entries arrive in bursts separated by the
        # guest's idle time between connections, so entries/span measures the
        # request arrival rate, not the lap rate. Each of these deltas is one
        # lap: probe round trip + one execution of the parser.
        self.lap_ms = []
        self.errors = []

        lib, off = plugins.symbols.lookup(self.path, self.symbol)
        if off is None:
            self.logger.error(
                f"persist: SYMBOL RESOLUTION FAILED for {self.symbol} in "
                f"{self.path}; no probe placed, this run measures nothing.")
            self.resolved = None
        else:
            self.resolved = f"{lib}+{off:#x}"
            uprobes.uprobe(path=self.path, symbol=self.symbol, on_enter=True,
                           fail_register_ok=False)(self.on_entry)

        mode = "CONTROL (no rewind)" if self.laps_per_entry == 0 else \
            f"LOOP laps={self.laps_per_entry}"
        self.logger.info(
            f"persist: {mode} on {self.symbol} @ {self.resolved}")

    def on_entry(self, regs, *args, **kwargs):
        now = time.time()
        self.n_entries += 1
        if self.t_first is None:
            self.t_first = now
        self.t_last = now

        try:
            if self.remaining > 0 and self.t_prev is not None:
                self.lap_ms.append((now - self.t_prev) * 1000.0)
            self.t_prev = now

            if self.remaining > 0:
                # A lap we caused. Put the input arguments back so the parser
                # sees the same call it saw the first time.
                self.remaining -= 1
                self.n_rewinds += 1
                for name, val in zip(ARG_REGS, self.saved_args):
                    regs.set_register(name, val)
                if self.remaining > 0 and self.n_entries < self.max_total:
                    regs.lr = self.entry_pc
                else:
                    regs.lr = self.real_lr      # last lap: return to the caller
            else:
                # A genuine call from lighttpd. Snapshot it and start a burst.
                self.n_fresh += 1
                self.entry_pc = regs.pc
                self.real_lr = regs.lr
                self.saved_args = [regs.get_register(n) for n in ARG_REGS]
                if self.laps_per_entry > 0 and self.n_entries < self.max_total:
                    self.remaining = self.laps_per_entry
                    regs.lr = self.entry_pc
        except Exception as e:                      # noqa: BLE001
            if len(self.errors) < 5:
                self.errors.append(repr(e))
        return
        yield

    def uninit(self) -> None:
        span = None
        rate = None
        if self.t_first is not None and self.t_last is not None:
            span = self.t_last - self.t_first
            if span > 0:
                rate = self.n_entries / span

        lap = None
        if self.lap_ms:
            v = sorted(self.lap_ms)
            lap = {"n": len(v), "median_ms": statistics.median(v),
                   "p10_ms": v[max(0, len(v) // 10)],
                   "p90_ms": v[min(len(v) - 1, 9 * len(v) // 10)]}
            self.logger.info(f"persist: per-lap interval {lap}")

        out = {
            "lap_interval": lap,
            "lap_rate_per_s": (1000.0 / lap["median_ms"]) if lap else None,
            "symbol": self.symbol, "path": self.path,
            "resolved": self.resolved,
            "mode": "control" if self.laps_per_entry == 0 else "loop",
            "laps_per_entry": self.laps_per_entry,
            "entries": self.n_entries, "fresh_calls": self.n_fresh,
            "rewinds": self.n_rewinds,
            "span_s": span, "entries_per_s": rate,
            "errors": self.errors,
        }
        self.logger.info(f"persist: RESULTS {out}")
        if self.resolved is None:
            self.logger.error(
                "persist: probe was never placed - this run says nothing.")
        elif self.n_entries == 0:
            self.logger.error(
                "persist: probe placed but never hit - the parser was not "
                "reached. Not a zero-rate result; a no-data result.")
        if self.outdir:
            p = os.path.join(self.outdir, "persist.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"persist: wrote {p}")
