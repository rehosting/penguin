"""Is a syscall boundary cheaper to hook than a uprobe?

It should be, and for a structural reason: igloo_driver already hypercalls on
every syscall enter and return, so a syscall hook adds no NEW guest trap -- it
is portal dispatch on a trap the guest was taking anyway. A uprobe adds a
breakpoint instruction, a kernel uprobe handler, and an execute-out-of-line
single-step that would not otherwise happen, all executing as emulated ARM.

The uprobe bracket costs 253 us, of which ~76 us is host-side Python and
~177 us is guest-side. If the structural argument is right, a syscall bracket
should land near the host-side figure instead.

METHOD. Bracket enter->return on several candidate syscalls at once and report
every one that fires. This doubles as a frequency census: the cheapest syscall
that fires often enough for a stable median is the one to read.

CONFOUND, stated up front. A syscall bracket measures hook overhead PLUS the
kernel's own work for that syscall, which a 12-byte probed function does not
have. So each number is an UPPER bound on the hook cost, and the cheapest
syscall gives the tightest bound. That is why several are measured rather than
one: if the cheapest and the most expensive differ by less than their distance
from the uprobe figure, the comparison survives the confound.

Run this alongside parsecost so the uprobe and syscall numbers come from the
same run -- an end-to-end A/B across runs is not resolvable on this target
(identical configs gave 41.21 s and 34.69 s drive windows).
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

# Cheap first, so the tightest bound is likely near the top.
CANDIDATES = [
    "getpid", "gettimeofday", "clock_gettime", "getuid", "geteuid",
    "fcntl64", "fcntl", "close", "epoll_ctl", "setsockopt", "poll",
    "epoll_wait", "accept", "writev", "read", "write", "stat64", "open",
]


class HookCost(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or None
        raw = self.get_arg("syscalls") or CANDIDATES
        self.syms = list(dict.fromkeys(raw))   # config merge concatenates lists
        self.samples = {n: [] for n in self.syms}
        self.py_ms = {n: [] for n in self.syms}
        self._open = {n: None for n in self.syms}
        self.registered = []
        self.failed = []

        for name in self.syms:
            try:
                kw = {}
                if self.comm:
                    kw["comm_filter"] = self.comm
                syscalls.syscall(f"on_sys_{name}_enter", **kw)(
                    self._mk_enter(name))
                syscalls.syscall(f"on_sys_{name}_return", **kw)(
                    self._mk_return(name))
                self.registered.append(name)
            except Exception as e:                       # noqa: BLE001
                self.failed.append(f"{name}: {e!r}")

        self.logger.info(
            f"hookcost: bracketing {len(self.registered)} syscalls "
            f"(comm={self.comm}); failed={len(self.failed)}")
        if self.failed:
            self.logger.info(f"hookcost: not registered: {self.failed[:6]}")

    def _mk_enter(self, name):
        def enter(*args, **kwargs):
            t0 = time.perf_counter()
            self._open[name] = t0
            self.py_ms[name].append((time.perf_counter() - t0) * 1000.0)
            return
            yield
        enter.__name__ = f"hc_enter_{name}"
        return enter

    def _mk_return(self, name):
        def ret(*args, **kwargs):
            tin = time.perf_counter()
            t0 = self._open[name]
            self._open[name] = None
            if t0 is not None:
                self.samples[name].append((tin - t0) * 1000.0)
            self.py_ms[name].append((time.perf_counter() - tin) * 1000.0)
            return
            yield
        ret.__name__ = f"hc_ret_{name}"
        return ret

    def uninit(self) -> None:
        def stats(v):
            if not v:
                return None
            v = sorted(v)
            return {"n": len(v), "median_ms": statistics.median(v),
                    "p10_ms": v[max(0, len(v) // 10)],
                    "p90_ms": v[min(len(v) - 1, 9 * len(v) // 10)]}

        st = {n: stats(self.samples[n]) for n in self.syms}
        fired = {n: v for n, v in st.items() if v}
        self.logger.info("hookcost: RESULTS (enter->return bracket)")
        for n, v in sorted(fired.items(), key=lambda kv: kv[1]["median_ms"]):
            self.logger.info(
                f"  {n:16s} n={v['n']:6d}  median {v['median_ms']:.4f} ms")
        if not fired:
            self.logger.error(
                "hookcost: no syscall fired - this run says nothing. Not a "
                "zero-cost result; a no-data result.")
        else:
            cheapest = min(fired, key=lambda n: fired[n]["median_ms"])
            self.logger.info(
                f"hookcost: tightest upper bound on syscall hook cost = "
                f"{fired[cheapest]['median_ms']:.4f} ms (via {cheapest})")

        out = {"comm": self.comm, "registered": self.registered,
               "failed": self.failed, "stats": st,
               "python_in_callback": {n: stats(self.py_ms[n])
                                      for n in self.syms}}
        if self.outdir:
            p = os.path.join(self.outdir, "hookcost.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"hookcost: wrote {p}")
