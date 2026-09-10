"""Measure G -- the guest work per fuzz iteration -- at the parser itself.

Every exec/s figure in this lane is 1/(reset + G), and G has never been
measured. The 15.2 exec/s of the first loop was dominated by an in-guest
fork+exec of nc and a trip through the guest TCP stack, none of which a
fastsnap iteration would pay.

lighttpd keeps its dynamic symbols (420 exported FUNCs), so the parser can be
bracketed by name rather than by a reversed offset:

    http_request_parse        0x192f0, 7652 bytes   <- the work we care about
    http_request_header_finished 0x19290,  96 bytes <- the overhead control

CONTROL, and it is not optional here. A uprobe costs a guest trap, a hypercall,
a portal round trip into host Python, and a return. That could easily exceed
the parse it is measuring, in which case a naive number would be probe cost
wearing G's clothes. So the same enter/return bracket is placed on a 96-byte
function whose real duration is negligible; its measured interval IS the probe
overhead, and

    G  ~=  dt(http_request_parse)  -  dt(http_request_header_finished)

If the control's interval is not small relative to the parser's, this plugin
cannot measure G and says so rather than reporting a number.
"""

import json
import os
import statistics
import time

from penguin import Plugin, plugins

uprobes = plugins.uprobes

TARGET = "http_request_parse"
CONTROL = "http_request_header_finished"

# Controls must not be probed in the same run as the target when they are
# called from inside it: the probe pair would land in the middle of the
# interval being measured and inflate it by exactly the quantity it is
# supposed to isolate. get_http_method_key is called by http_request_parse,
# so the two runs are deliberately separate.


class ParseCost(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        # NOT a wildcard. symbols.lookup() disables its nm and ELF-fallback
        # resolvers whenever the path contains '*' (symbols.py:286,292), so a
        # glob can only ever be answered by the prebuilt JSON symbol DB. With
        # fail_register_ok=True that silently produced a no-op decorator, and
        # the run reported "no samples" -- indistinguishable from "the parser
        # was never called". That is what the first three attempts at G were.
        self.path = self.get_arg("path") or "/usr/sbin/lighttpd"
        # dict.fromkeys, not list(): penguin's config merge CONCATENATES YAML
        # lists across patch layers rather than replacing them, so a two-entry
        # `symbols:` arrives here as six. Without the dedupe that silently
        # installs three duplicate probe pairs per address and every interval
        # is inflated by callbacks that are not in the run being compared
        # against. (Same mechanism visibly tripled ram_term.windows_ms.)
        raw = self.get_arg("symbols") or [TARGET, CONTROL]
        self.syms = list(dict.fromkeys(raw))
        if len(raw) != len(self.syms):
            self.logger.warning(
                f"parsecost: config merge duplicated the symbol list "
                f"({len(raw)} -> {len(self.syms)} after dedupe)")
        self.target = self.get_arg("target") or TARGET
        self.samples = {n: [] for n in self.syms}
        self._open = {n: {} for n in self.syms}
        self.resolved = {}

        for name in self.syms:
            # Pre-flight the resolution so registration is an observable fact
            # rather than an assumption. fail_register_ok is False below: if a
            # probe cannot be placed the run must say so loudly, because a
            # silent miss looks exactly like a real zero.
            lib, off = plugins.symbols.lookup(self.path, name)
            self.resolved[name] = None if off is None else f"{lib}+{off:#x}"
            if off is None:
                self.logger.error(
                    f"parsecost: SYMBOL RESOLUTION FAILED for {name} in "
                    f"{self.path}. No probe will be placed.")
                continue
            self.logger.info(f"parsecost: {name} -> {lib} file offset {off:#x}")

            uprobes.uprobe(path=self.path, symbol=name, on_enter=True,
                           fail_register_ok=False)(self._mk_enter(name))
            uprobes.uretprobe(path=self.path, symbol=name,
                              fail_register_ok=False)(self._mk_return(name))

        self.logger.info(
            f"parsecost: bracketing {self.syms} in {self.path}; "
            f"target={self.target}; resolved={self.resolved}")

    def _mk_enter(self, name):
        def enter(*args, **kwargs):
            self._open[name][id(args)] = time.time()
            self._open[name]["last"] = time.time()
            return
            yield
        enter.__name__ = f"enter_{name}"
        return enter

    def _mk_return(self, name):
        def ret(*args, **kwargs):
            t0 = self._open[name].pop("last", None)
            if t0 is not None:
                self.samples[name].append((time.time() - t0) * 1000.0)
            return
            yield
        ret.__name__ = f"ret_{name}"
        return ret

    def uninit(self) -> None:
        def stats(v):
            if not v:
                return None
            v = sorted(v)
            return {"n": len(v), "median_ms": statistics.median(v),
                    "p10_ms": v[max(0, len(v) // 10)],
                    "p90_ms": v[min(len(v) - 1, 9 * len(v) // 10)]}

        allstats = {n: stats(self.samples[n]) for n in self.syms}
        self.logger.info("parsecost: RESULTS")
        for n, st in allstats.items():
            tag = " <- target" if n == self.target else " <- overhead control"
            self.logger.info(f"  {n}: {st}{tag}")

        out = {"path": self.path, "target": self.target,
               "symbols": self.syms, "resolved": self.resolved,
               "stats": allstats, "G_ms": None}

        tgt = allstats.get(self.target)
        ctls = {n: st for n, st in allstats.items()
                if n != self.target and st}
        if not tgt:
            self.logger.error(
                "parsecost: no samples for the target probe; this run says "
                "nothing about the target interval.")
        elif not ctls:
            self.logger.warning(
                "parsecost: no control samples - the interval cannot be "
                "separated from probe overhead. Reporting raw interval only.")
        else:
            # The cheapest control is the best estimate of pure probe cost.
            cname = min(ctls, key=lambda n: ctls[n]["median_ms"])
            cmed = ctls[cname]["median_ms"]
            g = tgt["median_ms"] - cmed
            ratio = cmed / tgt["median_ms"] if tgt["median_ms"] else 9
            out.update({"G_ms": g, "overhead_control": cname,
                        "overhead_ms": cmed, "overhead_fraction": ratio})
            self.logger.info(
                f"  G = {tgt['median_ms']:.4f} - {cmed:.4f} ({cname}) "
                f"= {g:.4f} ms")
            if ratio > 0.5:
                self.logger.error(
                    f"parsecost: probe overhead is {ratio:.0%} of the measured "
                    "interval. G is NOT resolvable with this instrument; the "
                    "difference is noise, not a measurement.")

        if self.outdir:
            p = os.path.join(self.outdir, "parsecost.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"parsecost: wrote {p}")
