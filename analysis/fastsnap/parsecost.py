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


class ParseCost(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.path = self.get_arg("path") or "*lighttpd"
        self.samples = {TARGET: [], CONTROL: []}
        self._open = {TARGET: {}, CONTROL: {}}

        for name in (TARGET, CONTROL):
            uprobes.uprobe(path=self.path, symbol=name, on_enter=True,
                           fail_register_ok=True)(self._mk_enter(name))
            uprobes.uretprobe(path=self.path, symbol=name,
                              fail_register_ok=True)(self._mk_return(name))
        self.logger.info(
            f"parsecost: bracketing {TARGET} (target) and {CONTROL} (overhead "
            f"control) in {self.path}")

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

        tgt, ctl = stats(self.samples[TARGET]), stats(self.samples[CONTROL])
        self.logger.info("parsecost: RESULTS")
        self.logger.info(f"  {TARGET}: {tgt}")
        self.logger.info(f"  {CONTROL}: {ctl}   <- probe-overhead CONTROL")

        out = {"target": TARGET, "control": CONTROL,
               "target_stats": tgt, "control_stats": ctl, "G_ms": None}

        if not tgt:
            self.logger.error(
                "parsecost: CONTROL FAILED - no samples for the target probe; "
                "this run says nothing about G.")
        elif not ctl:
            self.logger.warning(
                "parsecost: no control samples - the parser interval cannot be "
                "separated from probe overhead. Reporting raw interval only.")
        else:
            g = tgt["median_ms"] - ctl["median_ms"]
            ratio = ctl["median_ms"] / tgt["median_ms"] if tgt["median_ms"] else 9
            out["G_ms"] = g
            out["overhead_fraction"] = ratio
            self.logger.info(f"  G (parse - overhead) = {g:.4f} ms")
            if ratio > 0.5:
                self.logger.error(
                    f"parsecost: probe overhead is {ratio:.0%} of the measured "
                    "interval. G is NOT resolvable with this instrument; the "
                    "difference is noise, not a measurement.")
            else:
                self.logger.info(
                    f"  overhead is {ratio:.0%} of the interval -- G resolvable")

        if self.outdir:
            p = os.path.join(self.outdir, "parsecost.json")
            with open(p, "w") as fh:
                json.dump(out, fh, indent=2)
            self.logger.info(f"parsecost: wrote {p}")
