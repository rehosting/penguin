"""
Crashes Plugin (crashes.py) for Penguin
=======================================

This module provides the Crashes plugin, which records fatal signal
deliveries to guest processes -- userland crashes -- to ``crashes.yaml`` in
the output directory. Before this, the only crash signal Penguin recorded
was a kernel panic; a guest service dying from SIGSEGV left no artifact.

The plugin registers guest signal-delivery hooks (via the SignalMonitor
plugin / igloo_driver) for a configurable set of fatal-by-default signals
and aggregates deliveries, de-duplicating identical (process, signal, pc)
triples with a count -- mirroring how NetBinds de-duplicates binds.

The recorded ``pc`` comes from the target task's saved userspace register
frame (``task_pt_regs``) at signal-delivery time. For synchronous faults
(SIGSEGV/SIGBUS/SIGILL/SIGFPE) that frame is the exception trap frame, so
the pc is the faulting instruction address. For asynchronous signals (e.g.
a ``kill``) it is wherever the task last entered the kernel.

Output ``crashes.yaml``::

    crashes:
    - proc: httpd
      pid: 412
      signal: 11
      signame: SIGSEGV
      pc: '0x004013a8'
      time: 12.481      # host wall-clock seconds since emulation start
      count: 3          # de-duplicated identical (proc, signal, pc)

The file is rewritten on every recorded delivery (crashes are rare), so it
is always current; an empty ``crashes: []`` is written at startup so
downstream consumers can rely on the file existing.

Caveats
-------

- **Deliveries, not terminations.** The underlying driver hook fires when a
  signal is *dequeued for delivery*, before the kernel applies its
  disposition, and the event does not say whether a userspace handler is
  installed. A process that catches SIGSEGV/SIGABRT/etc. and survives (e.g.
  a runtime using SIGSEGV for GC barriers, or a daemon with an abort
  handler) is still recorded. Treat a crashes.yaml row as "a fatal-class
  signal was delivered", not proof the process died.
- Deliveries another subscriber has already marked dropped (``event.drop``)
  are skipped, but publish order between subscribers is not deterministic,
  so a drop made *after* this plugin runs is still recorded.
- ``time`` is host wall-clock seconds since this plugin initialized (i.e.
  emulation start), not guest uptime.

Arguments
---------

- signals (list of str, optional): Signal names to record. Defaults to the
  signals whose default action is to terminate with a core dump and that
  indicate a program fault: SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE,
  SIGSYS. Names are resolved per guest architecture (MIPS numbering
  differs), so always configure by name, not number.

Overall Purpose
---------------

A crashing service is one of the most common reasons a rehost "runs" but
produces no bound port. This plugin makes those crashes visible in the
output directory and in the run score (see ``manager.calculate_score``).
"""

import time
from os.path import join

import yaml
from pydantic import Field
from penguin import plugins, Plugin, PluginArgs

CRASHES_FILE = "crashes.yaml"

# Fatal-by-default signals that indicate a program fault (man signal(7):
# default action terminates the process with a core dump), minus the
# debugger/profiling ones (SIGTRAP, SIGXCPU, SIGXFSZ, SIGQUIT) that are not
# crash indicators in practice.
DEFAULT_FATAL_SIGNALS = [
    "SIGSEGV",
    "SIGBUS",
    "SIGILL",
    "SIGABRT",
    "SIGFPE",
    "SIGSYS",
]


class Crashes(Plugin):
    class Args(PluginArgs):
        signals: list[str] = Field(
            default=DEFAULT_FATAL_SIGNALS,
            description="Signal names to record as crashes. Resolved per "
            "guest architecture, so use names (e.g. SIGSEGV), not numbers.",
        )

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.start_time = time.time()

        # (proc, signal, pc) -> record dict; insertion-ordered
        self.records = {}

        # Guest signal number -> canonical name, resolved for the guest arch
        # (MIPS numbers several signals differently).
        self.signames = {}
        for name in self.get_arg("signals"):
            num = plugins.signals.signal_name_to_num(name)
            if num is None:
                raise ValueError(f"crashes plugin: unknown signal name {name!r}")
            self.signames.setdefault(num, name)

        # Write an empty report up front so consumers can rely on the file.
        self.write_report()

        plugins.subscribe(plugins.signal_monitor, "signal_deliver", self.on_signal_deliver)
        # One guest hook per watched signal, so only these deliveries trap
        # out to the host.
        for num in self.signames:
            plugins.signal_monitor.register_hook(sig=num)

    def on_signal_deliver(self, cpu, event):
        """
        Record a fatal signal delivery. SignalMonitor publishes every hooked
        delivery (including ones registered by other plugins), so filter to
        our watched set here.
        """
        sig = int(event.sig)
        signame = self.signames.get(sig)
        if signame is None:
            return

        # Another subscriber may have dropped this delivery to bypass it
        # (e.g. a SIGILL-emulation consumer that advances the PC). Publish
        # order between subscribers is not deterministic, so this only
        # filters drops made before we run; a drop made afterwards is still
        # recorded.
        if event.drop:
            return

        pc = int(event.pc)
        if pc == 0 and event.regs:
            pc = event.regs.get_pc()

        key = (event.comm, sig, pc)
        rec = self.records.get(key)
        if rec is None:
            rec = {
                "proc": event.comm,
                "pid": int(event.pid),
                "signal": sig,
                "signame": signame,
                "pc": f"0x{pc:08x}",
                "time": round(time.time() - self.start_time, 3),
                "count": 1,
            }
            self.records[key] = rec
            self.logger.info(
                f"{signame} delivered to {event.comm} (pid {rec['pid']}) at {rec['pc']}"
            )
        else:
            rec["count"] += 1
        self.write_report()

    def write_report(self):
        with open(join(self.outdir, CRASHES_FILE), "w") as f:
            yaml.safe_dump({"crashes": list(self.records.values())}, f, sort_keys=False)

    def uninit(self):
        self.write_report()

    # --- snapshot / restore ------------------------------------------------- #
    def save_state(self):
        """Carry recorded crashes across a snapshot restore. crashes.yaml lives
        in the wiped out_dir and the restored guest is past the signal
        deliveries, so without this every pre-snapshot crash disappears from the
        report. The dict *keys* are internal dedup tuples — only the record
        values are carried and the keys are rebuilt on load. ``signames`` and
        ``start_time`` are not saved: signames is re-derived from config in
        __init__, and each record already stores its own relative ``time``.
        Returns None when nothing has crashed."""
        if not self.records:
            return None
        return {"records": list(self.records.values())}

    def load_state(self, data) -> None:
        """Rebuild the records dict (phase one, no I/O); on_restore rewrites the
        report. The dedup key mirrors on_signal_deliver: (proc, signal, pc)."""
        if not data:
            return
        for rec in data.get("records", []):
            key = (rec["proc"], rec["signal"], int(rec["pc"], 16))
            self.records[key] = rec

    def on_restore(self, tag: str) -> None:
        """Re-emit crashes.yaml into the wiped out_dir from the restored records.
        Silent: the report is an output file, nothing downstream re-actuates."""
        self.write_report()
