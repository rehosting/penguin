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

The file is kept current as deliveries arrive; an empty ``crashes: []`` is
written at startup so downstream consumers can rely on the file existing.

It used to be rewritten on *every* delivery, on the premise stated here that
"crashes are rare". A snapshot fuzzing loop falsifies that premise, and the
cost is not linear: the report is a full YAML re-serialisation of every
record, the key is ``(proc, signal, pc)``, and a stack-smash whose return
address comes from the input gives almost every crash its own pc -- so the
dict grows without bound and each write costs more than the last. Measured on
such a loop, signal-delivery latency rose linearly with the record count
across three independent runs, from 19 ms at 111 records to 101 ms at 409,
and the rewriting accounted for over half the run's wall clock. This happens
on the vCPU thread, so every millisecond of it is a millisecond the guest is
not running.

So writes are now eager only while they are cheap (up to ``report_eager_max``
records) and time-throttled above that, with a forced write at
startup, teardown, restore and reset. A consumer reading mid-run sees a file
at most ``report_interval_s`` stale instead of one that is exact and
quadratic.

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

# libyaml where it exists: the same output, produced by C rather than by the
# pure-Python emitter, which is most of the constant factor in the cost
# described above. Falls back cleanly on a build without libyaml.
_DUMPER = getattr(yaml, "CSafeDumper", yaml.SafeDumper)

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

        # See write_report(). Defaults chosen so an ordinary target -- a few
        # distinct crash sites, seconds apart -- writes on every delivery
        # exactly as before, and only an aggregate large enough to be
        # expensive starts batching.
        self.report_eager_max = int(self.get_arg("report_eager_max") or 64)
        self.report_interval_s = float(self.get_arg("report_interval_s") or 2.0)
        self._last_report = 0.0
        self._report_pending = False

        # Records handed back by load_state() on a snapshot restore, applied in
        # on_restore() once every plugin has loaded. None when not restoring.
        self._restore_data = None

        # Guest signal number -> canonical name, resolved for the guest arch
        # (MIPS numbers several signals differently).
        self.signames = {}
        for name in self.get_arg("signals"):
            num = plugins.signals.signal_name_to_num(name)
            if num is None:
                raise ValueError(f"crashes plugin: unknown signal name {name!r}")
            self.signames.setdefault(num, name)

        # Write an empty report up front so consumers can rely on the file.
        self.write_report(force=True)

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

    # ------------------------------------------------------------------
    # Snapshot / restore
    #
    # ``records`` is host-side state a VM snapshot does not capture, so the
    # three-hook protocol from plugin_manager.Plugin applies (same shape as
    # NetBinds):
    #
    # - ``save_state``/``load_state``/``on_restore`` carry the aggregate
    #   across a *cross-process* once-and-continue restore, where a fresh
    #   penguin process attaches to a guest that is already past the crashes
    #   it suffered before the snapshot. Without this the restored run starts
    #   blank and every pre-snapshot crash silently disappears from the
    #   report.
    # - ``reset_state`` is the *restore-many* case a fuzzing loop builds:
    #   restoring the same point repeatedly must rewind the report with the
    #   guest, or dedup counts accumulate across iterations that the guest
    #   never actually executed.
    #
    # ``time`` is deliberately NOT rebased on restore: it is seconds since
    # emulation start on the timeline the delivery happened on, and a restored
    # run is a different timeline. Rows carried across a restore are tagged
    # ``pre_restore: true`` so a consumer can tell which clock a row is on.
    # ------------------------------------------------------------------

    def save_state(self):
        """Return the aggregated crash records for the snapshot's host sidecar."""
        if not self.records:
            return None
        return {"records": list(self.records.values())}

    def load_state(self, data) -> None:
        """Stash records captured at snapshot time; applied in on_restore()."""
        self._restore_data = data or None

    def on_restore(self, tag: str) -> None:
        """Rehydrate the aggregate so the restored run's report is continuous."""
        data = self._restore_data
        self._restore_data = None
        if not data:
            return
        self.records = {}
        for rec in data.get("records", []):
            rec = dict(rec)
            rec["pre_restore"] = True
            key = (rec["proc"], int(rec["signal"]), int(rec["pc"], 16))
            self.records[key] = rec
        self.write_report(force=True)

    def reset_state(self) -> None:
        """Rewind to a pristine report for restore-many (fuzzing) loops."""
        self.records = {}
        self.write_report(force=True)

    def write_report(self, force=False):
        """Serialise the report, eagerly while that is cheap.

        The cost is proportional to the number of records, so the throttle is
        tied to the number of records rather than to a delivery count: a target
        with a handful of distinct crash sites keeps the old
        write-on-every-delivery behaviour exactly, and only a run that has
        grown a large aggregate -- which is the run where the cost matters --
        starts batching.

        `force` is for the four points where the file must be exact regardless:
        startup, teardown, restore and reset.
        """
        now = time.time()
        if (not force
                and len(self.records) > self.report_eager_max
                and (now - self._last_report) < self.report_interval_s):
            self._report_pending = True
            return
        with open(join(self.outdir, CRASHES_FILE), "w") as f:
            yaml.dump({"crashes": list(self.records.values())}, f,
                      Dumper=_DUMPER, sort_keys=False)
        self._last_report = now
        self._report_pending = False

    def uninit(self):
        self.write_report(force=True)
