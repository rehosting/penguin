"""Fixture plugin for snapshot_kprobe_test.py (not a product plugin).

Registers one entry kprobe on do_filp_open (hot: every path open) and, once it
fires, records the guest-assigned probe_id plus a live hit count into the run's
out_dir. The test compares the probe_id across a save run and a --from-snapshot
restore run: the guest-side kprobe survives savevm, so a correct restore
re-attaches the host callback to the SAME id (and events keep flowing), whereas
a regression either re-installs a second probe (new, higher id) or drops the
surviving probe's events entirely (no id file, zero hits).
"""
from os.path import join

from penguin import Plugin, plugins


class SnapKprobeProbe(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.hits = 0
        self._wrote_id = False
        # Unfiltered so it keeps firing on the stay-alive loop's busybox execs
        # after a restore too.
        self._handle = plugins.kprobes.kprobe(
            symbol="do_filp_open", on_enter=True)(self.on_open)

    def on_open(self, pt_regs):
        self.hits += 1
        if not self._wrote_id:
            ids = plugins.kprobes._handle_to_probe_ids.get(self._handle, [])
            with open(join(self.outdir, "kprobe_ids.txt"), "w") as f:
                f.write(f"ids={sorted(ids)}\n")
            self._wrote_id = True
        with open(join(self.outdir, "kprobe_hits.txt"), "w") as f:
            f.write(f"{self.hits}\n")
