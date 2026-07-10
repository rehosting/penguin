"""Fixture plugin for snapshot_sysctl_test.py (not a product plugin).

Registers one modeled sysctl (/proc/sys/kernel/snaptrack) with a custom read
handler that increments a counter and records the running total into the run's
out_dir. The stay-alive init reads it in a loop, so reads flow before AND after
a snapshot restore.

Overriding read() makes the node "customized", so the sysctl layer wires a
host-side proc_handler trampoline into the guest ctl_table. That guest node
survives savevm; the host tramp_id->callback map does not. This exercises the
sysctl on_restore re-bind primitive: after a restore, guest reads of the node
must still route back to this Python handler.
"""
from os.path import join

from penguin import Plugin, plugins
from hyperfile.models.base import SysctlFile


class SnapTrackSysctl(SysctlFile):
    PATH = "kernel/snaptrack"
    MODE = 0o644

    def __init__(self, outdir):
        self._outdir = outdir
        self.reads = 0
        super().__init__()

    def read(self, ptregs, file, user_buf, size, offset_ptr):
        self.reads += 1
        with open(join(self._outdir, "sysctl_reads.txt"), "w") as f:
            f.write(f"{self.reads}\n")

        offset = yield from plugins.kffi.deref(offset_ptr)
        data = f"{self.reads}\n".encode("utf-8")
        if int(offset) >= len(data) or int(size) <= 0:
            return 0
        chunk = min(int(size), len(data) - int(offset))
        yield from plugins.mem.write(user_buf, data[int(offset):int(offset) + chunk])
        yield from plugins.mem.write(offset_ptr, int(offset) + chunk)
        return chunk


class SnapSysctlProbe(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        plugins.sysctl.register_sysctl(SnapTrackSysctl(self.outdir))
