"""Fixture plugin for snapshot_devfs_test.py (not a product plugin).

Registers one modeled character device (/dev/snaptrack) whose host-side read
handler increments a counter and records the running total into the run's
out_dir. The guest's stay-alive init reads the node in a loop, so reads keep
flowing before AND after a snapshot restore.

The modeled device's guest-side node (its ctl_table/inode + the ops function
pointers wired into the guest kernel) is baked into guest RAM and so survives a
QEMU savevm. The HOST side is a kffi trampoline -> Python callback map that is
process-local and lost across a cross-process -loadvm. This fixture answers the
open question empirically: after a restore, do guest reads of the modeled node
still route back to this Python handler (dispatch survives), or do they hit a
dead host trampoline (reads stop reaching us, counter frozen / read() errors)?
"""
from os.path import join

from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import DevFile, FilePtr, CharPtr, LoffTPtr, SizeT


class SnapTrackDevFile(DevFile):
    PATH = "snaptrack"

    def __init__(self, outdir):
        self._outdir = outdir
        self.reads = 0
        super().__init__()

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr,
             size: SizeT, loff_ptr: LoffTPtr):
        self.reads += 1
        # Persist the running host-side read count every time the model is hit,
        # so the test can compare the count before the save against the count
        # after the restore.
        with open(join(self._outdir, "devfs_reads.txt"), "w") as f:
            f.write(f"{self.reads}\n")

        size_val = int(size)
        offset = yield from plugins.kffi.deref(loff_ptr)
        data = f"{self.reads}\n".encode("utf-8")

        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return

        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff_ptr, offset + chunk)
        ptregs.retval = chunk


class SnapDevfsProbe(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        plugins.devfs.register_devfs(SnapTrackDevFile(self.outdir))
