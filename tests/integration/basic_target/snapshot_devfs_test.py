#!/usr/bin/env python3
"""Snapshot re-attach smoke: modeled /dev node (devfs) dispatch survives restore.

A modeled character device's guest-side node (inode + ops function pointers) is
baked into guest RAM and survives savevm; the host kffi trampoline->callback map
is process-local and lost across a cross-process -loadvm. This checks guest reads
of /dev/snaptrack still route back to the host model after a restore (devfs
on_restore re-bind) rather than hitting a dead trampoline. The fixture's host
read handler counts hits into devfs_reads.txt; a fresh count-from-zero > 0 on the
restore run proves dispatch survived.

Usage: python3 snapshot_devfs_test.py -i <image> [-a armel] [-k 4.10]
"""
from _snapshot_harness import ReattachSmoke, cli, read_count

INIT_SH = """#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do
  /busybox cat /dev/snaptrack >/dev/null 2>&1
  /busybox sleep 1
done
"""


def check_save(ctx):
    if read_count(ctx.project, 0, "devfs_reads.txt") == 0:
        raise AssertionError("modeled /dev node was never read on the save run")


def check_restore(ctx):
    if read_count(ctx.project, 1, "devfs_reads.txt") == 0:
        raise AssertionError(
            "DEAD DISPATCH: modeled /dev node received no reads after restore "
            "(guest node survived savevm but its ops trampoline no longer routes "
            "to the host model). devfs on_restore re-bind failed.")


SPEC = ReattachSmoke(
    name="devfs",
    init_sh=INIT_SH,
    probe_srcs=["snap_devfs_probe.py"],
    plugins=["snap_devfs_probe"],
    check_save=check_save,
    check_restore=check_restore,
)

if __name__ == "__main__":
    cli(SPEC)()
