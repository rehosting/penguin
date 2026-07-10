#!/usr/bin/env python3
"""Snapshot re-attach smoke: modeled sysctl dispatch survives restore.

A customized sysctl wires a host-side proc_handler trampoline into the guest
ctl_table; the node survives savevm but the host tramp_id->callback map is lost
across a cross-process -loadvm. This checks guest reads of
/proc/sys/kernel/snaptrack still route back to the host handler after a restore
(sysctl on_restore re-bind). The fixture's read handler counts hits into
sysctl_reads.txt; a fresh count-from-zero > 0 on the restore run proves dispatch
survived.

Usage: python3 snapshot_sysctl_test.py -i <image> [-a armel] [-k 4.10]
"""
from _snapshot_harness import ReattachSmoke, cli, read_count

INIT_SH = """#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do
  /busybox cat /proc/sys/kernel/snaptrack >/dev/null 2>&1
  /busybox sleep 1
done
"""


def check_save(ctx):
    if read_count(ctx.project, 0, "sysctl_reads.txt") == 0:
        raise AssertionError("modeled sysctl was never read on the save run")


def check_restore(ctx):
    if read_count(ctx.project, 1, "sysctl_reads.txt") == 0:
        raise AssertionError(
            "DEAD DISPATCH: modeled sysctl received no reads after restore "
            "(guest node survived savevm but its proc_handler trampoline no "
            "longer routes to the host model). sysctl on_restore re-bind failed.")


SPEC = ReattachSmoke(
    name="sysctl",
    init_sh=INIT_SH,
    probe_srcs=["snap_sysctl_probe.py"],
    plugins=["snap_sysctl_probe"],
    check_save=check_save,
    check_restore=check_restore,
)

if __name__ == "__main__":
    cli(SPEC)()
