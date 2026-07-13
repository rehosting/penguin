#!/usr/bin/env python3
"""Snapshot re-attach smoke: a kprobe re-attaches to the surviving guest probe.

A kprobe's guest-side installation lives in the guest kprobe_table and survives
a QEMU savevm; only the host-side id->callback map is lost across a cross-process
-loadvm. A correct restore re-binds the host callback to the SAME, surviving
probe_id (Kprobes.on_restore) rather than installing a duplicate or dropping the
surviving probe's events.

The fixture probes do_filp_open (hot: every path open) and records the
guest-assigned probe_id (kprobe_ids.txt) plus a live hit count (kprobe_hits.txt).
The restore run must report the SAME probe_id as the save run and a non-zero
post-restore hit count.

Usage: python3 snapshot_kprobe_test.py -i <image> [-a armel] [-k 4.10]
"""
from _snapshot_harness import ReattachSmoke, cli, read_count, read_text

# Stay-alive init; the unfiltered probe keeps firing on the loop's busybox execs.
INIT_SH = """#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do /busybox sleep 1; done
"""


def check_save(ctx):
    ids = read_text(ctx.project, 0, "kprobe_ids.txt")
    hits = read_count(ctx.project, 0, "kprobe_hits.txt")
    if not ids or hits == 0:
        raise AssertionError("probe did not register/fire on the save run")


def check_restore(ctx):
    save_ids = read_text(ctx.project, 0, "kprobe_ids.txt")
    rest_ids = read_text(ctx.project, 1, "kprobe_ids.txt")
    rest_hits = read_count(ctx.project, 1, "kprobe_hits.txt")
    # The guest probe survived savevm; a correct restore re-attaches to the SAME
    # id and events keep flowing. A regression re-installs (new id) or drops the
    # surviving probe's events (no ids file / zero hits).
    if rest_ids != save_ids:
        raise AssertionError(
            f"kprobe was not re-attached across restore: save {save_ids} != "
            f"restore {rest_ids} (re-installed a duplicate, or lost the host map)")
    if rest_hits == 0:
        raise AssertionError("re-attached kprobe received no events after restore")


SPEC = ReattachSmoke(
    name="kprobe",
    init_sh=INIT_SH,
    probe_srcs=["snap_kprobe_probe.py"],
    plugins=["snap_kprobe_probe"],
    check_save=check_save,
    check_restore=check_restore,
)

if __name__ == "__main__":
    cli(SPEC)()
