#!/usr/bin/env python3
"""Snapshot re-attach smoke: core_pattern lock is re-armed after restore.

core_pattern_guard hijacks /proc/sys/kernel/core_pattern's proc_handler after
the guest fires the one-shot `core_pattern_lock` hypercall, so guest writes that
try to redirect core dumps are logged and dropped. That hypercall fires ONCE
during boot and does NOT re-fire on a -loadvm restore, and the sysctl node's
host handler trampoline is lost across a cross-process restore. Without a re-arm
(core_pattern_guard.on_restore re-registering -> sysctl re-bind) the lock
silently lapses.

Unlike the devfs/sysctl smokes, the sysctl plugin here is only pulled in via
core_pattern_guard (which force-loads it) and its node is registered from a
hypercall/on_restore, so this is the case that exercises the register-time
re-bind fast-path and the load-ordering guarantee.

Signal: the product handler's stable INFO log on every guest write attempt,
"guest tried to set core_pattern to '<marker>'". The stay-alive init writes a
unique marker in a loop; the line must appear in BOTH runs' logs iff the handler
is live.

Usage: python3 snapshot_core_pattern_test.py -i <image> [-a armel] [-k 4.10]
"""
from _snapshot_harness import ReattachSmoke, cli, log_contains

MARKER = "/tmp/SNAP_RESTORE_COREPAT_MARKER"

INIT_SH = f"""#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do
  /busybox echo "{MARKER}" > /proc/sys/kernel/core_pattern 2>/dev/null
  /busybox sleep 1
done
"""

_NEEDLE = f"guest tried to set core_pattern to '{MARKER}'"


def check_save(ctx):
    if not log_contains(ctx.save_log, _NEEDLE):
        raise AssertionError(
            "core_pattern lock was never active on the save run (no guard log) "
            "- fixture/config problem, not the restore path")


def check_restore(ctx):
    if not log_contains(ctx.restore_log, _NEEDLE):
        raise AssertionError(
            "LOCK LAPSED: core_pattern_guard logged no guest write attempts after "
            "restore - the lock was not re-armed (its install hypercall does not "
            "re-fire, and the sysctl handler trampoline was lost).")


SPEC = ReattachSmoke(
    name="corepat",
    init_sh=INIT_SH,
    # Enable core dumps AND lock the pattern -> the guest init fires
    # `core_pattern_lock`, arming core_pattern_guard. No project-local probe: the
    # built-in core_pattern_guard is the subject.
    extra_core={"core_dumps": {"lock": True}},
    check_save=check_save,
    check_restore=check_restore,
)

if __name__ == "__main__":
    cli(SPEC)()
