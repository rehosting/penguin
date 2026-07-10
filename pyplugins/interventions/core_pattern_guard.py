"""
Lock /proc/sys/kernel/core_pattern after the guest's init script sets it.

source.d/40_mount_shared_dir.sh writes our pattern via the kernel's real
proc_dostring_coredump handler (populating the core_pattern[] global that
format_corename reads), then fires the `core_pattern_lock` hypercall. We
respond by registering a SysctlFile that hijacks the proc_handler -- reads
return our pattern, writes are logged at info and dropped, so guest software
(systemd-coredump, apport, container runtimes) can't redirect dumps away
from /igloo/shared/core_dumps.

The kernel's core_pattern[] global is set BEFORE we hijack (via the init
script's echo), and our handler eats subsequent writes without touching the
global. The driver's sysctl mutation repoints ctl_table.data to our buffer
but never writes through to the original .data target, so the global keeps
the value the init script put there.

Dormant when core dumps are disabled or core.core_dumps.lock is false: the
init script only fires the hypercall when both CORE_DUMPS and CORE_DUMPS_LOCK
are in the guest env (set by core.py from core.core_dumps). We subscribe
unconditionally anyway so a stray core_pattern_lock is honored instead of
tripping send_hypercall's "Unregistered send_hypercall command" error.
"""

from penguin import Plugin, plugins
from hyperfile.models.base import SysctlFile


class CorePatternSysctl(SysctlFile):
    PATH = "kernel/core_pattern"
    MODE = 0o644
    MAXLEN = 256

    def __init__(self, pattern: str, owner):
        self.INITIAL_VALUE = pattern
        super().__init__()
        self._owner = owner
        self._pattern_bytes = pattern.encode("utf-8")

    def proc_handler(self, ptregs, ctl, write, buffer, lenp, ppos_ptr):
        size = yield from plugins.kffi.deref(lenp)

        if int(write):
            try:
                raw = yield from plugins.mem.read(buffer, size=int(size), fmt="bytes")
                payload = raw.rstrip(b"\x00\n").decode("utf-8", errors="replace")
            except Exception as e:
                payload = f"<unreadable: {e}>"
            self._owner.logger.info(
                f"guest tried to set core_pattern to {payload!r}; "
                f"keeping penguin's locked pattern {self._pattern_bytes.decode()!r}"
            )
            yield from plugins.mem.write(ppos_ptr, int(size))
            ptregs.retval = 0
            return 0

        offset = yield from plugins.kffi.deref(ppos_ptr)
        if int(offset) == 0:
            data = self._pattern_bytes + b"\n"
            n = min(len(data), int(size))
            yield from plugins.mem.write(buffer, data[:n])
            yield from plugins.mem.write(lenp, n)
            yield from plugins.mem.write(ppos_ptr, n)
        else:
            yield from plugins.mem.write(lenp, 0)
        ptregs.retval = 0
        return 0


class CorePatternGuard(Plugin):
    def __init__(self):
        self._registered = False
        self._pattern = None
        self._restore_pattern = None
        # Force the sysctl plugin to load eagerly now (it is otherwise
        # lazy-loaded on first `plugins.sysctl` access). We depend on it, but
        # more importantly for snapshot restore: our sysctl is only registered
        # from a hypercall / on_restore, so nothing else pulls sysctl in on a
        # -loadvm boot. If sysctl first loaded during our on_restore, it would
        # have already MISSED the snapshot load_state dispatch (which runs before
        # any on_restore), so its saved handler trampolines would never be
        # restored and our re-registration could not re-bind. Loading it here
        # ensures sysctl.load_state runs and populates its restore map first.
        self._sysctl = plugins.sysctl
        plugins.send_hypercall.subscribe("core_pattern_lock", self._on_lock)

    def _on_lock(self, pattern: str):
        if self._registered:
            return 0, ""
        self._pattern = pattern
        plugins.sysctl.register_sysctl(CorePatternSysctl(pattern, self))
        self._registered = True
        self.logger.debug(f"locked core_pattern at {pattern!r}")
        return 0, ""

    # --- snapshot / restore ------------------------------------------------ #
    def save_state(self):
        """Persist the locked pattern. The `core_pattern_lock` hypercall that
        installs our sysctl fires only once from the guest init script and does
        NOT re-fire on a -loadvm boot, so without this the lock silently lapses
        after a restore and guest software could redirect core dumps again."""
        if not self._registered:
            return None
        return {"pattern": self._pattern}

    def load_state(self, data) -> None:
        if data:
            self._restore_pattern = data.get("pattern")

    def on_restore(self, tag: str) -> None:
        """Re-register our core_pattern sysctl. The guest node survived the
        snapshot, so register_sysctl takes its restore fast-path and re-binds
        the surviving handler instead of re-creating it."""
        if self._restore_pattern is None or self._registered:
            return
        self._pattern = self._restore_pattern
        plugins.sysctl.register_sysctl(CorePatternSysctl(self._pattern, self))
        self._registered = True
        self.logger.info(
            f"Re-locked core_pattern at {self._pattern!r} after snapshot restore")
