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

No-op when core.shared_dir is unset -- there's nowhere to mirror dumps to,
and the init script's hypercall won't fire either.
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
                f"keeping {self._pattern_bytes.decode()!r} so dumps land in /igloo/shared/core_dumps"
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
        conf = self.get_arg("conf") or {}
        if not conf.get("core", {}).get("shared_dir"):
            return

        self._registered = False
        plugins.send_hypercall.subscribe("core_pattern_lock", self._on_lock)

    def _on_lock(self, pattern: str):
        if self._registered:
            return 0, ""
        plugins.sysctl.register_sysctl(CorePatternSysctl(pattern, self))
        self._registered = True
        self.logger.debug(f"locked core_pattern at {pattern!r}")
        return 0, ""
