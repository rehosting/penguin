"""Host bridge for the guest ``penguest`` binding.

Registers the portalcall handlers that the guest-side ``penguest`` module
(shipped to ``/igloo/pylib``; see ``docs/penguest.md``) calls. Today that is
guest -> host logging (``penguest.log`` / ``penguest.report``): the guest passes
a (pointer, length, level) triple over the portal, and this plugin reads the
string out of guest memory and emits it into the run's penguin log.

The real logging logic lives in :meth:`Penguest.handle_log` (a plain portal
generator) so it can be unit-tested host-side without the portalcall decorator.
"""

import os
import re

from penguin import Plugin, plugins

# Must match PENGUEST_LOG_MAGIC in src/resources/penguest/__init__.py.
PENGUEST_LOG_MAGIC = 0x7067104C

# Must match _LOG_LEVELS in src/resources/penguest/__init__.py.
_LEVEL_NAMES = {0: "debug", 1: "info", 2: "warning", 3: "error", 4: "finding"}
_MAX_LOG_BYTES = 64 * 1024

# The message is guest-controlled, so strip control chars (newlines, ANSI/terminal
# escapes, NULs) before it reaches the log or the log file -- this blocks log-line
# forgery and terminal-escape injection. Tabs go too so the TSV log file stays clean.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Bound the persisted log so a guest spamming penguest.log can't fill host disk.
_MAX_LOG_FILE = 8 * 1024 * 1024


class Penguest(Plugin):
    """Host side of the guest ``penguest`` binding."""

    def __init__(self):
        # Persist guest log lines to <outdir>/penguest_guest.log (created lazily
        # on first guest log) so they survive the run and the AI loop / tests can
        # read them back, in addition to the live penguin log.
        outdir = self.get_arg("outdir")
        self._guest_log_path = (
            os.path.join(outdir, "penguest_guest.log") if outdir else None)
        self._log_bytes = 0
        self._log_capped = False
        self._log_cap = int(self.get_arg("guest_log_max_bytes") or _MAX_LOG_FILE)

    @plugins.portalcall.portalcall(PENGUEST_LOG_MAGIC)
    def _on_guest_log(self, ptr, length, level):
        return (yield from self.handle_log(ptr, length, level))

    def handle_log(self, ptr, length, level):
        """Read a ``length``-byte UTF-8 string from guest memory at ``ptr`` and
        log it at ``level``. Returns 0 (the guest ignores the value)."""
        length = int(length) & 0xFFFFFFFF
        if length > _MAX_LOG_BYTES:
            self.logger.warning(
                f"penguest.log: truncating oversized message ({length} bytes)")
            length = _MAX_LOG_BYTES
        data = b""
        if length:
            data = bytes((yield from plugins.mem.read_bytes(ptr, length)))
        msg = _CONTROL_CHARS.sub("�", data.decode("utf-8", "replace"))
        self._emit(_LEVEL_NAMES.get(int(level) & 0xFFFFFFFF, "info"), msg)
        return 0

    def _emit(self, level_name, msg):
        prefix = "[guest finding] " if level_name == "finding" else "[guest] "
        {
            "debug": self.logger.debug,
            "info": self.logger.info,
            "warning": self.logger.warning,
            "error": self.logger.error,
            "finding": self.logger.info,
        }[level_name](prefix + msg)
        if not self._guest_log_path or self._log_capped:
            return
        line = f"{level_name}\t{msg}\n".encode("utf-8")
        if self._log_bytes + len(line) > self._log_cap:
            self._log_capped = True
            self.logger.warning(
                "penguest guest log hit its %d-byte cap; further guest log lines "
                "are logged but not persisted", self._log_cap)
            return
        with open(self._guest_log_path, "ab") as f:
            f.write(line)
        self._log_bytes += len(line)
