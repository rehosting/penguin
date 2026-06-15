#!/usr/bin/env python3
"""Regression test plugin for issue #839.

A single pseudofile node configured with BOTH a `from_plugin` read and a
`from_plugin` write must dispatch each operation to the correct handler. The
bug was that the read/write external adapters shared one `self._func`
instance attribute, so the read silently invoked the write function.

This plugin exposes distinguishable VFS-style `read`/`write` handlers. The
signatures contain neither `details`/`filename` (read) nor `buf` (write), so
`_detect_plugin_style` resolves them to `ReadExternalVFS` / `WriteExternalVFS`
— exactly the colliding path. The guest does a write-then-read round-trip and
expects the read handler's marker back; with the bug present, the read is
misrouted to the write handler (which never fills `user_buf`) and the marker
is absent.
"""
from penguin import plugins, Plugin

# Distinctive payload the read handler returns. If a read is misrouted to the
# write handler this marker is never written to the user buffer.
READ_MARKER = b"READ_HANDLER\n"


class FromPluginTest(Plugin):
    def __init__(self):
        # Bytes most recently seen by the write handler (proves write ran).
        self._last_write = b""

    def read(self, ptregs, file, user_buf, size, loff):
        size_val = int(size)
        offset = yield from plugins.kffi.deref(loff)
        data = READ_MARKER

        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return

        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk)
        ptregs.retval = chunk

    def write(self, ptregs, file, user_buf, size, loff):
        size_val = int(size)
        # Bypass the smart dispatcher by requesting raw bytes.
        self._last_write = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        self.logger.info(f"from_plugin_test write handler got {self._last_write!r}")
        # Deliberately do NOT touch user_buf — so a misrouted read returns nothing.
        ptregs.retval = size_val
