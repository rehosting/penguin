#!/usr/bin/env python3
"""Regression test for issue #843: data-aware poll() + single-object backing.

A `from_plugin`-backed char device used to report itself *permanently* readable
via poll() (the always-ready stub won the MRO), so a poll()->read() reader
busy-looped when the backing had no data. This test exercises both new ways to
provide a data-aware poll():

1. **Single-object backing** (`plugin: poll_backing_test:PollBacking`): one
   class owns read/write/poll over its own rx buffer.
2. **Per-domain `poll:` form**: `read`/`write`/`poll` each `from_plugin` against
   this plugin's methods.

In both cases poll() reports POLLIN only when the buffer actually holds data, so
a poll() on a fresh/empty node returns no readable event (the busy-loop fix),
and becomes readable only after a write enqueues bytes.
"""
from penguin import Plugin, plugins

# poll() mask bits
_POLLIN = 0x001
_POLLOUT = 0x004
_POLLRDNORM = 0x040
_POLLWRNORM = 0x100


class _RxBackingBase:
    """Shared serial-style rx buffer: writes enqueue, reads drain.

    poll() is data-aware — readable only when the buffer is non-empty, always
    writable. ``read``/``write`` are VFS-signature generators; ``poll`` is a
    plain function (no hypercalls needed to answer it).
    """

    def __init__(self, **kwargs):
        self._buf = bytearray()
        super().__init__(**kwargs)

    def write(self, ptregs, file, user_buf, size, loff):
        n = int(size)
        if n > 0:
            data = yield from plugins.mem.read(user_buf, n, fmt="bytes")
            self._buf += data
        ptregs.retval = n

    def read(self, ptregs, file, user_buf, size, loff):
        n = int(size)
        if n <= 0 or not self._buf:
            ptregs.retval = 0
            return
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        yield from plugins.mem.write(user_buf, chunk)
        ptregs.retval = len(chunk)

    def poll(self, ptregs, file, poll_table_struct):
        mask = _POLLOUT | _POLLWRNORM  # always writable
        if self._buf:
            mask |= _POLLIN | _POLLRDNORM  # readable only when data is queued
        ptregs.retval = mask


class PollBacking(_RxBackingBase):
    """Single-object backing class referenced via `plugin: poll_backing_test:PollBacking`."""


class PollBackingTest(Plugin, _RxBackingBase):
    """Loaded pyplugin exposing read/write/poll for the per-domain `from_plugin` form."""

    def __init__(self):
        # Plugin.__preinit__ already ran; just set up our own rx buffer.
        self._buf = bytearray()
