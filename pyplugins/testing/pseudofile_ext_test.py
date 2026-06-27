#!/usr/bin/env python3
"""Runtime coverage for the expanded pseudofile surface.

Exercises the parts of the expansion the schema/unit tests can't reach in a
live guest:

  * the broadened VFS-op surface dispatched via ``from_plugin`` — ``lseek``
    (returns a sentinel offset) and ``open``/``release`` (lifecycle hooks that
    record into a host file so the verifier can confirm they fired);
  * a ``@register_model`` custom read model selected from YAML by
    ``model: custom`` (the low-friction "expand models in Python" path).

open/release are observed via a host file (``self.outdir``) rather than by
reading the node back, so the node under test keeps an ordinary ``const_buf``
read and we don't conflate the lifecycle hooks with the read path.

The provenance/observability half (a ``provenance: default`` node reporting
``default_read``/``default_write``/``default_ioctl`` into
``pseudofiles_failures.yaml``) is config + built-in models only — no handler
here, just fixture nodes + verifier conditions in ``pseudofile_ext_ops.yaml``.
"""
import os

from penguin import Plugin
from hyperfile.models.registry import register_model
from hyperfile.models.read import ReadBufWrapper


# A custom read model, registered by name at import time. Selecting
# ``read: {model: custom, model_name: ext_sensor, scale: N}`` in YAML must
# construct this class with the extra kwargs forwarded (here, ``scale``).
@register_model("read", "ext_sensor")
class ExtSensorRead(ReadBufWrapper):
    def __init__(self, *, scale=1, **kwargs):
        super().__init__(buffer=str(6 * scale).encode(), **kwargs)


EVENTS_FILE = "ext_lifecycle_events.txt"


class PseudofileExtTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")

    def _record(self, event):
        # Append to a host file the verifier can inspect, proving the fop fired.
        with open(os.path.join(self.outdir, EVENTS_FILE), "a") as f:
            f.write(event + "\n")

    # open()/release() VFS handlers: func(ptregs, inode, file). The bodies run
    # when the external adapter iterates the returned generator; `if False:
    # yield` keeps them generators with no actual yield point.
    def on_open(self, ptregs, inode, file):
        self._record("open")
        self.logger.info("ext open")
        if False:
            yield

    def on_release(self, ptregs, inode, file):
        self._record("release")
        self.logger.info("ext release")
        if False:
            yield

    # lseek() handler: func(ptregs, file, offset, whence). Returns a distinctive
    # sentinel offset so the guest can prove the call reached the plugin.
    def seek_sentinel(self, ptregs, file, offset, whence):
        ptregs.retval = 4242
        if False:
            yield
