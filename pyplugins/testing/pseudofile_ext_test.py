#!/usr/bin/env python3
"""Runtime coverage for the expanded pseudofile surface.

Exercises two things the schema/unit tests can't reach in a live guest:

  * a ``lseek`` handler dispatched via ``from_plugin`` (the broadened VFS-op
    surface) — proving the kernel's lseek reaches a plugin and its return value
    flows back;
  * a ``@register_model`` custom read model selected from YAML by
    ``model: custom`` (the low-friction "expand models in Python" path).

The provenance/observability half (a ``provenance: default`` node reporting
``default_read``/``default_write``/``default_ioctl`` into
``pseudofiles_failures.yaml``) is driven entirely from config + the built-in
models, so it needs no handler here — only the fixture nodes and verifier
conditions in ``pseudofile_ext_ops.yaml``.
"""
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


class PseudofileExtTest(Plugin):
    def __init__(self):
        pass

    # lseek() handler: func(ptregs, file, offset, whence). Returns a distinctive
    # sentinel offset so the guest can prove the call reached the plugin.
    def seek_sentinel(self, ptregs, file, offset, whence):
        ptregs.retval = 4242
        if False:
            yield
