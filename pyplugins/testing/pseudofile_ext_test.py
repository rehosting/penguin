#!/usr/bin/env python3
"""Runtime coverage for the expanded pseudofile surface.

Exercises three things the schema/unit tests can't reach in a live guest:

  * the broadened VFS-operation domains (``open``/``release``/``lseek`` via
    ``from_plugin``) — proving the kernel's calls actually reach a plugin
    handler and that side effects/return values flow back;
  * a ``@register_model`` custom read model selected from YAML by
    ``model: custom`` (the low-friction "expand models in Python" path);

The provenance/observability half (a ``provenance: default`` node reporting
``default_read``/``default_write``/``default_ioctl`` into
``pseudofiles_failures.yaml``) is driven entirely from config + the built-in
models, so it needs no handler here — only the fixture nodes and verifier
conditions in ``pseudofile_ext_ops.yaml``.
"""
from penguin import plugins, Plugin
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
        # Lifecycle counters, observable through the ``lifecycle`` read handler.
        self._open_count = 0
        self._release_count = 0

    # open()/release() VFS handlers: func(ptregs, inode, file). The bodies run
    # when the external adapter iterates the returned generator, so the
    # `if False: yield` keeps them generators with no actual yield point.
    def on_open(self, ptregs, inode, file):
        self._open_count += 1
        self.logger.info(f"ext open #{self._open_count}")
        if False:
            yield

    def on_release(self, ptregs, inode, file):
        self._release_count += 1
        self.logger.info(f"ext release #{self._release_count}")
        if False:
            yield

    # lseek() handler: func(ptregs, file, offset, whence). Returns a distinctive
    # sentinel offset so the guest can prove the call reached the plugin.
    def seek_sentinel(self, ptregs, file, offset, whence):
        ptregs.retval = 4242
        if False:
            yield

    # A read handler that reports the lifecycle counters, so the guest can
    # observe that open()/release() fired the expected number of times.
    def lifecycle(self, ptregs, file, user_buf, size, loff):
        data = f"open={self._open_count} release={self._release_count}\n".encode()
        size_val = int(size)
        offset = yield from plugins.kffi.deref(loff)
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk)
        ptregs.retval = chunk
