"""Declarative models for VFS operations beyond read/write/ioctl/poll.

These expose the rest of the ``file_operations`` surface that ``VFSFile``
already defines (lseek, open, release, mmap) as first-class, named config
models, so a node can model them without dropping to a full plugin. Every
model here is optional: a node that omits a domain keeps today's behavior
(the no-op ``VFSFile`` stub, i.e. the kernel default).
"""

import inspect
from penguin import plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from .base import FilePtr, InodePtr, VmAreaPtr, LoffT, CInt


# ---------------------------------------------------------------------------
# lseek
# ---------------------------------------------------------------------------

class SeekDefault:
    """Standard offset arithmetic against the node's reported SIZE.

    Makes the implicit known-size seek behavior nameable. Handles
    SEEK_SET/SEEK_CUR/SEEK_END and clamps to [0, SIZE].
    """

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt):
        offset_val = int(offset)
        whence_val = int(whence)
        size = int(getattr(self, "SIZE", 0))

        cur = yield from plugins.kffi.read_field(file, "struct file", "f_pos")
        cur_val = int(cur)

        if whence_val == 0:      # SEEK_SET
            new_offset = offset_val
        elif whence_val == 1:    # SEEK_CUR
            new_offset = cur_val + offset_val
        elif whence_val == 2:    # SEEK_END
            new_offset = size + offset_val
        else:
            ptregs.retval = -22  # -EINVAL
            return

        if new_offset < 0 or new_offset > size:
            ptregs.retval = -22
            return

        yield from plugins.kffi.write_field(file, "struct file", "f_pos", new_offset)
        ptregs.retval = new_offset


class SeekUnsupported:
    """Reject seeking with -ESPIPE (for pipe/stream-like nodes)."""

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt):
        if False:
            yield
        ptregs.retval = -29  # -ESPIPE


class SeekExternalVFS:
    """Call a plugin function with the lseek VFS signature."""

    def __init__(self, *, lseek_plugin: str = None, lseek_function: str = "lseek", **kwargs):
        self._lseek_func = getattr(getattr(plugins, lseek_plugin), lseek_function)
        super().__init__(**kwargs)

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt):
        res = self._lseek_func(ptregs, file, offset, whence)
        if inspect.isgenerator(res):
            yield from res


# ---------------------------------------------------------------------------
# open / release
# ---------------------------------------------------------------------------

class OpenExternalVFS:
    """Call a plugin function on open(): func(ptregs, inode, file)."""

    def __init__(self, *, open_plugin: str = None, open_function: str = "open", **kwargs):
        self._open_func = getattr(getattr(plugins, open_plugin), open_function)
        super().__init__(**kwargs)

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        # Default to success (0). open() is `int (*)(...)`: a non-zero return
        # fails the open() syscall, so a side-effect-only hook that never
        # touches retval would otherwise break the file. The hook may still set
        # ptregs.retval to fail the open deliberately.
        ptregs.retval = 0
        res = self._open_func(ptregs, inode, file)
        if inspect.isgenerator(res):
            yield from res


class ReleaseExternalVFS:
    """Call a plugin function on release()/close(): func(ptregs, inode, file)."""

    def __init__(self, *, release_plugin: str = None, release_function: str = "release", **kwargs):
        self._release_func = getattr(getattr(plugins, release_plugin), release_function)
        super().__init__(**kwargs)

    def release(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        # Default to success (0); release() is `int (*)(...)` like open().
        ptregs.retval = 0
        res = self._release_func(ptregs, inode, file)
        if inspect.isgenerator(res):
            yield from res


# ---------------------------------------------------------------------------
# mmap
# ---------------------------------------------------------------------------

class MmapExternalVFS:
    """Call a plugin function on mmap(): func(ptregs, file, vm_area_struct)."""

    def __init__(self, *, mmap_plugin: str = None, mmap_function: str = "mmap", **kwargs):
        self._mmap_func = getattr(getattr(plugins, mmap_plugin), mmap_function)
        super().__init__(**kwargs)

    def mmap(self, ptregs: PtRegsWrapper, file: FilePtr, vm_area_struct: VmAreaPtr):
        res = self._mmap_func(ptregs, file, vm_area_struct)
        if inspect.isgenerator(res):
            yield from res


# ---------------------------------------------------------------------------
# Generic plugin-op adapters for the remaining (device-specific) fops:
# flush, fsync, fasync, lock, read_iter, write_iter, get_unmapped_area,
# compat_ioctl. Each just forwards the kernel's call to a plugin function with
# the op's native VFS signature; the per-op signature is supplied by the
# registration layer's DWARF info, so the adapter only needs to forward args.
# ---------------------------------------------------------------------------

def _make_plugin_op_adapter(op):
    """Build a mixin class that routes ``op`` to a plugin function.

    Reads ``{op}_plugin`` / ``{op}_function`` kwargs (produced by
    ``_translate_kwargs``) and defines a method named ``op`` forwarding all
    arguments to the plugin function, yielding if it is a generator.
    """
    plugin_kw = f"{op}_plugin"
    func_kw = f"{op}_function"
    attr = f"_{op}_func"

    def __init__(self, **kwargs):
        plugin = kwargs.pop(plugin_kw, None)
        function = kwargs.pop(func_kw, op)
        setattr(self, attr, getattr(getattr(plugins, plugin), function))
        super(adapter, self).__init__(**kwargs)

    def _method(self, *args):
        res = getattr(self, attr)(*args)
        if inspect.isgenerator(res):
            yield from res

    cls_name = "".join(p.title() for p in op.split("_")) + "ExternalVFS"
    adapter = type(cls_name, (object,), {
        "__init__": __init__,
        op: _method,
        "__doc__": f"Call a plugin function for {op}().",
    })
    return adapter


FlushExternalVFS = _make_plugin_op_adapter("flush")
FsyncExternalVFS = _make_plugin_op_adapter("fsync")
FasyncExternalVFS = _make_plugin_op_adapter("fasync")
LockExternalVFS = _make_plugin_op_adapter("lock")
ReadIterExternalVFS = _make_plugin_op_adapter("read_iter")
WriteIterExternalVFS = _make_plugin_op_adapter("write_iter")
GetUnmappedAreaExternalVFS = _make_plugin_op_adapter("get_unmapped_area")
CompatIoctlExternalVFS = _make_plugin_op_adapter("compat_ioctl")
