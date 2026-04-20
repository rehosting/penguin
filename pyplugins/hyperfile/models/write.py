from wrappers.ptregs_wrap import PtRegsWrapper
from penguin import plugins
import inspect
from os.path import isabs, join as pjoin
from .base import FilePtr, CharPtr, LoffTPtr, SizeT


class WriteDiscard:
    '''
    This mixin discards all written data.
    '''

    def __init__(self, **kwargs):
        # Even though we don't need args, we must pass kwargs up
        # in case we are mixed with something that does.
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr) -> None:
        """
        Discards all written data.
        Always returns the size written.
        """
        ptregs.retval = int(size)


class WriteReturnConst:
    '''
    A mixin that returns a constant value on write.
    '''

    def __init__(self, *, const: int, **kwargs):
        self.const = const
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr) -> None:
        ptregs.retval = self.const


class WriteUnhandled(WriteReturnConst):
    '''
    A mixin that returns -EINVAL on write.
    '''

    def __init__(self, **kwargs):
        super().__init__(const=-22, **kwargs)


class WriteRecord:
    '''
    Records all written data into self.written_data.
    '''

    def __init__(self, **kwargs):
        # Initialize the buffer here instead of doing hasattr checks in the loop.
        # Use setdefault in case another mixin touched it, though unlikely.
        if not hasattr(self, "written_data"):
            self.written_data = b""
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr) -> None:
        """
        Records all written data into self.written_data.
        Always returns the size written.
        """
        size_val = int(size)
        buf = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        self.written_data += buf
        ptregs.retval = size_val


class WriteDefault(WriteRecord):
    pass


class WriteToFile:
    '''
    Writes incoming data to a file on the host.
    '''

    def __init__(self, *, write_filepath: str = None, proj_dir: str = None, **kwargs):
        self.proj_dir = proj_dir
        if not isabs(write_filepath):
            # Paths are relative to the project directory, unless absolute
            self.write_filepath = pjoin(self.proj_dir, write_filepath)
        else:
            self.write_filepath = write_filepath
        # 2. FORWARD: Pass the rest up.
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr) -> None:
        """
        Writes all data to the specified host file.
        Always returns the size written.
        """
        if not self.write_filepath:
            # Fallback if initialized without a path, or return error
            ptregs.retval = -22
            return

        size_val = int(size)
        buf = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)

        with open(self.write_filepath, "wb") as f:
            f.seek(offset)
            f.write(buf)

        ptregs.retval = size_val


class WriteFromPlugin:
    '''
    Calls a function on a plugin to handle the write.
    Example usage:
        class MyFile(WriteFromPlugin, ...):
            def __init__(self):
                super().__init__(plugin="myplugin", function="handle_write")
    '''

    def __init__(self, *, plugin: str, function: str = "write", **kwargs):
        self._kwargs = kwargs
        self._kwargs["plugin"] = plugin
        self._kwargs["function"] = function
        self._plugin_name = plugin
        self._plugin_func = function
        self._plugin_obj = getattr(plugins, plugin, None)
        if self._plugin_obj is None:
            raise ValueError(
                f"WriteFromPlugin: plugin '{plugin}' not found in plugins")
        self._func = getattr(self._plugin_obj, self._plugin_func, None)
        if self._func is None:
            raise ValueError(
                f"WriteFromPlugin: function '{function}' not found on plugin '{plugin}'")
        sig = inspect.signature(self._func)
        params = sig.parameters.values()

        required = [
            p for p in params
            if p.default is inspect._empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        optional = [
            p for p in params
            if p.default is not inspect._empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        self._old_style = (len(required) == 6 and len(optional) == 1)
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        buf = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        if self._old_style:
            fname = getattr(self, "full_path", "unknown")
            result = self._func(self, fname, user_buf,
                                size_val, loff, buf, self._kwargs)
            # If the plugin returns a value, use it as retval, else default to size
            ptregs.retval = result if result is not None else size_val
        else:
            # New style: (self, ptregs, file, user_buf, size, loff)
            yield from self._func(ptregs, file, user_buf, size, loff)


class WriteExternalVFS:
    """Modern VFS Write Adapter"""

    def __init__(self, *, write_plugin: str = None, write_function: str = "write", **kwargs):
        self._func = getattr(getattr(plugins, write_plugin), write_function)
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        yield from self._func(ptregs, file, user_buf, size, loff)


class WriteExternalLegacy:
    """Legacy Write Adapter"""

    def __init__(self, *, write_plugin: str = None, write_function: str = "write", **kwargs):
        self._func = getattr(getattr(plugins, write_plugin), write_function)
        self._legacy_kwargs = kwargs.copy()
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        # Legacy writes often expected the buffer to be pre-read for them
        buf = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")

        result = self._func(self, getattr(self, "full_path", "unknown"),
                            user_buf, size_val, loff, buf, self._legacy_kwargs)

        # Legacy plugins usually return the bytes written or an error code
        ptregs.retval = result if result is not None else size_val
