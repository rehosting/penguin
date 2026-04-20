from wrappers.ptregs_wrap import PtRegsWrapper
from penguin import plugins
from typing import Union
from .base import FilePtr, CInt

class IoctlReturnMixin:
    '''
    Base mixin that simply returns a constant integer for any IOCTL.
    '''
    def __init__(self, *, ioctl_retval: int = 0, **kwargs):
        self.ioctl_retval = ioctl_retval
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        ptregs.retval = self.ioctl_retval

class IoctlZero(IoctlReturnMixin):
    '''
    Always returns 0 (Success).
    '''
    def __init__(self, **kwargs):
        super().__init__(ioctl_retval=0, **kwargs)

class IoctlUnhandled(IoctlReturnMixin):
    '''
    Always returns -25 (-ENOTTY: Inappropriate ioctl for device).
    '''
    def __init__(self, **kwargs):
        super().__init__(ioctl_retval=-25, **kwargs)

class IoctlWriteDataArg:
    '''
    Writes a constant buffer to the address pointed to by 'arg'.
    Returns 0 after writing.
    '''
    def __init__(self, *, ioctl_data: Union[bytes, int, str] = b"", retval: int = 0, **kwargs):
        if isinstance(ioctl_data, str):
            ioctl_data = ioctl_data.encode("utf-8")
        self.ioctl_data = ioctl_data
        self.retval = retval
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        # Only write if we have data and a valid pointer
        arg_addr = int(arg)
        if self.ioctl_data and arg_addr != 0:
            yield from plugins.mem.write(arg_addr, self.ioctl_data)
        
        # Standard success return
        ptregs.retval = self.retval


class IoctlExternalVFS:
    """Modern VFS Ioctl Adapter"""
    def __init__(self, *, ioctl_plugin: str = None, ioctl_function: str = "ioctl", **kwargs):
        self._func = getattr(getattr(plugins, ioctl_plugin), ioctl_function)
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        yield from self._func(ptregs, file, cmd, arg)


class IoctlExternalLegacy:
    """Legacy Ioctl Adapter"""
    def __init__(self, *, ioctl_plugin: str = None, ioctl_function: str = "ioctl", **kwargs):
        self._func = getattr(getattr(plugins, ioctl_plugin), ioctl_function)
        self._legacy_kwargs = kwargs.copy()
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        # Legacy ioctls were often synchronous and returned the value directly
        result = self._func(self, getattr(self, "full_path", "unknown"), int(cmd), int(arg), self._legacy_kwargs)
        ptregs.retval = result if result is not None else 0


class IoctlDispatcher:
    """
    The Mixin that DevFile inherits. 
    It routes the ioctl 'cmd' to the correct Handler.
    """
    def __init__(self, *, ioctl_handlers: dict = None, **kwargs):
        self.ioctl_handlers = ioctl_handlers or {}
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        cmd_val = int(cmd)
        
        # 1. Try exact match
        handler = self.ioctl_handlers.get(cmd_val)
        
        # 2. Try string match (sometimes yaml parses numbers as strings)
        if handler is None:
            handler = self.ioctl_handlers.get(str(cmd_val))

        # 3. Try wildcard
        if handler is None:
            handler = self.ioctl_handlers.get("*")
            
        # 4. Dispatch or Fail
        if handler:
            # We pass 'self' so handlers can access file attributes if needed
            yield from handler.handle(self, ptregs, file, cmd_val, arg)
        else:
            # Default error for unhandled ioctl
            ptregs.retval = -25 # -ENOTTY

class IoctlHandlerBase:
    def handle(self, file_obj, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        raise NotImplementedError

class IoctlReturnConst(IoctlHandlerBase):
    """Returns a static constant."""
    def __init__(self, val):
        self.val = val

    def handle(self, file_obj, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        ptregs.retval = self.val
        if False: yield # Ensure it's a generator

class IoctlPluginVFS(IoctlHandlerBase):
    """Calls a modern VFS plugin function."""
    def __init__(self, plugin_name, func_name):
        self.func = getattr(getattr(plugins, plugin_name), func_name)

    def handle(self, file_obj, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        yield from self.func(ptregs, file, cmd, arg)

class IoctlPluginLegacy(IoctlHandlerBase):
    """Calls a legacy plugin function (synchronous/complex return)."""
    def __init__(self, plugin_name, func_name, extra_kwargs):
        self.func = getattr(getattr(plugins, plugin_name), func_name)
        self.extra_kwargs = extra_kwargs

    def handle(self, file_obj, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        # Legacy signature often expects (self, filename, cmd, arg, details)
        # We pass file_obj as 'self' to the plugin
        result = self.func(
            file_obj, 
            getattr(file_obj, "full_path", "unknown"), 
            int(cmd), 
            int(arg), 
            self.extra_kwargs
        )
        ptregs.retval = result if result is not None else 0
        if False: yield # Ensure it's a generator