"""
PortalCall Plugin (portalcall.py) for Penguin
=============================================

This module provides the PortalCall plugin for the Penguin framework, enabling registration and handling of portalcalls via syscall filtering. It allows plugins to register handlers for specific portalcall magic values and process arguments from guest syscalls.

Features
--------

- Register portalcall handlers for specific magic values.
- Handle portalcall syscalls and dispatch to registered handlers.
- Safely read arguments from guest memory and return results.
- Supports coroutine-style handler functions.

Example Usage
-------------

.. code-block:: python

    from penguin import plugins

    @plugins.portalcall.portalcall(0x12345678)
    def my_portalcall_handler(arg1, arg2):
        # Process arguments and return result
        return arg1 + arg2

Classes
-------

- PortalCall: Main plugin class for portalcall registration and handling.

"""

from penguin import plugins, Plugin
from penguin.plugin_manager import resolve_bound_method_from_class
from typing import Callable, Dict, Iterator

PORTAL_MAGIC = 0xc1d1e1f1
PORTAL_MAGIC_64 = 0xffffffffc1d1e1f1


class PortalCall(Plugin):
    """
    Plugin that provides an interface to register and handle portalcalls via syscall filtering.
    """

    def __init__(self) -> None:
        self._portalcall_registry: Dict[int, Callable] = {}

        # 64-bit systems can sign-extend the magic number
        if self.panda.bits == 64:
            plugins.syscalls.syscall("on_sys_sendto_enter", arg_filters=[PORTAL_MAGIC_64, None, None, None, None])(self._portalcall_syscall_handler)
        plugins.syscalls.syscall("on_sys_sendto_enter", arg_filters=[PORTAL_MAGIC, None, None, None, None])(self._portalcall_syscall_handler)


    def _portalcall_syscall_handler(self, regs, proto, syscall, magic, user_magic, argc, args, dest_addr, addrlen):
        handler = self._portalcall_registry.get(user_magic & 0xffffffff)
        if handler is None:
            self.logger.error(
                f"No handler registered for user_magic {user_magic:#x}")
            return
        fn_to_call = resolve_bound_method_from_class(handler)
        if handler != fn_to_call:
            self._portalcall_registry[user_magic] = fn_to_call
        if argc == 0:
            argv = []
        else:
            argv = yield from plugins.mem.read_uint64_array(args, argc)
        result = fn_to_call(*argv)
        if isinstance(result, Iterator):
            result = yield from result
        syscall.skip_syscall = True
        if isinstance(result, int):
            syscall.retval = result
        else:
            syscall.retval = 0  # Default to 0 if result is not an int

    def portalcall(self, user_magic: int):
        """Decorator to register a portalcall handler for a given user_magic value."""
        def decorator(func):
            self._portalcall_registry[user_magic] = func
            return func
        return decorator
