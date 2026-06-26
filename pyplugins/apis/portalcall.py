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
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from typing import Callable, Dict, Iterator

PORTAL_MAGIC = 0xc1d1e1f1
PORTAL_MAGIC_64 = 0xffffffffc1d1e1f1
PORTAL_MAGIC_MASK = 0xffffffff

# Sentinel distinguishing "no handler registered" from a handler returning
# None: with no handler we must let the guest's real syscall execute (and
# fail loudly) instead of faking a successful return.
_MISSING_HANDLER = object()


class PortalCall(Plugin):
    """
    Plugin that provides an interface to register and handle portalcalls via syscall filtering.
    """

    def __init__(self) -> None:
        self._portalcall_registry: Dict[int, Callable] = {}
        self._pending_fastpath_magics = []
        self._synced_fastpath_magics = set()
        self._fastpath_supported = (
            hasattr(hop, "HYPER_OP_REGISTER_PORTALCALL_MAGIC") and
            hasattr(hop, "HYPER_OP_SET_PORTALCALL_FASTPATH")
        )
        if self._fastpath_supported:
            plugins.portal.register_interrupt_handler(
                "portalcall", self._portalcall_interrupt_handler)

        # scope_filter=False: the portal transport carries hypercalls for
        # Penguin's own infrastructure too (e.g. init.sh's readiness signal and
        # scope.py enabling gating), so it must never be scoped to the firmware
        # subtree -- doing so would cut off the transport for infra.
        # 64-bit systems can sign-extend the magic number
        if self.panda.bits == 64:
            plugins.syscalls.syscall("on_sys_sendto_enter", arg_filters=[PORTAL_MAGIC_64, None, None, None, None], scope_filter=False)(self._portalcall_syscall_handler)
        self._seen_missing_magics = set()
        plugins.syscalls.syscall("on_sys_sendto_enter", arg_filters=[PORTAL_MAGIC, None, None, None, None], scope_filter=False)(self._portalcall_syscall_handler)

    def _portalcall_syscall_handler(self, regs, proto, syscall, magic, user_magic, argc, args, dest_addr, addrlen):
        if not self._is_portal_magic(magic):
            return
        result = yield from self._dispatch_portalcall(user_magic, argc, args)
        if result is _MISSING_HANDLER:
            return
        syscall.skip_syscall = True
        if isinstance(result, int):
            syscall.retval = result
        else:
            syscall.retval = 0  # Default to 0 if result is not an int

    def _is_portal_magic(self, magic: int) -> bool:
        return int(magic) & PORTAL_MAGIC_MASK == PORTAL_MAGIC

    def _dispatch_portalcall(self, user_magic, argc, args):
        user_magic = user_magic & 0xffffffff
        handler = self._portalcall_registry.get(user_magic)
        if handler is None:
            if user_magic not in self._seen_missing_magics:
                self.logger.error(
                    f"No handler registered for user_magic {user_magic:#x}; "
                    "letting the guest syscall run unhandled")
                self._seen_missing_magics.add(user_magic)
            else:
                self.logger.debug(
                    f"No handler registered for user_magic {user_magic:#x}")
            return _MISSING_HANDLER
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
        return result

    def portalcall(self, user_magic: int):
        """Decorator to register a portalcall handler for a given user_magic value."""
        def decorator(func):
            user_magic_key = user_magic & 0xffffffff
            self._portalcall_registry[user_magic] = func
            self._portalcall_registry[user_magic_key] = func
            self._queue_fastpath_magic(user_magic_key)
            return func
        return decorator

    def _queue_fastpath_magic(self, user_magic: int) -> None:
        if not self._fastpath_supported:
            return
        if user_magic in self._synced_fastpath_magics:
            return
        if user_magic not in self._pending_fastpath_magics:
            self._pending_fastpath_magics.append(user_magic)
        plugins.portal.queue_interrupt("portalcall")

    def _portalcall_interrupt_handler(self):
        if not self._pending_fastpath_magics:
            return False

        pending = self._pending_fastpath_magics[:]
        self._pending_fastpath_magics = []

        yield PortalCmd(hop.HYPER_OP_SET_PORTALCALL_FASTPATH, addr=0)
        for user_magic in pending:
            if user_magic in self._synced_fastpath_magics:
                continue
            yield PortalCmd(
                hop.HYPER_OP_REGISTER_PORTALCALL_MAGIC,
                addr=user_magic)
            self._synced_fastpath_magics.add(user_magic)
        yield PortalCmd(hop.HYPER_OP_SET_PORTALCALL_FASTPATH, addr=1)
