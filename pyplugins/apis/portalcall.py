from penguin import plugins, Plugin
from penguin.plugin_manager import resolve_bound_method_from_class
from typing import Callable, Dict, Iterator

PORTAL_MAGIC = 0xc1d1e1f1


class PortalCall(Plugin):
    """
    Plugin that provides an interface to register and handle portalcalls via syscall filtering.
    """

    def __init__(self) -> None:
        self._portalcall_registry: Dict[int, Callable] = {}
        # Register with syscalls plugin for portalcall filtering

    @plugins.syscalls.syscall("on_sys_sendto_enter", arg_filters=[PORTAL_MAGIC, None, None, None, None])
    def _portalcall_syscall_handler(self, regs, proto, syscall, magic, user_magic, argc, args, dest_addr, addrlen):
        handler = self._portalcall_registry.get(user_magic)
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
