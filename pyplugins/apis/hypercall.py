from collections import defaultdict
from collections.abc import Iterator
from typing import Any, Callable, DefaultDict, List

from penguin import Plugin


def _hypercall_aliases(nr: int) -> tuple[int, ...]:
    raw = int(nr)
    unsigned32 = raw & 0xFFFFFFFF
    signed32 = unsigned32 - 0x100000000 if unsigned32 & 0x80000000 else unsigned32
    unsigned64 = raw & 0xFFFFFFFFFFFFFFFF
    return tuple(dict.fromkeys((raw, unsigned32, signed32, unsigned64)))


class Hypercall(Plugin):
    """
    QEMU backend hypercall registry.

    This replaces the old PANDA C hypercall plugin with a Penguin pyplugin that
    owns the magic-number to callback mapping. qemu_compat only forwards backend
    hypercall exits here.
    """

    def __init__(self) -> None:
        self.handlers: DefaultDict[int, List[Callable]] = defaultdict(list)

    def register(self, nr: int, func: Callable) -> Callable:
        for alias in _hypercall_aliases(nr):
            self.handlers[alias].append(func)
        return func

    def hypercall(self, nr: int) -> Callable[[Callable], Callable]:
        def decorator(func: Callable) -> Callable:
            return self.register(nr, func)
        return decorator

    def __call__(self, nr: int) -> Callable[[Callable], Callable]:
        return self.hypercall(nr)

    def _handle_portal_cmd(self, cmd: Any) -> Any:
        from hyper.consts import HYPER_OP as hop

        if cmd.op in {hop.HYPER_OP_READ, hop.HYPER_OP_READ_STR}:
            return self.panda.virtual_memory_read(self.panda.get_cpu(), cmd.addr, cmd.size)
        if cmd.op == hop.HYPER_OP_WRITE:
            self.panda.virtual_memory_write(self.panda.get_cpu(), cmd.addr, cmd.data or b"")
            return cmd.size

        raise RuntimeError(
            f"Hypercall compatibility layer cannot service PortalCmd op={cmd.op:#x} "
            "without the guest portal interrupt path"
        )

    def _run_result(self, result: Any) -> Any:
        if not isinstance(result, Iterator):
            return result

        value = None
        while True:
            try:
                cmd = result.send(value)
            except StopIteration as stop:
                return stop.value

            value = None
            if cmd.__class__.__name__ == "PortalCmd":
                value = self._handle_portal_cmd(cmd)

    def dispatch(self, cpu, nr: int, ret_ptr) -> int:
        handlers = None
        for alias in _hypercall_aliases(nr):
            handlers = self.handlers.get(alias)
            if handlers:
                break
        if not handlers:
            return 1

        for handler in handlers:
            try:
                result = handler(cpu)
                result = self._run_result(result)
                if isinstance(result, int):
                    self.panda._set_current_retval(result)
            except Exception as exc:
                self.logger.exception("Error in hypercall handler for %#x: %s", nr, exc)

        if ret_ptr[0] == 0:
            ret_ptr[0] = self.panda._current_retval
        return 0
