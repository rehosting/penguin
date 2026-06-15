from penguin import plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from .base import FilePtr, PollTablePtr
import inspect


# POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM
_POLL_READY_MASK = 0x145


class PollAlwaysReady:
    """
    Legacy/default poll mixin: report the node permanently readable and
    writable. This is the historical behavior for /dev pseudofiles that do not
    model poll explicitly. Note that a reader doing poll()->read() against a
    callback-backed node that has no data will busy-loop, so data-aware nodes
    should provide their own poll() (via a `poll: from_plugin` domain or a
    single-object `plugin:` backing) instead of relying on this.
    """

    _POLL_READY_MASK = _POLL_READY_MASK

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table_struct: PollTablePtr):
        ptregs.retval = self._POLL_READY_MASK


class PollExternalVFS:
    """
    Modern Adapter: Calls a plugin function with the standard VFS poll
    signature so the plugin can report readiness based on its own state.
    func(ptregs, file, poll_table_struct) -> Generator | None

    The resolved callable is stored in its own attribute (`_poll_func`) so it
    never collides with the read/write/ioctl adapters (see issue #839).
    """

    def __init__(self, *, poll_plugin: str = None, poll_function: str = "poll", **kwargs):
        self._poll_func = getattr(getattr(plugins, poll_plugin), poll_function)
        super().__init__(**kwargs)

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table_struct: PollTablePtr):
        res = self._poll_func(ptregs, file, poll_table_struct)
        if inspect.isgenerator(res):
            yield from res
