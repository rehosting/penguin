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


class PollNeverReady:
    """
    Report the node permanently *not* ready: poll()/select()/epoll return a
    zero mask, so the waiter parks on the per-device wait queue (the devfs poll
    proxy calls poll_wait() before consulting us — issue #77) instead of
    spinning. Use this for event-source nodes whose read() blocks until a
    hardware event that never occurs under emulation (e.g. an AVM-style
    /dev/watchdog whose supervisor thread does poll()->read() and busy-loops
    forever against the always-ready default). A later write to the node wakes
    the parked waiter via the proxy's wake_up_interruptible(), so a
    request/response device can still make progress.
    """

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table_struct: PollTablePtr):
        ptregs.retval = 0


class PollPeriodic:
    """
    Report the node readable on a fixed cadence. An igloo_driver kernel timer
    marks the node ready every ``interval_ms`` and wakes the per-device wait
    queue; the devfs poll proxy then returns POLLIN once per tick and parks the
    waiter in between (issue #77 supplies the wait queue). Models an event-source
    device that delivers a periodic hardware heartbeat -- e.g. an AVM-style
    /dev/watchdog whose supervisor main loop epoll_wait()s with an infinite
    timeout and only advances its service state machine when the watchdog ticks.
    always-ready spins that loop; never-ready (``blocking``) deadlocks it;
    periodic readiness matches real hardware.

    The cadence lives entirely in the driver timer: a host-side poll model
    cannot re-arm an epoll(timeout=-1) waiter, since poll() is only re-invoked
    when poll_wq is woken. This mixin therefore only carries the interval down
    to devfs registration (via ``POLL_INTERVAL_MS``, read by devfs.py) so the
    driver arms its timer. Its poll() is a park fallback for a driver that
    predates the timer field.
    """

    def __init__(self, *, interval_ms: int = 1000, **kwargs):
        self.POLL_INTERVAL_MS = int(interval_ms)
        super().__init__(**kwargs)

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table_struct: PollTablePtr):
        ptregs.retval = 0


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
