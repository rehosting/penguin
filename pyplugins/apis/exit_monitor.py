"""
Exit Monitor Plugin (exit_monitor.py)
=====================================

Surfaces guest task-exit events from the igloo_driver ``do_exit`` kprobe. Unlike
the exit/exit_group *syscall* hooks, this fires on the kernel task-exit path, so
it also captures deaths that never issue an exit syscall -- fatal signals
(SIGSEGV/SIGKILL/...), OOM kills, kernel-forced exits -- each with the real,
wait(2)-status-encoded exit code. One event per user process (reported at
thread-group-leader death), so it maps 1:1 onto the leader-only process model.

This is the authoritative process-exit source: it replaces the host-side
signal-death heuristic (which cannot distinguish a caught SIGSEGV from a fatal
one) and needs no per-signal guesswork.

Usage
-----

.. code-block:: python

    from penguin import plugins

    @plugins.subscribe(plugins.exit_monitor, "proc_exit")
    def on_exit(cpu, event):
        # event.code is the raw do_exit() code in wait-status encoding.
        print(f"pid {event.pid} ({event.comm}) exited, code={event.code:#x}")

    plugins.exit_monitor.enable()   # opt in; costs nothing until enabled
"""

from penguin import plugins, Plugin
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd


class ExitEvent:
    """Wrapper for struct exit_event from the guest driver."""
    __slots__ = ('_ee', 'comm')

    def __init__(self, ee):
        self._ee = ee
        raw = bytes(ee.comm)
        self.comm = raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

    def __getattr__(self, attr):
        return getattr(self._ee, attr)

    def __bytes__(self) -> bytes:
        return bytes(self._ee)

    # --- wait(2) status decoding of the raw do_exit() code ------------- #
    @property
    def signaled(self) -> bool:
        """True if the process was killed by a signal (WIFSIGNALED)."""
        return (int(self.code) & 0x7f) not in (0, 0x7f)

    @property
    def termsig(self) -> int:
        """Signal number that killed the process, or 0 (WTERMSIG)."""
        return int(self.code) & 0x7f if self.signaled else 0

    @property
    def core_dumped(self) -> bool:
        return bool(int(self.code) & 0x80) if self.signaled else False

    @property
    def exit_status(self) -> int:
        """Normal-exit status (WEXITSTATUS); meaningful only if not signaled."""
        return (int(self.code) >> 8) & 0xff


class ExitMonitor(Plugin):
    """Interacts with the igloo_driver do_exit kprobe to surface task exits."""

    def __init__(self):
        super().__init__()
        self._enabled = False
        self._pending = 0   # net enable(+1)/disable(-1) requests to flush
        plugins.portal.register_interrupt_handler(
            "exit_monitor", self._interrupt_handler)
        plugins.hypercall.hypercall(iconsts.IGLOO_HYP_PROC_EXIT)(
            self._on_proc_exit)
        plugins.register(self, "proc_exit")

    def _interrupt_handler(self):
        """Flush queued enable/disable toggles to the guest driver."""
        want = self._enabled
        # collapse to a single op reflecting the desired state
        op = (hop.HYPER_OP_REGISTER_EXIT_HOOK if want
              else hop.HYPER_OP_UNREGISTER_EXIT_HOOK)
        yield PortalCmd(op)
        return False

    def _on_proc_exit(self, cpu):
        """Hypercall handler: guest driver reports a task exit."""
        ptr = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        try:
            ee_raw = plugins.kffi.read_type_panda(cpu, ptr, "exit_event")
            if not ee_raw:
                self.logger.error(f"Failed to read exit_event at {ptr:#x}")
            else:
                plugins.publish(self, "proc_exit", cpu, ExitEvent(ee_raw))
        except Exception as e:
            self.logger.error(f"Error handling proc_exit hypercall: {e}")
        self.panda.arch.set_retval(cpu, 0)

    def enable(self) -> bool:
        """Enable the guest do_exit hook (idempotent). Opt-in: nothing fires
        until at least one plugin calls this."""
        self._enabled = True
        return plugins.portal.queue_interrupt("exit_monitor")

    def disable(self) -> bool:
        self._enabled = False
        return plugins.portal.queue_interrupt("exit_monitor")
