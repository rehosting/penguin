"""
Signal Monitor Plugin (signal_monitor.py)
=========================================

This module provides the Signal Monitor plugin for the Penguin framework.
It allows monitoring and interception of signals sent to processes in the guest OS.
Plugins can register for signal events and optionally drop signals or modify the process state.

Usage
-----

.. code-block:: python

    from penguin import plugins

    @plugins.subscribe(plugins.signal_monitor, "signal_deliver")
    def on_signal(cpu, event):
        print(f"Signal {event.sig} delivered to {event.comm} (PID {event.pid})")
        if event.sig == 4: # SIGILL
            print("Intercepted SIGILL! Bypassing...")
            event.drop = True
            event.regs.set_pc(event.regs.get_pc() + 4) # Advance PC (assuming 4-byte instruction)

    # Register a hook for all signals
    plugins.signal_monitor.register_hook()
"""

from penguin import plugins, Plugin
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper
from typing import Optional


class SignalEvent:
    """
    Wrapper for struct signal_event from the guest driver.
    """
    __slots__ = ('_se', 'comm', 'regs')

    def __init__(self, se):
        self._se = se
        # Extract comm string safely
        raw_bytes = bytes(se.comm)
        self.comm = raw_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        self.regs = None

    def __getattr__(self, attr):
        return getattr(self._se, attr)

    def __setattr__(self, attr, value):
        if attr in self.__slots__:
            object.__setattr__(self, attr, value)
        else:
            setattr(self._se, attr, value)

    def __bytes__(self) -> bytes:
        return bytes(self._se)


class SignalMonitor(Plugin):
    """
    Signal Monitor Plugin
    =====================
    Interacts with the igloo_driver to monitor and intercept signals.
    """

    def __init__(self):
        super().__init__()
        self._pending_commands = []
        plugins.portal.register_interrupt_handler(
            "signal_monitor", self._signal_interrupt_handler)
        # Register the hypercall handler for signal delivery events
        self.panda.hypercall(iconsts.IGLOO_HYP_SIGNAL_DELIVER)(self._on_signal_deliver)
        plugins.register(self, "signal_deliver")

    def _signal_interrupt_handler(self):
        """
        Process queued signal hook register/unregister commands.
        """
        if not self._pending_commands:
            return False

        pending_commands = self._pending_commands[:]
        self._pending_commands = []

        while pending_commands:
            command = pending_commands.pop(0)
            op = command[0]

            if op == "register":
                _, init_data = command
                handle = yield from self._register_hook(init_data)
                if handle:
                    self.logger.debug(f"Registered signal hook {handle:#x}")
                else:
                    self.logger.debug("Signal hook registration completed")
            elif op == "unregister":
                _, handle = command
                yield from self._unregister_hook(handle)
            else:
                self.logger.error(f"Unknown signal monitor command: {op}")

        return False

    def _on_signal_deliver(self, cpu):
        """
        Internal hypercall handler called when the guest driver detects a signal delivery.
        """
        # arg1 is pointer to struct signal_event in guest memory
        ptr = self.panda.arch.get_arg(cpu, 1, convention="syscall")

        try:
            # Map the guest memory to a Python object using KFFI
            se_raw = plugins.kffi.read_type_panda(cpu, ptr, "signal_event")
            if not se_raw:
                self.logger.error(f"Failed to read signal_event at {ptr:#x}")
                self.panda.arch.set_retval(cpu, 0)
                return

            original_event = bytes(se_raw)
            event = SignalEvent(se_raw)

            # Wrap regs in pt_regs_wrapper for architecture-agnostic access
            regs_addr = getattr(se_raw.regs, "address", se_raw.regs)
            regs_obj = None
            original_regs = None
            if regs_addr:
                regs_obj = plugins.kffi.read_type_panda(cpu, regs_addr, "pt_regs")
                if regs_obj:
                    original_regs = bytes(regs_obj)
                    event.regs = get_pt_regs_wrapper(self.panda, regs_obj)

            # Notify subscribers
            plugins.publish(self, "signal_deliver", cpu, event)

            new_event = bytes(se_raw)
            if new_event != original_event:
                plugins.mem.write_bytes_panda(cpu, ptr, new_event)

            if regs_obj and original_regs is not None:
                new_regs = bytes(regs_obj)
                if new_regs != original_regs:
                    plugins.mem.write_bytes_panda(cpu, regs_addr, new_regs)

        except Exception as e:
            self.logger.error(f"Error handling signal delivery hypercall: {e}")

        # Return 0 to the guest
        self.panda.arch.set_retval(cpu, 0)

    def register_hook(self, sig: int = 0, pid: Optional[int] = None,
                      procname: Optional[str] = None) -> bool:
        """
        Register a signal hook in the guest driver.

        Parameters
        ----------
        sig : int, optional
            Signal number to hook (0 for all). Default is 0.
        pid : int, optional
            Filter by process ID.
        procname : str, optional
            Filter by process name (comm).

        Returns
        -------
        bool
            True if the hook registration was queued.
        """
        init_data = {
            "enabled": True,
            "sig": sig,
            "pid_filter_enabled": pid is not None,
            "filter_pid": pid or 0,
            "comm_filter_enabled": procname is not None,
            "comm_filter": procname or ""
        }

        self._pending_commands.append(("register", init_data))
        return plugins.portal.queue_interrupt("signal_monitor")

    def _register_hook(self, init_data):
        """
        Register a signal hook in the guest driver via the portal.
        """

        # Create the hook structure
        sh = plugins.kffi.new("struct signal_hook", init_data)
        as_bytes = bytes(sh)

        # Send to guest via portal
        result = yield PortalCmd(hop.HYPER_OP_REGISTER_SIGNAL_HOOK, size=len(as_bytes), data=as_bytes)
        if result == 0:
            self.logger.error("Failed to register signal hook in guest")
            return None
        return result

    def unregister_hook(self, handle: int) -> bool:
        """
        Unregister a signal hook.

        Parameters
        ----------
        handle : int
            The handle returned by register_hook.

        Returns
        -------
        bool
            True if the unregister command was queued.
        """
        self._pending_commands.append(("unregister", handle))
        return plugins.portal.queue_interrupt("signal_monitor")

    def _unregister_hook(self, handle: int):
        """
        Unregister a signal hook via the portal.
        """
        result = yield PortalCmd(hop.HYPER_OP_UNREGISTER_SIGNAL_HOOK, addr=handle)
        return result != 0
