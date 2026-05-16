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
    yield from plugins.signal_monitor.register_hook()
"""

from penguin import plugins, Plugin
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper
from typing import Optional, Generator, Any

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
        # Register the hypercall handler for signal delivery events
        self.panda.hypercall(iconsts.IGLOO_HYP_SIGNAL_DELIVER)(self._on_signal_deliver)
        plugins.register(self, "signal_deliver")

    def _on_signal_deliver(self, cpu):
        """
        Internal hypercall handler called when the guest driver detects a signal delivery.
        """
        # arg1 is pointer to struct signal_event in guest memory
        ptr = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        
        try:
            # Map the guest memory to a Python object using KFFI
            se_raw = plugins.kffi.new("struct signal_event", ptr)
            event = SignalEvent(se_raw)
            
            # Wrap regs in pt_regs_wrapper for architecture-agnostic access
            if se_raw.regs:
                regs_obj = plugins.kffi.new("struct pt_regs", se_raw.regs)
                event.regs = get_pt_regs_wrapper(self.panda, regs_obj)
            
            # Notify subscribers
            plugins.publish(self, "signal_deliver", cpu, event)
            
            # Note: changes to event._se are live if backed by guest memory.
            # Changes to event.regs (the wrapper) modify the regs_obj, 
            # which should also be backed by guest memory.
            
        except Exception as e:
            self.logger.error(f"Error handling signal delivery hypercall: {e}")

        # Return 0 to the guest
        self.panda.arch.set_retval(cpu, 0)

    def register_hook(self, sig: int = 0, pid: Optional[int] = None, 
                      procname: Optional[str] = None) -> Generator[Any, None, Optional[int]]:
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
        Optional[int]
            Handle to the registered hook, or None on failure.
        """
        init_data = {
            "enabled": True,
            "sig": sig,
            "pid_filter_enabled": pid is not None,
            "filter_pid": pid or 0,
            "comm_filter_enabled": procname is not None,
            "comm_filter": procname or ""
        }
        
        # Create the hook structure
        sh = plugins.kffi.new("struct signal_hook", init_data)
        as_bytes = bytes(sh)
        
        # Send to guest via portal
        result = yield PortalCmd(hop.HYPER_OP_REGISTER_SIGNAL_HOOK, size=len(as_bytes), data=as_bytes)
        if result == 0:
            self.logger.error("Failed to register signal hook in guest")
            return None
        return result

    def unregister_hook(self, handle: int) -> Generator[Any, None, bool]:
        """
        Unregister a signal hook.

        Parameters
        ----------
        handle : int
            The handle returned by register_hook.

        Returns
        -------
        bool
            True if successful.
        """
        result = yield PortalCmd(hop.HYPER_OP_UNREGISTER_SIGNAL_HOOK, addr=handle)
        return result != 0
