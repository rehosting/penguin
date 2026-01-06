"""
.. include:: /docs/kprobes.md
   :parser: myst_parser.sphinx_
"""

import os
from penguin import Plugin, plugins
from penguin.plugin_manager import resolve_bound_method_from_class
from typing import Dict, List, Any, Union, Callable, Optional, Iterator
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import portal_type
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper


class Kprobes(Plugin):
    """
    Kprobes Plugin
    ==============

    Provides an interface for registering and handling kernel probes (kprobes) in the guest kernel.
    Supports filtering by PID or process name, and coroutine-based event handling.

    Attributes
    ----------
    probes : Dict[int, Dict[str, Any]]
        Registered probe callbacks by probe ID.
    probe_info : Dict[int, Dict[str, Any]]
        Metadata for each registered probe.
    _pending_kprobes : List[Dict[str, Any]]
        Queue of kprobes pending registration.
    _func_to_probe_id : Dict[Callable, int]
        Maps callback functions to probe IDs.
    _name_to_probe_id : Dict[str, int]
        Maps function names to probe IDs.
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.projdir = self.get_arg("proj_dir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.probes: Dict[int, Dict[str, Any]] = {}
        self.probe_info = {}
        self._pending_kprobes: List[Dict[str, Any]] = []
        self._func_to_probe_id = {}  # Maps function to probe_id
        self._name_to_probe_id = {}  # Maps function name to probe_id
        self.portal = plugins.portal
        self.portal.register_interrupt_handler(
            "kprobes", self._kprobe_interrupt_handler)
        self.fs_init = False
        self.panda.hypercall(iconsts.IGLOO_HYP_KPROBE_ENTER)(
            self._kprobe_enter_handler)
        self.panda.hypercall(iconsts.IGLOO_HYP_KPROBE_RETURN)(
            self._kprobe_return_handler)
        self.saved_regs_info = {}
        self._kprobe_event = self.plugins.portal.wrap(self._kprobe_event)

    def _kprobe_event(self, cpu: Any, is_enter: bool) -> Any:
        """
        Handle a kprobe event from the portal.

        Invokes the registered callback for the probe, passing a `pt_regs` wrapper.

        Parameters
        ----------
        cpu : Any
            CPU context.
        is_enter : bool
            True if entry probe, False if return probe.

        Returns
        -------
        Any
            Return value from the callback, if any.
        """
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        # possible issue with registring multiple cpu _memregions
        sce = plugins.kffi.read_type_panda(cpu, arg, "portal_event")
        ptregs_addr = sce.regs.address
        pt_regs_raw = plugins.kffi.read_type_panda(cpu, ptregs_addr, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)
        original_bytes = pt_regs.to_bytes()[:]

        if sce.id not in self.probes:
            self.logger.error(
                f"Kprobe ID {sce.id} not found in registered probes")
            return

        probe_info = self.probes[sce.id]
        cb = probe_info["callback"]
        fn = resolve_bound_method_from_class(cb)
        probe_info["callback"] = fn  # Cache resolved function
        fn_ret = fn(pt_regs)
        if isinstance(fn_ret, Iterator):
            fn_ret = yield from fn(pt_regs)

        new = pt_regs.to_bytes()
        if original_bytes != new:
            plugins.mem.write_bytes_panda(cpu, ptregs_addr, new)
        return fn_ret

    def _kprobe_enter_handler(self, cpu: Any) -> None:
        """
        Entry handler for kprobes.
        """
        self._kprobe_event(cpu, True)

    def _kprobe_return_handler(self, cpu: Any) -> None:
        """
        Return handler for kprobes.
        """
        self._kprobe_event(cpu, False)

    @plugins.live_image.fs_init
    def on_fs_init(self):
        self.portal.queue_interrupt("kprobes")
        self.fs_init = True

    def _kprobe_interrupt_handler(self) -> bool:
        """
        Handle interrupts for pending kprobe registrations.
        Processes one pending kprobe registration per call.
        Returns True if more kprobes are pending, False otherwise.
        """
        if not self._pending_kprobes:
            return False

        pending_kprobes = self._pending_kprobes[:]

        while pending_kprobes:
            kprobe_config, func = pending_kprobes.pop(0)
            symbol = kprobe_config["symbol"]
            offset = kprobe_config["offset"]
            callback = kprobe_config["callback"]
            options = kprobe_config["options"]

            is_method = hasattr(func, '__self__') or (
                hasattr(func, '__qualname__') and '.' in func.__qualname__)
            qualname = getattr(func, '__qualname__', None)

            probe_id = yield from self._register_kprobe(
                symbol,
                offset,
                process_filter=options.get('process_filter'),
                on_enter=options.get('on_enter', True),
                on_return=options.get('on_return', False),
                pid_filter=options.get('pid_filter')
            )

            if probe_id:
                self.probes[probe_id] = {
                    "callback": func,
                    "is_method": is_method,
                    "qualname": qualname,
                }
                self.probe_info[probe_id] = {
                    "symbol": symbol,
                    "offset": offset,
                    "callback": callback,
                    "options": options
                }
                # Track function to probe_id mappings
                self._func_to_probe_id[func] = probe_id
                if hasattr(func, "__name__"):
                    self._name_to_probe_id[func.__name__] = probe_id
                self.logger.debug(
                    f"Successfully registered kprobe ID {probe_id} for {symbol}+{offset}")
            else:
                self.logger.error(
                    f"Failed to register kprobe for {symbol}+{offset}")

        return False

    def _register_kprobe(
        self,
        symbol: str,
        offset: int,
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None
    ) -> Iterator[Optional[int]]:
        """
        Register a kprobe with the kernel using the portal.

        Parameters
        ----------
        symbol : str
            Kernel symbol name.
        offset : int
            Offset in the function to place the probe (usually 0).
        process_filter : Optional[str]
            Process name filter.
        on_enter : bool
            Trigger on function entry.
        on_return : bool
            Trigger on function return.
        pid_filter : Optional[int]
            PID filter.

        Yields
        ------
        Optional[int]
            Probe ID if registration succeeds, None otherwise.
        """
        # Determine the probe type based on entry/return flags
        if on_enter and on_return:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_BOTH
        elif on_enter:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_ENTRY
        elif on_return:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_RETURN
        else:
            self.logger.error(
                "Invalid probe type: at least one of on_enter or on_return must be True")
            return None

        # Set the PID filter, defaulting to 0xffffffff for "any PID"
        filter_pid = pid_filter if pid_filter is not None else 0xffffffff

        # Debug output before registration
        self.logger.debug(f"Registering kprobe: symbol={symbol}, offset={offset:#x}, type={probe_type}, "
                          f"filter_comm={process_filter}, filter_pid={filter_pid:#x}")

        # Create a registration struct that matches the C-side struct kprobe_registration
        reg = plugins.kffi.new("kprobe_registration")

        # Fill in the symbol field (first 256 bytes, null-terminated)
        sym_bytes = symbol.encode('latin-1')
        # Ensure we leave room for null terminator
        for i, b in enumerate(sym_bytes[:255]):
            reg.symbol[i] = b
        reg.symbol[min(len(sym_bytes), 255)] = 0  # Ensure null termination

        # Set the offset, type and pid
        reg.offset = offset
        reg.type = probe_type
        reg.pid = filter_pid

        # Fill in the comm field (process filter) if provided - TASK_COMM_LEN is 16
        if process_filter:
            comm_bytes = process_filter.encode('latin-1')
            # Leave room for null terminator (16-1)
            for i, b in enumerate(comm_bytes[:15]):
                reg.comm[i] = b
            reg.comm[min(len(comm_bytes), 15)] = 0
        else:
            reg.comm[0] = 0  # Empty comm filter (match any process)

        # Serialize the registration struct to bytes
        reg_bytes = reg.to_bytes()

        # Send the registration to the kernel via portal
        result = yield PortalCmd("register_kprobe", offset, len(reg_bytes), None, reg_bytes)

        if result is None:
            self.logger.error(
                f"Failed to register kprobe at {symbol}+{offset:#x}")
            return None

        probe_id = result
        self.logger.debug(
            f"Kprobe successfully registered with ID: {probe_id}")
        return probe_id

    def _unregister_kprobe(self, probe_id: int) -> Iterator[bool]:
        """
        Unregister a kprobe by its ID.
        """
        self.logger.debug(f"unregister_kprobe called: probe_id={probe_id}")
        result = yield PortalCmd("unregister_kprobe", probe_id, 0)
        if result is True:
            if probe_id in self.probes:
                del self.probes[probe_id]
            self.logger.debug(f"Kprobe {probe_id} successfully unregistered")
            return True
        else:
            self.logger.error(f"Failed to unregister kprobe {probe_id}")
            return False

    def kprobe(
        self,
        symbol: str,
        offset: int = 0,
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None
    ) -> Callable[[Callable], Callable]:
        """
        Decorator to register a kprobe at the specified symbol and offset.

        Parameters
        ----------
        symbol : str
            Kernel symbol name.
        offset : int
            Offset in the function (default: 0).
        process_filter : Optional[str]
            Process name to filter events.
        on_enter : bool
            Trigger on function entry (default: True).
        on_return : bool
            Trigger on function return (default: False).
        pid_filter : Optional[int]
            PID to filter events for a specific process.

        Returns
        -------
        Callable[[Callable], Callable]
            Decorator function that registers the kprobe.
        """
        def _register_decorator(kprobe_configs):
            def decorator(func):
                is_method = hasattr(func, '__self__') or (
                    hasattr(func, '__qualname__') and '.' in func.__qualname__)
                qualname = getattr(func, '__qualname__', None)
                for kprobe_config in kprobe_configs:
                    kprobe_config["callback"] = func
                    kprobe_config["is_method"] = is_method
                    kprobe_config["qualname"] = qualname
                    self._pending_kprobes.append((kprobe_config, func))
                if self.fs_init:
                    self.portal.queue_interrupt("kprobes")
                return func
            return decorator

        options = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter
        }

        kprobe_configs = [{
            "symbol": symbol,
            "offset": offset,
            "options": options.copy(),
        }]
        return _register_decorator(kprobe_configs)

    def kretprobe(
        self,
        symbol: str,
        process_filter: Optional[str] = None,
        on_enter: bool = False,
        on_return: bool = True,
        pid_filter: Optional[int] = None
    ) -> Callable[[Callable], Callable]:
        """
        Decorator to register a return kprobe (kretprobe).

        Equivalent to `kprobe()` with `on_enter=False, on_return=True`.
        """
        return self.kprobe(symbol, 0, process_filter,
                           on_enter, on_return, pid_filter)

    def unregister(self, probe_id: int) -> None:
        """
        Unregister a kprobe by its ID.
        """
        self._unregister_kprobe(probe_id)
