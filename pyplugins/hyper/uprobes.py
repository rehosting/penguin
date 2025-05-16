from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
import functools
import struct
from typing import Dict, List, Any, Optional, Union, Tuple
from hyper.consts import *

UPROBE_TYPE_ENTRY = 1
UPROBE_TYPE_RETURN = 2
UPROBE_TYPE_BOTH = 3

class Uprobes(PyPlugin):
    """
    Plugin that provides an interface for registering user-space probes (uprobes).
    Uses the portal's interrupt mechanism for registration.
    """
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.uprobes")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.probes: Dict[int, Dict[str, Any]] = {}
        self.probe_info = {}
        self._pending_uprobes: List[Dict[str, Any]] = []
        self.portal = plugins.portal
        self.portal.register_interrupt_handler("uprobes", self._uprobe_interrupt_handler)
        self.first_interrupt = True
        self.panda.hypercall(IGLOO_HYP_UPROBE_ENTER)(self._uprobe_enter_handler)
        self.panda.hypercall(IGLOO_HYP_UPROBE_RETURN)(self._uprobe_return_handler)
        self.saved_regs_info = {}

    def _get_portal_event(self, cpu, sequence, arg):
        sri = self.saved_regs_info.get(cpu, None)
        if sri:
            id_, saved_sc, saved_sequence = sri
            if saved_sequence == sequence:
                return id_, saved_sc
        # save the pt_regs

        # possible issue with registring multiple cpu _memregions
        sce = plugins.kffi.read_type_panda(cpu, arg, "portal_event")
        id_ = sce.id
        pt_regs= plugins.kffi.read_type_panda(cpu, sce.regs.address, "pt_regs")
        self.saved_regs_info[cpu] = (id_, pt_regs, sequence)
        return sce.id, pt_regs

    
    def _uprobe_event(self, cpu, is_enter):
        sequence = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")

        id_, pe = self._get_portal_event(cpu, sequence, arg)

        if id_ not in self.probes:
            self.logger.error(f"Uprobe ID {id_} not found in registered probes")
            return
        self.probes[id_](pe)


    def _uprobe_enter_handler(self, cpu):
        self._uprobe_event(cpu, True)

    def _uprobe_return_handler(self, cpu):
        self._uprobe_event(cpu, False)

    def _uprobe_interrupt_handler(self):
        """
        We have to skip the first interrupt because there isn't really a filesystem
        yet, and we can't register uprobes until we have a filesystem.
        """
        if self.first_interrupt:
            self.first_interrupt = False
            self.portal.queue_interrupt("uprobes")
            return True
        """
        Handle interrupts for pending uprobe registrations.
        Processes one pending uprobe registration per call.
        Returns True if more uprobes are pending, False otherwise.
        Always yields at least once to be a generator.
        """
        if not self._pending_uprobes:
            return False

        pending_uprobes = self._pending_uprobes[:]

        while pending_uprobes:
            uprobe_config, func = pending_uprobes.pop(0)
            path = uprobe_config["path"]
            offset = uprobe_config["offset"]
            callback = uprobe_config["callback"]
            options = uprobe_config["options"]
            self.logger.debug(f"Registering uprobe for {path}:{offset}")
            probe_id = yield from self._register_uprobe(
                path,
                offset,
                process_filter=options.get('process_filter'),
                on_enter=options.get('on_enter', True),
                on_return=options.get('on_return', False),
                pid_filter=options.get('pid_filter')
            )
            if probe_id:
                self.probes[probe_id] = func 
                self.probe_info[probe_id] = {
                    "path": path,
                    "offset": offset,
                    "callback": callback,
                    "options": options
                }
                self.logger.info(f"Successfully registered uprobe ID {probe_id} for {path}:{offset}")
            else:
                self.logger.error(f"Failed to register uprobe for {path}:{offset}")
            # Only process one per interrupt
            break
        return len(self._pending_uprobes) > 0

    def _register_uprobe(self, path, offset, process_filter=None, on_enter=True, on_return=False, pid_filter=None):
        # Match the kernel's handle_op_register_uprobe: send path, filter_comm, probe_type, filter_pid as a packed buffer
        probe_type = UPROBE_TYPE_BOTH if (on_enter and on_return) else (UPROBE_TYPE_ENTRY if on_enter else UPROBE_TYPE_RETURN)
        filter_pid = pid_filter if pid_filter is not None else 0xffffffff
        # Data format: path\0[process_filter]\0[probe_type][pid_filter]
        buf = bytearray()
        buf += path.encode('latin-1') + b'\0'
        if process_filter:
            buf += process_filter.encode('latin-1') + b'\0'
        else:
            buf += b'\0'
        # Now append probe_type and filter_pid as 8-byte little-endian unsigned longs
        buf += probe_type.to_bytes(8, 'little')
        buf += filter_pid.to_bytes(8, 'little')
        result = yield ("uprobe_reg", offset, bytes(buf))
        if result is None:
            self.logger.error(f"Failed to register uprobe at {path}:{offset}")
            return None
        probe_id = result
        self.logger.debug(f"Uprobe registered with ID: {probe_id}")
        return probe_id

    def _unregister_uprobe(self, probe_id):
        self.logger.debug(f"unregister_uprobe called: probe_id={probe_id}")
        result = yield ("uprobe_unreg", probe_id)
        if result is True:
            if probe_id in self.probes:
                del self.probes[probe_id]
            self.logger.debug(f"Uprobe {probe_id} successfully unregistered")
            return True
        else:
            self.logger.error(f"Failed to unregister uprobe {probe_id}")
            return False

    def uprobe(self, path:str, symbol: Union[str, int], process_filter=None, on_enter=True, on_return=False, pid_filter=None):
        """
        Decorator to register a uprobe at the specified path and symbol/offset.
        Args:
            path: Path to the executable or library file
            symbol: Symbol name (string) or offset (integer) in the file
            process_filter: Optional process name to filter events
            on_enter: Whether to trigger on function entry (default: True)
            on_return: Whether to trigger on function return (default: False)
            pid_filter: Optional PID to filter events for a specific process
        Returns:
            Decorator function that registers the uprobe
        """
        offset = symbol if isinstance(symbol, int) else 0  # TODO: Symbol lookup
        options = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter
        }
        def decorator(func):
            uprobe_config = {
                "path": path,
                "offset": offset,
                "callback": func,
                "options": options
            }
            self._pending_uprobes.append((uprobe_config, func))
            self.portal.queue_interrupt("uprobes")
            return func
        return decorator
    
    def uretprobe(self, path, symbol: Union[str, int], process_filter=None, on_enter=False, on_return=True, pid_filter=None):
        self.uprobe(path, symbol, process_filter, on_enter, on_return, pid_filter)
    
    def unregister(self, probe_id):
        """
        Unregister a uprobe by its ID.
        Args:
            probe_id: ID of the uprobe to unregister
        """
        self._unregister_uprobe(probe_id)
