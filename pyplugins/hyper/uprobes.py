from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
import functools
import struct
from typing import Dict, List, Any, Optional, Union, Tuple
from hyper.consts import *

# Uprobe type constants
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
        
        # Map probe_id -> uprobe details
        self.probes = {}
        
        # Pending uprobes to be registered
        self._pending_uprobes = []
        
        # Get portal plugin
        self.portal = plugins.portal
        
        # Register with portal's interrupt handler system
        self.portal.register_interrupt_handler("uprobes", self._uprobe_interrupt_handler)
        
        # Register callbacks for uprobe enter/return events
        self.panda.hypercall(IGLOO_HYP_UPROBE_ENTER)(self._uprobe_enter_handler)
        self.panda.hypercall(IGLOO_HYP_UPROBE_RETURN)(self._uprobe_return_handler)
    
    def _uprobe_enter_handler(self, cpu, uprobe_id, task):
        """Handler for uprobe entry events from the kernel"""
        if uprobe_id in self.probes:
            probe = self.probes[uprobe_id]
            callback = probe["callback"]
            try:
                callback(cpu, uprobe_id, task, is_entry=True)
            except Exception as e:
                self.logger.error(f"Error in uprobe enter handler: {e}")
    
    def _uprobe_return_handler(self, cpu, uprobe_id, task):
        """Handler for uprobe return events from the kernel"""
        if uprobe_id in self.probes:
            probe = self.probes[uprobe_id]
            callback = probe["callback"]
            try:
                callback(cpu, uprobe_id, task, is_entry=False)
            except Exception as e:
                self.logger.error(f"Error in uprobe return handler: {e}")
    
    @plugins.portal.wrap
    def _uprobe_interrupt_handler(self):
        """
        Handle interrupts from the portal for uprobe registrations.
        Processes one pending uprobe registration from the queue.
        
        Returns:
            bool: True if more probes are pending, False otherwise
        """
        if not self._pending_uprobes:
            self.logger.debug("No pending uprobes to register")
            return False
            
        # Take one item from the queue
        uprobe_config = self._pending_uprobes.pop(0)
        path = uprobe_config["path"]
        offset = uprobe_config["offset"]
        callback = uprobe_config["callback"]
        options = uprobe_config["options"]
        
        self.logger.debug(f"Registering uprobe for {path}:{offset}")
        
        # Register the uprobe
        probe_id = yield from self._register_uprobe(
            path, 
            offset, 
            process_filter=options.get('process_filter'),
            on_enter=options.get('on_enter', True),
            on_return=options.get('on_return', False),
            pid_filter=options.get('pid_filter')
        )
        
        if probe_id:
            # Store uprobe details for later use
            self.probes[probe_id] = {
                "path": path,
                "offset": offset,
                "callback": callback,
                "options": options
            }
            self.logger.info(f"Successfully registered uprobe ID {probe_id} for {path}:{offset}")
        else:
            self.logger.error(f"Failed to register uprobe for {path}:{offset}")
        
        # Return True if there are more items to process
        return len(self._pending_uprobes) > 0
    
    @plugins.portal.wrap
    def _register_uprobe(self, path, offset, process_filter=None, on_enter=True, on_return=False, pid_filter=None):
        """
        Register a user probe (uprobe) at a specific file path and offset.
        
        Args:
            path: Path to the executable or library file
            offset: Offset in the file where the probe should be placed
            process_filter: Optional process name to filter events (None = all processes)
            on_enter: Whether to trigger on function entry (True by default)
            on_return: Whether to trigger on function return (False by default)
            pid_filter: Optional PID to filter events for a specific process
            
        Returns:
            Probe ID that can be used to unregister the probe
        """
        if on_enter and on_return:
            probe_type = UPROBE_TYPE_BOTH
        elif on_enter:
            probe_type = UPROBE_TYPE_ENTRY
        elif on_return:
            probe_type = UPROBE_TYPE_RETURN
        else:
            raise ValueError("At least one of on_enter or on_return must be True")
            
        self.logger.debug(f"register_uprobe called: path={path}, offset={offset}, filter={process_filter}, type={probe_type}, pid={pid_filter}")
        
        # Format the data in the required layout expected by the kernel
        # Format: path\0[process_filter]\0[probe_type][pid_filter]
        data = path.encode('latin-1') + b'\0'
        
        if process_filter is not None:
            data += process_filter.encode('latin-1')
        data += b'\0'  # Add null terminator after filter (even if empty)

        # Add probe type as an integer
        data += struct.pack("<Q", probe_type)
        
        # Add PID filter if specified, otherwise use CURRENT_PID_NUM (0xffffffff)
        if pid_filter is not None:
            data += struct.pack("<Q", pid_filter)
        else:
            data += struct.pack("<Q", 0xffffffff)  # Match any process
        
        # Register the uprobe
        result = yield ("register_uprobe", offset, data)
        
        if result is None:
            self.logger.error(f"Failed to register uprobe at {path}:{offset}")
            return None
            
        # The kernel returns the probe ID
        probe_id = result
        self.logger.debug(f"Uprobe registered with ID: {probe_id}")
        return probe_id

    @plugins.portal.wrap
    def _unregister_uprobe(self, probe_id):
        """
        Unregister a previously registered uprobe.

        Args:
            probe_id: ID of the probe returned from register_uprobe

        Returns:
            True if successfully unregistered, False otherwise
        """
        self.logger.debug(f"unregister_uprobe called: probe_id={probe_id}")

        result = yield ("unregister_uprobe", probe_id)

        if result is True:
            if probe_id in self.probes:
                del self.probes[probe_id]
            self.logger.debug(f"Uprobe {probe_id} successfully unregistered")
            return True
        else:
            self.logger.error(f"Failed to unregister uprobe {probe_id}")
            return False
    
    def uprobe(self, path, symbol: Union[str, int], process_filter=None, 
              on_enter=True, on_return=False, pid_filter=None):
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
        # Determine the offset based on symbol
        offset = symbol if isinstance(symbol, int) else 0  # TODO: Symbol lookup
        
        # Create options dictionary
        options = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter
        }
        
        def decorator(func):
            # Queue this uprobe for registration
            uprobe_config = {
                "path": path,
                "offset": offset,
                "callback": func,
                "options": options
            }
            
            # Add to pending uprobes and queue interrupt
            self._pending_uprobes.append(uprobe_config)
            self.portal.queue_interrupt("uprobes")
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Just call the original function - actual uprobe logic is in handlers
                return func(*args, **kwargs)
                
            return wrapper
        
        return decorator
