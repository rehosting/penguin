import os
import lzma
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from typing import Dict, List, Any, Union
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import portal_type
from wrappers.ptregs_wrap import get_pt_regs_wrapper
try:
    import cxxfilt  # For C++ symbol demangling
    HAVE_CXXFILT = True
except ImportError:
    HAVE_CXXFILT = False


class Uprobes(PyPlugin):
    """
    Plugin that provides an interface for registering user-space probes (uprobes).
    Uses the portal's interrupt mechanism for registration.
    """

    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.projdir = self.get_arg("proj_dir")
        self.logger = getColoredLogger("plugins.uprobes")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.libsymbols = os.path.join(
            self.projdir, "static", "LibrarySymbols.json.xz")
        self.probes: Dict[int, Dict[str, Any]] = {}
        self.probe_info = {}
        self._pending_uprobes: List[Dict[str, Any]] = []
        self.portal = plugins.portal
        self.portal.register_interrupt_handler(
            "uprobes", self._uprobe_interrupt_handler)
        self.first_interrupt = True
        self.panda.hypercall(iconsts.IGLOO_HYP_UPROBE_ENTER)(
            self._uprobe_enter_handler)
        self.panda.hypercall(iconsts.IGLOO_HYP_UPROBE_RETURN)(
            self._uprobe_return_handler)
        self.saved_regs_info = {}
        # Add symbol cache for lazy loading
        self._symbols_cache = None
        self._symbols_loaded = False

    def _load_symbols(self):
        """Lazily load symbols from LibrarySymbols.yaml if it exists"""
        if self._symbols_loaded:
            return self._symbols_cache

        # Set flag to indicate we attempted loading (even if file doesn't exist)
        self._symbols_loaded = True
        self._symbols_cache = {"symbols": {}}

        # Look for the symbols file in the project directory
        symbols_path = self.libsymbols

        if os.path.exists(symbols_path):
            try:
                with lzma.open(symbols_path, 'rt', encoding='utf-8') as f:
                    import ujson as json
                    sym = json.load(f)
                    if "symbols" in sym:
                        self._symbols_cache = sym["symbols"]
                    else:
                        raise ValueError(
                            f"Invalid symbols file format: {symbols_path}")
                self.logger.info(f"Loaded library symbols from {symbols_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load library symbols: {e}")
        else:
            self.logger.debug(
                f"Library symbols file not found at {symbols_path}")

        return self._symbols_cache

    def _lookup_symbol(self, path, symbol):
        """Look up a symbol's offset in the specified library"""
        symbols_data = self._load_symbols()
        if not symbols_data:
            return None, None

        # Handle wildcard paths containing asterisks
        if '*' in path:
            self.logger.debug(
                f"Looking up symbol '{symbol}' in wildcard path '{path}'")
            # Remove asterisks for substring matching
            pattern = path.replace('*', '')
            matches = []

            # Find all libraries that match our wildcard pattern
            for lib_path, lib_symbols in symbols_data.items():
                lib_basename = os.path.basename(lib_path)
                # If the pattern is found in the path
                if pattern in lib_path or pattern in lib_basename:
                    if symbol in lib_symbols:
                        offset = lib_symbols[symbol]
                        matches.append((lib_path, offset))
                        self.logger.debug(
                            f"Found symbol '{symbol}' at offset {offset} in '{lib_path}' (wildcard match)")

            # Return the first match if any were found
            if matches:
                self.logger.info(
                    f"Using '{matches[0][0]}' for wildcard path '{path}'")
                return matches[0]  # Return tuple of (path, offset)

        # Normalize path to handle absolute/relative paths
        normalized_path = os.path.basename(path)

        # Try to demangle the symbol if it looks like a C++ mangled name
        demangled_symbol = None
        if HAVE_CXXFILT and symbol.startswith('_Z'):
            try:
                demangled_symbol = cxxfilt.demangle(symbol)
            except Exception:
                pass

        # First, try direct path matches
        for lib_path, lib_symbols in symbols_data.items():
            # Check for exact path or basename match
            if path == lib_path or normalized_path == os.path.basename(lib_path):
                # Try exact symbol match
                if symbol in lib_symbols:
                    return lib_path, lib_symbols[symbol]

                # If we have a demangled symbol, try that
                if demangled_symbol:
                    for lib_sym, offset in lib_symbols.items():
                        try:
                            if HAVE_CXXFILT and lib_sym.startswith('_Z'):
                                demangled_lib_sym = cxxfilt.demangle(lib_sym)
                                if demangled_lib_sym == demangled_symbol:
                                    return lib_path, offset
                        except Exception:
                            pass

        # Next, try partial path matches
        for lib_path, lib_symbols in symbols_data.items():
            lib_basename = os.path.basename(lib_path)

            # Check for partial matches in library names
            if (normalized_path in lib_basename or lib_basename in normalized_path or
                    (normalized_path.rstrip('-') and lib_basename.startswith(normalized_path.rstrip('-')))):

                # Try exact symbol match
                if symbol in lib_symbols:
                    return lib_path, lib_symbols[symbol]

                # Try demangled match
                if demangled_symbol:
                    for lib_sym, offset in lib_symbols.items():
                        try:
                            if HAVE_CXXFILT and lib_sym.startswith('_Z'):
                                demangled_lib_sym = cxxfilt.demangle(lib_sym)
                                if demangled_lib_sym == demangled_symbol:
                                    return lib_path, offset
                        except Exception:
                            pass

        return None, None

    def _get_portal_event(self, cpu, sequence, arg):
        sri = self.saved_regs_info.get(cpu, None)
        if sri:
            saved_sequence, id_, pt_regs, ptregs_addr, original_bytes = sri
            if saved_sequence == sequence:
                return id_, pt_regs, ptregs_addr, original_bytes
        # save the pt_regs

        # possible issue with registring multiple cpu _memregions
        sce = plugins.kffi.read_type_panda(cpu, arg, "portal_event")
        id_ = sce.id
        ptregs_addr = sce.regs.address
        pt_regs_raw = plugins.kffi.read_type_panda(cpu, ptregs_addr, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)
        original_bytes = pt_regs.to_bytes()[:]
        self.saved_regs_info[cpu] = (
            sequence, id_, pt_regs, ptregs_addr, original_bytes)
        return id_, pt_regs, ptregs_addr, original_bytes

    def _uprobe_event(self, cpu, is_enter):
        sequence = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")

        id_, pt_regs, ptregs_addr, original_bytes = self._get_portal_event(
            cpu, sequence, arg)

        if id_ not in self.probes:
            self.logger.error(
                f"Uprobe ID {id_} not found in registered probes")
            return
        self.probes[id_](pt_regs)

        new = pt_regs.to_bytes()
        if original_bytes != new:
            self.panda.virtual_memory_write(cpu, ptregs_addr, new)

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
            symbol = uprobe_config.get("symbol", "[offset]") or "[offset]"
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
                self.logger.info(
                    f"Successfully registered uprobe ID {probe_id} for {path}:{offset} ({symbol})")
            else:
                self.logger.error(
                    f"Failed to register uprobe for {path}:{offset} ({symbol})")

    def _register_uprobe(self, path, offset, process_filter=None, on_enter=True, on_return=False, pid_filter=None):
        """
        Register a uprobe with the kernel using the portal.

        This follows the same approach as register_syscall_hook, using a KFfi struct
        that matches the C-side struct uprobe_registration in portal_uprobe.c.
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
        self.logger.debug(f"Registering uprobe: path={path}, offset={offset:#x}, type={probe_type}, "
                          f"filter_comm={process_filter}, filter_pid={filter_pid:#x}")

        # Create a registration struct that matches the C-side struct uprobe_registration
        reg = plugins.kffi.new("uprobe_registration")

        # Fill in the path field (first 256 bytes, null-terminated)
        path_bytes = path.encode('latin-1')
        # Ensure we leave room for null terminator
        for i, b in enumerate(path_bytes[:255]):
            reg.path[i] = b
        reg.path[min(len(path_bytes), 255)] = 0  # Ensure null termination

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
        result = yield ("uprobe_reg", offset, reg_bytes)

        if result is None:
            self.logger.error(
                f"Failed to register uprobe at {path}:{offset:#x}")
            return None

        probe_id = result
        self.logger.debug(
            f"Uprobe successfully registered with ID: {probe_id}")
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

    def uprobe(self, path: str, symbol: Union[str, int], process_filter=None, on_enter=True, on_return=False, pid_filter=None, fail_register_ok=False):
        """
        Decorator to register a uprobe at the specified path and symbol/offset.
        Args:
            path: Path to the executable or library file (can include * wildcards)
            symbol: Symbol name (string) or offset (integer) in the file
            process_filter: Optional process name to filter events
            on_enter: Whether to trigger on function entry (default: True)
            on_return: Whether to trigger on function return (default: False)
            pid_filter: Optional PID to filter events for a specific process
            fail_register_ok: If True, silently return if symbol not found
        Returns:
            Decorator function that registers the uprobe
        """
        if isinstance(symbol, int):
            offset = symbol
            symbol_name = None
            resolved_path = path
        else:
            # Look up the symbol in the library
            symbol_name = symbol
            resolved_path, offset = self._lookup_symbol(path, symbol)
            if offset is None:
                if fail_register_ok:
                    # Return None instead of the decorator to signal no registration
                    return None
                self.logger.warning(
                    f"Symbol '{symbol}' not found in '{path}'. Using offset 0.")
                offset = 0
                resolved_path = path  # Default to original path if resolution failed

        options = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter
        }

        def decorator(func):
            uprobe_config = {
                "path": resolved_path,  # Use resolved path instead of original
                "offset": offset,
                "callback": func,
                "options": options,
                "symbol": symbol_name  # Store the symbol name for reference
            }
            self._pending_uprobes.append((uprobe_config, func))
            self.portal.queue_interrupt("uprobes")
            return func
        return decorator

    def uretprobe(self, path, symbol: Union[str, int], process_filter=None, on_enter=False, on_return=True, pid_filter=None, fail_register_ok=False):
        return self.uprobe(path, symbol, process_filter, on_enter, on_return, pid_filter, fail_register_ok)

    def unregister(self, probe_id):
        """
        Unregister a uprobe by its ID.
        Args:
            probe_id: ID of the uprobe to unregister
        """
        self._unregister_uprobe(probe_id)
