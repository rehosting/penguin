"""
.. include:: /docs/uprobes.md
"""

import os
import lzma
from penguin import Plugin, plugins
from typing import Dict, List, Any, Union, Callable, Optional, Iterator
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import portal_type
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper
try:
    import cxxfilt  # For C++ symbol demangling
    HAVE_CXXFILT = True
except ImportError:
    HAVE_CXXFILT = False


class Uprobes(Plugin):
    """
    ## Uprobes Plugin

    Provides an interface for registering and handling user-space probes (uprobes) in guest processes.
    Supports flexible filtering, symbol lookup, and coroutine-based event handling.

    **Attributes:**
    - `probes` (`Dict[int, Dict[str, Any]]`): Registered probe callbacks by probe ID.
    - `probe_info` (`Dict[int, Dict[str, Any]]`): Metadata for each registered probe.
    - `_pending_uprobes` (`List[Dict[str, Any]]`): Queue of uprobes pending registration.
    - `_func_to_probe_id` (`Dict[Callable, int]`): Maps callback functions to probe IDs.
    - `_name_to_probe_id` (`Dict[str, int]`): Maps function names to probe IDs.
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.projdir = self.get_arg("proj_dir")
        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel("DEBUG")
        self.libsymbols = os.path.join(
            self.projdir, "static", "LibrarySymbols.json.xz")
        self.probes: Dict[int, Dict[str, Any]] = {}
        self.probe_info = {}
        self._pending_uprobes: List[Dict[str, Any]] = []
        self._func_to_probe_id = {}  # Maps function to probe_id
        self._name_to_probe_id = {}  # Maps function name to probe_id
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
        self._uprobe_event = self.plugins.portal.wrap(self._uprobe_event)

    def _load_symbols(self) -> Dict[str, Any]:
        """
        ### Lazily load symbols from the compressed symbols database.

        Loads and caches the symbols from `LibrarySymbols.json.xz` for symbol lookup.

        **Returns:**
        - `Dict[str, Any]`: Dictionary mapping library paths to symbol offsets.
        """
        if self._symbols_loaded:
            return self._symbols_cache

        # Set flag to indicate we attempted loading (even if file doesn't
        # exist)
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

    def _lookup_symbol(
            self, path: str, symbol: str) -> (Optional[str], Optional[int]):
        """
        ### Look up a symbol's offset in the specified library.

        Supports wildcards and demangling for C++ symbols.

        **Args:**
        - `path` (`str`): Path or pattern to the library.
        - `symbol` (`str`): Symbol name to look up.

        **Returns:**
        - `Optional[str]`: Resolved library path.
        - `Optional[int]`: Offset of the symbol in the library.
        """
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
            if path == lib_path or normalized_path == os.path.basename(
                    lib_path):
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

    def _uprobe_event(self, cpu: Any, is_enter: bool) -> Any:
        """
        ### Handle a uprobe event from the portal.

        Invokes the registered callback for the probe, passing a `pt_regs` wrapper.

        **Args:**
        - `cpu` (`Any`): CPU context.
        - `is_enter` (`bool`): True if entry probe, False if return probe.

        **Returns:**
        - Any: Return value from the callback, if any.
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
                f"Uprobe ID {sce.id} not found in registered probes")
            return

        probe_info = self.probes[sce.id]
        fn = probe_info["callback"]
        is_method = probe_info.get("is_method", False)
        qualname = probe_info.get("qualname", None)

        # Handle method callbacks (resolve class instance from plugins)
        if is_method and qualname and '.' in qualname:
            class_name = qualname.split('.')[0]
            method_name = qualname.split('.')[-1]
            try:
                instance = getattr(plugins, class_name)
                if instance and hasattr(instance, method_name):
                    bound_method = getattr(instance, method_name)
                    fn_ret = bound_method(pt_regs)
                    if isinstance(fn_ret, Iterator):
                        fn_ret = yield from bound_method(pt_regs)
                else:
                    self.logger.error(
                        f"Could not find method {method_name} on instance for {qualname}")
                    return
            except AttributeError:
                self.logger.error(
                    f"Could not find instance for class {class_name} from {qualname}")
                return
        else:
            fn_ret = fn(pt_regs)
            if isinstance(fn_ret, Iterator):
                fn_ret = yield from fn(pt_regs)

        new = pt_regs.to_bytes()
        if original_bytes != new:
            self.panda.virtual_memory_write(cpu, ptregs_addr, new)
        return fn_ret

    def _uprobe_enter_handler(self, cpu: Any) -> None:
        """
        ### Entry handler for uprobes.

        **Args:**
        - `cpu` (`Any`): CPU context.

        **Returns:** None
        """
        self._uprobe_event(cpu, True)

    def _uprobe_return_handler(self, cpu: Any) -> None:
        """
        ### Return handler for uprobes.

        **Args:**
        - `cpu` (`Any`): CPU context.

        **Returns:** None
        """
        self._uprobe_event(cpu, False)

    def _uprobe_interrupt_handler(self) -> bool:
        """
        ### Handle interrupts for pending uprobe registrations.

        Processes one pending uprobe registration per call.
        Returns True if more uprobes are pending, False otherwise.

        **Returns:**
        - `bool`: True if more uprobes are pending, False otherwise.
        """
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
            is_method = hasattr(func, '__self__') or (
                hasattr(func, '__qualname__') and '.' in func.__qualname__)
            qualname = getattr(func, '__qualname__', None)
            probe_id = yield from self._register_uprobe(
                path,
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
                    "path": path,
                    "offset": offset,
                    "callback": callback,
                    "options": options
                }
                # Track function to probe_id mappings
                self._func_to_probe_id[func] = probe_id
                if hasattr(func, "__name__"):
                    self._name_to_probe_id[func.__name__] = probe_id
                self.logger.debug(
                    f"Successfully registered uprobe ID {probe_id} for {path}:{offset} ({symbol})")
            else:
                self.logger.error(
                    f"Failed to register uprobe for {path}:{offset} ({symbol})")

    def _register_uprobe(
        self,
        path: str,
        offset: int,
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None
    ) -> Iterator[Optional[int]]:
        """
        ### Register a uprobe with the kernel using the portal.

        **Args:**
        - `path` (`str`): Path to the executable or library file.
        - `offset` (`int`): Offset in the file to place the probe.
        - `process_filter` (`Optional[str]`): Process name filter.
        - `on_enter` (`bool`): Trigger on function entry.
        - `on_return` (`bool`): Trigger on function return.
        - `pid_filter` (`Optional[int]`): PID filter.

        **Yields:**
        - `Optional[int]`: Probe ID if registration succeeds, None otherwise.
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

        # Create a registration struct that matches the C-side struct
        # uprobe_registration
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

        # Fill in the comm field (process filter) if provided - TASK_COMM_LEN
        # is 16
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
        result = yield PortalCmd("register_uprobe", offset, len(reg_bytes), None, reg_bytes)

        if result is None:
            self.logger.error(
                f"Failed to register uprobe at {path}:{offset:#x}")
            return None

        probe_id = result
        self.logger.debug(
            f"Uprobe successfully registered with ID: {probe_id}")
        return probe_id

    def _unregister_uprobe(self, probe_id: int) -> Iterator[bool]:
        """
        ### Unregister a uprobe by its ID.

        **Args:**
        - `probe_id` (`int`): ID of the uprobe to unregister.

        **Yields:**
        - `bool`: True if successfully unregistered, False otherwise.
        """
        self.logger.debug(f"unregister_uprobe called: probe_id={probe_id}")
        result = yield PortalCmd("unregister_uprobe", probe_id, 0)
        if result is True:
            if probe_id in self.probes:
                del self.probes[probe_id]
            self.logger.debug(f"Uprobe {probe_id} successfully unregistered")
            return True
        else:
            self.logger.error(f"Failed to unregister uprobe {probe_id}")
            return False

    def uprobe(
        self,
        path: Optional[str],
        symbol: Union[str, int],
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None,
        fail_register_ok: bool = False
    ) -> Callable[[Callable], Callable]:
        """
        ### Decorator to register a uprobe at the specified path and symbol/offset.

        **Args:**
        - `path` (`Optional[str]`): Path to the executable or library file (can include wildcards), or None to match all libraries containing the symbol.
        - `symbol` (`Union[str, int]`): Symbol name (string) or offset (integer) in the file.
        - `process_filter` (`Optional[str]`): Process name to filter events.
        - `on_enter` (`bool`): Trigger on function entry (default: True).
        - `on_return` (`bool`): Trigger on function return (default: False).
        - `pid_filter` (`Optional[int]`): PID to filter events for a specific process.
        - `fail_register_ok` (`bool`): If True, silently return if symbol not found.

        **Returns:**
        - `Callable[[Callable], Callable]`: Decorator function that registers the uprobe.
        """
        def _register_decorator(uprobe_configs):
            def decorator(func):
                is_method = hasattr(func, '__self__') or (
                    hasattr(func, '__qualname__') and '.' in func.__qualname__)
                qualname = getattr(func, '__qualname__', None)
                for uprobe_config in uprobe_configs:
                    uprobe_config["callback"] = func
                    uprobe_config["is_method"] = is_method
                    uprobe_config["qualname"] = qualname
                    self._pending_uprobes.append((uprobe_config, func))
                self.portal.queue_interrupt("uprobes")
                return func
            return decorator

        options = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter
        }

        if path is None:
            if isinstance(symbol, int):
                raise ValueError(
                    "If path is None, symbol must be a string, not int.")
            symbols_data = self._load_symbols()
            if not symbols_data:
                if fail_register_ok:
                    return None
                raise RuntimeError("No symbols data loaded.")
            matching_libs = [(lib_path, lib_symbols[symbol]) for lib_path,
                             lib_symbols in symbols_data.items() if symbol in lib_symbols]
            if not matching_libs:
                if fail_register_ok:
                    return None
                self.logger.warning(
                    f"Symbol '{symbol}' not found in any library.")
                return None
            uprobe_configs = [{
                "path": lib_path,
                "offset": offset,
                "options": options.copy(),
                "symbol": symbol
            } for lib_path, offset in matching_libs]
            return _register_decorator(uprobe_configs)

        if isinstance(symbol, int):
            offset = symbol
            symbol_name = None
            resolved_path = path
        else:
            symbol_name = symbol
            resolved_path, offset = self._lookup_symbol(path, symbol)
            if offset is None:
                if fail_register_ok:
                    return None
                self.logger.warning(
                    f"Symbol '{symbol}' not found in '{path}'. Using offset 0.")
                offset = 0
                resolved_path = path
        uprobe_configs = [{
            "path": resolved_path,
            "offset": offset,
            "options": options.copy(),
            "symbol": symbol_name
        }]
        return _register_decorator(uprobe_configs)

    def uretprobe(
        self,
        path: Optional[str],
        symbol: Union[str, int],
        process_filter: Optional[str] = None,
        on_enter: bool = False,
        on_return: bool = True,
        pid_filter: Optional[int] = None,
        fail_register_ok: bool = False
    ) -> Callable[[Callable], Callable]:
        """
        ### Decorator to register a return uprobe (uretprobe).

        Equivalent to `uprobe()` with `on_enter=False, on_return=True`.

        **Args:**
        - `path` (`Optional[str]`): Path to the executable or library file.
        - `symbol` (`Union[str, int]`): Symbol name or offset.
        - `process_filter` (`Optional[str]`): Process name filter.
        - `on_enter` (`bool`): Trigger on entry (default: False).
        - `on_return` (`bool`): Trigger on return (default: True).
        - `pid_filter` (`Optional[int]`): PID filter.
        - `fail_register_ok` (`bool`): If True, silently return if symbol not found.

        **Returns:**
        - `Callable[[Callable], Callable]`: Decorator for return probes.
        """
        return self.uprobe(path, symbol, process_filter,
                           on_enter, on_return, pid_filter, fail_register_ok)

    def unregister(self, probe_id: int) -> None:
        """
        ### Unregister a uprobe by its ID.

        **Args:**
        - `probe_id` (`int`): ID of the uprobe to unregister.

        **Returns:** None
        """
        self._unregister_uprobe(probe_id)
