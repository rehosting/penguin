"""
.. include:: /docs/uprobes.md
   :parser: myst_parser.sphinx_
"""

from penguin import plugins, Plugin
from typing import Dict, Any, Callable, Optional, Iterator, Union, List
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import portal_type
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper
import functools
from collections import defaultdict

__all__ = [
    "Uprobes"
]


class Uprobes(Plugin):
    """
    Uprobes Plugin
    ==============

    Provides an interface for registering and handling user-space probes (uprobes).
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.projdir = self.get_arg("proj_dir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # Maps probe_id to (callback_handle, is_method, read_only, original_func)
        self._hooks: Dict[int, tuple] = {}
        self._hook_info = {}
        self._pending_uprobes = []

        # Mappings for unregistering
        self._handle_to_probe_ids: Dict[Callable,
                                        List[int]] = defaultdict(list)
        self._func_to_probe_ids: Dict[Callable, List[int]] = defaultdict(list)
        self._name_to_probe_ids: Dict[str, List[int]] = defaultdict(list)

        self.portal = plugins.portal
        self.portal.register_interrupt_handler(
            "uprobes", self._uprobe_interrupt_handler)
        self.panda.hypercall(iconsts.IGLOO_HYP_UPROBE_ENTER)(
            self._uprobe_enter_handler)
        self.panda.hypercall(iconsts.IGLOO_HYP_UPROBE_RETURN)(
            self._uprobe_return_handler)
        self._uprobe_event = self.plugins.portal.wrap(self._uprobe_event)

    def _resolve_callback(self, f, is_method, hook_ptr):
        if is_method and hasattr(f, '__qualname__') and '.' in f.__qualname__:
            class_name = f.__qualname__.split('.')[0]
            method_name = f.__qualname__.split('.')[-1]
            try:
                instance = getattr(plugins, class_name)
                if instance and hasattr(instance, method_name):
                    bound_method = getattr(instance, method_name)
                    if hook_ptr in self._hooks:
                        # Update the callback but preserve metadata
                        _, _, read_only, original_func = self._hooks[hook_ptr]
                        self._hooks[hook_ptr] = (
                            bound_method, False, read_only, original_func)
                    return bound_method
            except AttributeError:
                pass
        return f

    def _uprobe_event(self, cpu: Any, is_enter: bool) -> Any:
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        sce = plugins.kffi.read_type_panda(cpu, arg, "portal_event")
        hook_id = sce.id
        if hook_id not in self._hooks:
            return

        f, is_method, read_only, _ = self._hooks[hook_id]
        ptregs_addr = sce.regs.address
        pt_regs_raw = plugins.kffi.read_type_panda(cpu, ptregs_addr, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)

        original_bytes = None
        if not read_only:
            original_bytes = pt_regs.to_bytes()[:]

        fn_to_call = f if not is_method else self._resolve_callback(
            f, is_method, hook_id)

        if fn_to_call:
            fn_ret = fn_to_call(pt_regs)
            if isinstance(fn_ret, Iterator):
                fn_ret = yield from fn_ret
        else:
            return

        if not read_only:
            new_bytes = pt_regs.to_bytes()
            if original_bytes != new_bytes:
                plugins.mem.write_bytes_panda(cpu, ptregs_addr, new_bytes)
        return fn_ret

    def _uprobe_enter_handler(self, cpu: Any) -> None:
        """
        Entry handler for uprobes.

        Parameters
        ----------
        cpu : Any
            CPU context.

        Returns
        -------
        None
        """
        self._uprobe_event(cpu, True)

    def _uprobe_return_handler(self, cpu: Any) -> None:
        """
        Return handler for uprobes.

        Parameters
        ----------
        cpu : Any
            CPU context.

        Returns
        -------
        None
        """
        self._uprobe_event(cpu, False)

    @plugins.live_image.fs_init
    def on_fs_init(self):
        self.portal.queue_interrupt("uprobes")

    def _uprobe_interrupt_handler(self) -> bool:
        """
        Handle interrupts for pending uprobe registrations and unregistrations.
        """
        if not self._pending_uprobes:
            return False

        pending_uprobes = self._pending_uprobes[:]
        self._pending_uprobes = []

        while pending_uprobes:
            item = pending_uprobes.pop(0)

            # Handle unregister
            if isinstance(item, tuple) and item[0] == 'unregister':
                _, probe_id = item
                import struct
                if getattr(self.panda, 'bits', 64) == 32:
                    data = struct.pack("<I", probe_id)
                else:
                    data = struct.pack("<Q", probe_id)
                yield PortalCmd("unregister_uprobe", size=len(data), data=data)
                continue

            # Handle register
            uprobe_config, handle = item
            original_func = getattr(handle, '_original_func', handle)

            probe_id = yield from self._register_uprobe(uprobe_config)

            if probe_id:
                is_method = uprobe_config.get("is_method", False)
                read_only = uprobe_config.get("read_only", False)

                # Store callback info: (handle, is_method, read_only, original_func)
                self._hooks[probe_id] = (
                    handle, is_method, read_only, original_func)
                self._hook_info[probe_id] = uprobe_config

                # Populate mappings
                self._handle_to_probe_ids[handle].append(probe_id)
                self._func_to_probe_ids[original_func].append(probe_id)

                func_name = getattr(original_func, "__name__", None)
                if func_name:
                    self._name_to_probe_ids[func_name].append(probe_id)

                self.logger.debug(
                    f"Registered uprobe ID {probe_id} for {uprobe_config['path']}:{uprobe_config.get('offset', 0):#x}")
            else:
                self.logger.error("Failed to register uprobe")

        return False

    def _register_uprobe(self, config: Dict[str, Any]) -> Iterator[Optional[int]]:
        path = config["path"]
        offset = config["offset"]
        on_enter = config.get("on_enter", True)
        on_return = config.get("on_return", False)
        pid_filter = config.get("pid_filter")
        process_filter = config.get("process_filter")

        if on_enter and on_return:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_BOTH
        elif on_enter:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_ENTRY
        elif on_return:
            probe_type = portal_type.PORTAL_UPROBE_TYPE_RETURN
        else:
            return None

        filter_pid = pid_filter if pid_filter is not None else 0xffffffff

        reg = plugins.kffi.new("uprobe_registration")
        path_bytes = path.encode('latin-1')
        for i, b in enumerate(path_bytes[:255]):
            reg.path[i] = b
        reg.path[min(len(path_bytes), 255)] = 0

        reg.offset = offset
        reg.type = probe_type
        reg.pid = filter_pid

        if process_filter:
            comm_bytes = process_filter.encode('latin-1')
            for i, b in enumerate(comm_bytes[:15]):
                reg.comm[i] = b
            reg.comm[min(len(comm_bytes), 15)] = 0
        else:
            reg.comm[0] = 0

        reg_bytes = reg.to_bytes()
        result = yield PortalCmd("register_uprobe", offset, len(reg_bytes), None, reg_bytes)

        if result is None:
            self.logger.error(
                f"Failed to register uprobe at {path}:{offset:#x}")
            return None

        probe_id = result
        self.logger.debug(
            f"Uprobe successfully registered with ID: {probe_id}")
        return result

    def _cleanup_probe_maps(self, probe_id: int):
        if probe_id in self._hooks:
            handle, _, _, original_func = self._hooks[probe_id]

            if handle in self._handle_to_probe_ids:
                if probe_id in self._handle_to_probe_ids[handle]:
                    self._handle_to_probe_ids[handle].remove(probe_id)

            if original_func in self._func_to_probe_ids:
                if probe_id in self._func_to_probe_ids[original_func]:
                    self._func_to_probe_ids[original_func].remove(probe_id)

            name = getattr(original_func, "__name__", None)
            if name and name in self._name_to_probe_ids:
                if probe_id in self._name_to_probe_ids[name]:
                    self._name_to_probe_ids[name].remove(probe_id)

            del self._hooks[probe_id]
            if probe_id in self._hook_info:
                del self._hook_info[probe_id]

    def uprobe(
        self,
        path: Optional[str] = None,
        symbol: Union[str, int] = None,
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None,
        read_only: bool = False,
        fail_register_ok: bool = False
    ) -> Callable[[Callable], Callable]:
        """
        Decorator to register a uprobe at the specified path and symbol/offset.

        Parameters
        ----------
        path : Optional[str]
            Path to the executable or library file (can include wildcards), or None to match all libraries containing the symbol.
        symbol : Union[str, int]
            Symbol name (string) or offset (integer) in the file.
        process_filter : Optional[str]
            Process name to filter events.
        on_enter : bool
            Trigger on function entry (default: True).
        on_return : bool
            Trigger on function return (default: False).
        pid_filter : Optional[int]
            PID to filter events for a specific process.
        read_only: bool
        fail_register_ok : bool
            If True, silently return if symbol not found.

        Returns
        -------
        Callable[[Callable], Callable]
            Decorator function that registers the uprobe.
        """
        def _register_decorator(uprobe_configs):
            def decorator(func):
                # Wrapper to act as a unique handle
                @functools.wraps(func)
                def wrapper(*args, **kwargs):
                    return func(*args, **kwargs)
                wrapper._original_func = func

                is_method = hasattr(func, '__self__') or (
                    hasattr(func, '__qualname__') and '.' in func.__qualname__)

                for uprobe_config in uprobe_configs:
                    uprobe_config["callback"] = func
                    uprobe_config["is_method"] = is_method
                    uprobe_config["read_only"] = read_only

                    # Store wrapper instead of raw func
                    self._pending_uprobes.append((uprobe_config, wrapper))

                if plugins.live_image.fs_generated:
                    self.portal.queue_interrupt("uprobes")
                return wrapper
            return decorator

        base_config = {
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter,
            'read_only': read_only
        }

        # 1. Search Everywhere (path is None)
        if path is None:
            if isinstance(symbol, int):
                raise ValueError("If path is None, symbol must be a string.")

            matching_libs = plugins.symbols.find_all(symbol)

            if not matching_libs:
                if fail_register_ok:
                    return lambda x: x
                self.logger.warning(
                    f"Symbol '{symbol}' not found in any library.")
                return lambda x: x

            uprobe_configs = []
            for lib_path, offset in matching_libs:
                cfg = base_config.copy()
                cfg.update(
                    {"path": lib_path, "offset": offset, "symbol": symbol})
                uprobe_configs.append(cfg)

            return _register_decorator(uprobe_configs)

        # 2. Specific Path
        if isinstance(symbol, int):
            offset = symbol
            symbol_name = f"offset_{offset:#x}"
            resolved_path = path
        else:
            symbol_name = symbol
            resolved_path, offset = plugins.symbols.lookup(path, symbol)

            if offset is None:
                if fail_register_ok:
                    return lambda x: x
                self.logger.warning(
                    f"Symbol '{symbol}' not found in '{path}'. Defaulting to offset 0.")
                offset = 0
                resolved_path = path

        cfg = base_config.copy()
        cfg.update(
            {"path": resolved_path, "offset": offset, "symbol": symbol_name})

        return _register_decorator([cfg])

    def uretprobe(self, path: Optional[str], symbol: Union[str, int], **kwargs) -> Callable:
        kwargs['on_enter'] = False
        kwargs['on_return'] = True
        return self.uprobe(path, symbol, **kwargs)

    def unregister(self, target: Union[Callable, str]):
        """
        Unregister a uprobe by handle, function, or name.

        Args:
            target: The handle (returned by decorator), function, or name of the uprobe to unregister.
        """
        probe_ids = []

        # 1. Try by handle (wrapper)
        if target in self._handle_to_probe_ids:
            probe_ids.extend(self._handle_to_probe_ids[target])

        # 2. Try by original function
        func = getattr(target, '_original_func', target)
        if func in self._func_to_probe_ids:
            for pid in self._func_to_probe_ids[func]:
                if pid not in probe_ids:
                    probe_ids.append(pid)
        # Check if target is a bound method, if so, check its __func__
        if hasattr(target, '__func__') and target.__func__ in self._func_to_probe_ids:
            for pid in self._func_to_probe_ids[target.__func__]:
                if pid not in probe_ids:
                    probe_ids.append(pid)

        # 3. Try by name
        if isinstance(target, str):
            if target in self._name_to_probe_ids:
                for pid in self._name_to_probe_ids[target]:
                    if pid not in probe_ids:
                        probe_ids.append(pid)

        if not probe_ids:
            self.logger.warning(f"No uprobes found for target {target}")
            return

        for pid in probe_ids:
            self._cleanup_probe_maps(pid)
            self._pending_uprobes.append(('unregister', pid))

        self.portal.queue_interrupt("uprobes")
