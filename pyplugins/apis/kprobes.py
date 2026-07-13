"""
.. include:: /docs/kprobes.md
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
from hyper.consts import HYPER_OP as hop
import inspect

__all__ = [
    "Kprobes"
]


class Kprobes(Plugin):
    """
    Kprobes Plugin
    ==============

    Provides an interface for registering and handling kernel-space probes (kprobes).
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.projdir = self.get_arg("proj_dir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # MIPS has no hardware single-step; the kernel single-steps a probed
        # instruction out-of-line, which can corrupt state and panic the guest
        # for certain mid-function instructions. Entry probes (offset 0) and
        # kretprobes are safe; non-zero offsets are unreliable. Detect MIPS so
        # we can warn. Prefer the normalized config arch; fall back to the
        # emulator-compat object's arch_name.
        arch = ""
        conf = self.get_arg("conf")
        if conf:
            arch = (conf.get("core", {}) or {}).get("arch", "") or ""
        if not arch:
            arch = getattr(getattr(self, "panda", None), "arch_name", "") or ""
        self._is_mips = "mips" in arch.lower()

        # Maps probe_id to (callback_handle, is_method, read_only, original_func, injection_config)
        self._hooks: Dict[int, tuple] = {}
        self._hook_info = {}
        self._pending_kprobes = []

        # Mappings for unregistering
        self._handle_to_probe_ids: Dict[Callable,
                                        List[int]] = defaultdict(list)
        self._func_to_probe_ids: Dict[Callable, List[int]] = defaultdict(list)
        self._name_to_probe_ids: Dict[str, List[int]] = defaultdict(list)

        # {reattach_key -> guest probe_id} carried across a snapshot restore.
        self._restored_ids: Dict[str, int] = {}

        self.portal = plugins.portal
        self.portal.register_interrupt_handler(
            "kprobes", self._kprobe_interrupt_handler)
        plugins.hypercall.hypercall(iconsts.IGLOO_HYP_KPROBE_ENTER)(
            self._kprobe_enter_handler)
        plugins.hypercall.hypercall(iconsts.IGLOO_HYP_KPROBE_RETURN)(
            self._kprobe_return_handler)
        self._kprobe_event = self.plugins.portal.wrap(self._kprobe_event)

    def _resolve_callback(self, f, is_method, hook_ptr):
        if (is_method and hasattr(f, '__qualname__')
                and '.' in f.__qualname__
                and '<locals>' not in f.__qualname__):
            class_name = f.__qualname__.split('.')[0]
            method_name = f.__qualname__.split('.')[-1]
            try:
                instance = getattr(plugins, class_name)
                if instance and hasattr(instance, method_name):
                    bound_method = getattr(instance, method_name)
                    if hook_ptr in self._hooks:
                        # Update the callback but preserve metadata
                        _, _, read_only, original_func, injection = self._hooks[hook_ptr]
                        self._hooks[hook_ptr] = (
                            bound_method, False, read_only, original_func, injection)
                    return bound_method
            except AttributeError:
                pass
        return f

    def _analyze_signature(self, func):
        """
        Analyze signature to determine argument injection based on "sugar" rules.

        Context Indices:
        0: is_enter (bool)
        1: tgid_pid (u64)
        2: cpu (Any)

        Rules:
        - Kwargs matching 'is_enter', 'tgid_pid'are explicitly bound.
        - If **kwargs exists, all context is passed.
        - Remaining Positional Args logic:
          - 1 arg:  (is_enter)
          - 2 args: (is_enter, tgid_pid)
        """
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.values())
        except Exception:
            return [], {}

        # Skip 'self' if method
        if params and params[0].name == 'self':
            params = params[1:]

        # Skip 'regs' (always first)
        if params:
            params = params[1:]

        pos_indices = []
        kw_indices = {}

        # Context Mapping
        CTX_ENTER = 0
        CTX_TGID_PID = 1

        # Temporary list of positionals to assign standard meanings to
        positional_candidates = []
        # Pre-identify parameter names to avoid double-injection
        param_names = {p.name for p in params}

        for p in params:
            if p.kind == p.VAR_KEYWORD:
                # ONLY inject if the context names aren't already explicitly handled
                if 'is_enter' not in param_names:
                    kw_indices['is_enter'] = CTX_ENTER
                if 'tgid_pid' not in param_names:
                    kw_indices['tgid_pid'] = CTX_TGID_PID
                continue

            if p.kind == p.VAR_POSITIONAL:
                continue

            # Explicit Name Matching
            mapped_idx = -1
            if p.name == 'is_enter':
                mapped_idx = CTX_ENTER
            elif p.name == 'tgid_pid':
                mapped_idx = CTX_TGID_PID

            if mapped_idx != -1:
                # Explicit match found
                if p.kind == p.KEYWORD_ONLY:
                    kw_indices[p.name] = mapped_idx
                else:
                    # It's positional-capable, but we treated it by name.
                    # We add it to positionals list but pre-filled.
                    # Actually, simplistic approach: explicit names are satisfied.
                    # We just need to handle the "unnamed" positionals.
                    pos_indices.append(mapped_idx)
            else:
                # Candidate for Sugar assignment
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
                    # Store index in pos_indices to patch later
                    positional_candidates.append(len(pos_indices))
                    pos_indices.append(None)  # Placeholder

        # Apply Sugar Rules to unnamed positionals
        count = len(positional_candidates)

        if count == 1:
            # 1 Arg -> is_enter
            idx = positional_candidates[0]
            pos_indices[idx] = CTX_ENTER
        elif count == 2:
            # 2 Args -> is_enter, tgid_pid
            idx0 = positional_candidates[0]
            idx1 = positional_candidates[1]
            pos_indices[idx0] = CTX_ENTER
            pos_indices[idx1] = CTX_TGID_PID
        else:
            # Fallback: fill with None or maybe assume is_enter, tgid_pid order?
            # For now, safe default is None to avoid injection errors
            pass

        # Clean up any None entries (shouldn't happen with valid logic above unless >2 positionals)
        pos_indices = [x if x is not None else -1 for x in pos_indices]

        return pos_indices, kw_indices

    def _kprobe_event(self, cpu: Any, is_enter: bool) -> Any:
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        sce = plugins.kffi.read_type_panda(cpu, arg, "portal_event")
        hook_id = sce.id
        if hook_id not in self._hooks:
            return

        f, is_method, read_only, _, injection = self._hooks[hook_id]
        ptregs_addr = sce.regs.address
        pt_regs_raw = plugins.kffi.read_type_panda(cpu, ptregs_addr, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)

        original_bytes = None
        if not read_only:
            original_bytes = bytes(pt_regs_raw)

        fn_to_call = f if not is_method else self._resolve_callback(
            f, is_method, hook_id)

        if fn_to_call:
            tgid_pid = (sce.tgid << 32) | sce.tid

            # Context Map: 0->is_enter, 1->tgid_pid
            ctx_values = (is_enter, tgid_pid)
            pos_ids, kw_ids = injection

            args = []
            for i in pos_ids:
                if i >= 0:
                    args.append(ctx_values[i])
                else:
                    args.append(None)  # Should not happen with 1 or 2 args
            kwargs = {}
            if kw_ids:
                kwargs = {k: ctx_values[i] for k, i in kw_ids.items()}

            fn_ret = fn_to_call(pt_regs, *args, **kwargs)

            if isinstance(fn_ret, Iterator):
                fn_ret = yield from fn_ret
        else:
            return

        if not read_only:
            new_bytes = bytes(pt_regs_raw)
            if original_bytes != new_bytes:
                plugins.mem.write_bytes_panda(cpu, ptregs_addr, new_bytes)
        return fn_ret

    def _kprobe_enter_handler(self, cpu: Any) -> None:
        """
        Entry handler for kprobes.

        Parameters
        ----------
        cpu : Any
            CPU context.

        Returns
        -------
        None
        """
        self._kprobe_event(cpu, True)

    def _kprobe_return_handler(self, cpu: Any) -> None:
        """
        Return handler for kprobes.

        Parameters
        ----------
        cpu : Any
            CPU context.

        Returns
        -------
        None
        """
        self._kprobe_event(cpu, False)

    @plugins.live_image.fs_init
    def on_fs_init(self):
        self.portal.queue_interrupt("kprobes")

    def _kprobe_interrupt_handler(self) -> bool:
        """
        Handle interrupts for pending kprobe registrations and unregistrations.
        """
        if not self._pending_kprobes:
            return False

        pending_kprobes = self._pending_kprobes[:]
        self._pending_kprobes = []

        while pending_kprobes:
            item = pending_kprobes.pop(0)

            # Handle unregister
            if isinstance(item, tuple) and item[0] == 'unregister':
                _, probe_id = item
                yield PortalCmd(hop.HYPER_OP_UNREGISTER_KPROBE, addr=probe_id)
                continue

            # Handle register
            kprobe_config, handle = item
            original_func = getattr(handle, '_original_func', handle)

            probe_id = yield from self._register_kprobe(kprobe_config)

            if probe_id:
                is_method = kprobe_config.get("is_method", False)
                read_only = kprobe_config.get("read_only", False)

                # [PATCH] Analyze signature
                injection = self._analyze_signature(original_func)

                self._hooks[probe_id] = (
                    handle, is_method, read_only, original_func, injection)
                self._hook_info[probe_id] = kprobe_config

                # Populate mappings
                self._handle_to_probe_ids[handle].append(probe_id)
                self._func_to_probe_ids[original_func].append(probe_id)

                func_name = getattr(original_func, "__name__", None)
                if func_name:
                    self._name_to_probe_ids[func_name].append(probe_id)

                self.logger.debug(
                    f"Registered kprobe ID {probe_id} for {kprobe_config['symbol']}+{kprobe_config.get('offset', 0):#x}")
            else:
                self.logger.error("Failed to register kprobe")

        return False

    # --- snapshot / restore ------------------------------------------------ #
    @staticmethod
    def _reattach_key(config, original_func):
        """Stable, JSON-safe identity for a registration, matched across a
        restore. Includes the handler qualname so multiple probes at the same
        site (e.g. an aggregate + a filter probe on do_filp_open) stay distinct."""
        fn = getattr(original_func, "__qualname__", "") or ""
        return (f"{config['symbol']}+{config.get('offset', 0):#x}:"
                f"{bool(config.get('on_enter', True))}:"
                f"{bool(config.get('on_return', False))}:"
                f"{config.get('process_filter')}:{config.get('pid_filter')}:{fn}")

    def save_state(self):
        """Persist {reattach_key -> guest probe_id}. The guest-side kprobes live
        in the guest kprobe_table and survive savevm, so a cross-process restore
        must re-bind host callbacks to those existing ids rather than install
        duplicates. Callbacks aren't serialisable -- they come fresh from the
        owner plugin's re-register on the restore boot; only the ids are carried."""
        probes = {}
        for probe_id, entry in self._hooks.items():
            original_func = entry[3]
            config = self._hook_info.get(probe_id)
            if config:
                probes[self._reattach_key(config, original_func)] = probe_id
        return {"probes": probes} if probes else None

    def load_state(self, data) -> None:
        """Phase one: stash the saved key->id map (no guest I/O)."""
        if data:
            self._restored_ids = dict(data.get("probes", {}))

    def on_restore(self, tag: str) -> None:
        """Re-bind host callbacks to the kprobes that survived the snapshot.

        The guest-side probe (and its id) is baked into guest RAM and still fires
        after -loadvm; only the host id->callback map was lost. The normal
        register drain does NOT run on a restore boot (it is kicked by fs_init /
        a portal interrupt that a -loadvm boot doesn't re-issue), so bind
        directly here: for each pending registration whose key matches a saved
        id, populate _hooks with the fresh callback at the EXISTING id and drop
        it from the pending queue, so it is never re-installed (which would leave
        a duplicate guest probe). Unmatched pendings fall through to the normal
        path (genuinely new probes)."""
        if not self._restored_ids:
            return
        remaining = []
        for item in self._pending_kprobes:
            if isinstance(item, tuple) and item and item[0] == 'unregister':
                remaining.append(item)
                continue
            kprobe_config, handle = item
            original_func = getattr(handle, '_original_func', handle)
            probe_id = self._restored_ids.pop(
                self._reattach_key(kprobe_config, original_func), None)
            if probe_id is None:
                remaining.append(item)
                continue
            is_method = kprobe_config.get("is_method", False)
            read_only = kprobe_config.get("read_only", False)
            injection = self._analyze_signature(original_func)
            self._hooks[probe_id] = (
                handle, is_method, read_only, original_func, injection)
            self._hook_info[probe_id] = kprobe_config
            self._handle_to_probe_ids[handle].append(probe_id)
            self._func_to_probe_ids[original_func].append(probe_id)
            func_name = getattr(original_func, "__name__", None)
            if func_name:
                self._name_to_probe_ids[func_name].append(probe_id)
            self.logger.info(
                f"Re-attached kprobe id {probe_id} to {kprobe_config['symbol']} "
                "after snapshot restore (no reinstall)")
        self._pending_kprobes = remaining

    def _register_kprobe(self, config: Dict[str, Any]) -> Iterator[Optional[int]]:
        on_enter = config.get("on_enter", True)
        on_return = config.get("on_return", False)

        if on_enter and on_return:
            probe_type = portal_type.PORTAL_KPROBE_TYPE_BOTH
        elif on_enter:
            probe_type = portal_type.PORTAL_KPROBE_TYPE_ENTRY
        elif on_return:
            probe_type = portal_type.PORTAL_KPROBE_TYPE_RETURN
        else:
            return None

        init_data = {
            "symbol": config["symbol"].encode('latin-1'),
            "offset": config["offset"],
            "type": probe_type,
            "pid": config.get("pid_filter") if config.get("pid_filter") is not None else 0xffffffff,
            "comm": config["process_filter"].encode('latin-1') if config.get("process_filter") else b""
        }

        # 1. Allocate and initialize the struct in one call
        reg = plugins.kffi.new("kprobe_registration", init_data)

        # 2. Extract the native bytes representation directly
        reg_bytes = bytes(reg)

        result = yield PortalCmd(hop.HYPER_OP_REGISTER_KPROBE, reg.offset, len(reg_bytes), None, reg_bytes)

        if result is None:
            self.logger.error(
                f"Failed to register kprobe at {config['symbol']}+{config['offset']:#x}")
            return None

        probe_id = result
        self.logger.debug(
            f"Kprobe successfully registered with ID: {probe_id}")
        return result

    def _cleanup_probe_maps(self, probe_id: int):
        if probe_id in self._hooks:
            handle, _, _, original_func, _ = self._hooks[probe_id]

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

    def kprobe(
        self,
        symbol: str,
        offset: int = 0,
        process_filter: Optional[str] = None,
        on_enter: bool = True,
        on_return: bool = False,
        pid_filter: Optional[int] = None,
        read_only: bool = False,
        fail_register_ok: bool = False
    ) -> Callable[[Callable], Callable]:
        """
        Decorator to register a kprobe on a kernel function by symbol name.

        The guest kernel resolves the symbol via kallsyms at registration time.

        Parameters
        ----------
        symbol : str
            Kernel symbol name (resolved via kallsyms in the guest).
        offset : int
            Offset (in bytes) from the symbol at which to place the probe
            (default: 0).
        process_filter : Optional[str]
            Process name (comm) to filter events.
        on_enter : bool
            Trigger on function entry (default: True).
        on_return : bool
            Trigger on function return (default: False).
        pid_filter : Optional[int]
            PID to filter events for a specific process.
        read_only: bool
            If True, register state modifications are not written back.
        fail_register_ok : bool
            If True, silently ignore registration failures.

        Returns
        -------
        Callable[[Callable], Callable]
            Decorator function that registers the kprobe.
        """
        def _register_decorator(kprobe_configs):
            def decorator(func):
                # Wrapper to act as a unique handle
                @functools.wraps(func)
                def wrapper(*args, **kwargs):
                    return func(*args, **kwargs)
                wrapper._original_func = func

                is_method = hasattr(func, '__self__') or (
                    hasattr(func, '__qualname__')
                    and '.' in func.__qualname__
                    and '<locals>' not in func.__qualname__)

                for kprobe_config in kprobe_configs:
                    kprobe_config["callback"] = func
                    kprobe_config["is_method"] = is_method
                    kprobe_config["read_only"] = read_only

                    # Store wrapper instead of raw func
                    self._pending_kprobes.append((kprobe_config, wrapper))

                if plugins.live_image.fs_generated:
                    self.portal.queue_interrupt("kprobes")
                return wrapper
            return decorator

        def _no_op_decorator(func):
            return func

        if symbol is None:
            self.logger.error("Must specify a kernel symbol name.")
            return _no_op_decorator

        if offset and self._is_mips:
            self.logger.warning(
                f"kprobe(symbol={symbol!r}, offset={offset:#x}): non-entry kprobe "
                "offsets are unreliable on MIPS — single-step-out-of-line can "
                "corrupt register state and panic the guest kernel. Prefer offset=0 "
                "or a kretprobe. See docs/kprobes.md."
            )

        cfg = {
            'symbol': symbol,
            'offset': offset,
            'process_filter': process_filter,
            'on_enter': on_enter,
            'on_return': on_return,
            'pid_filter': pid_filter,
            'read_only': read_only
        }

        return _register_decorator([cfg])

    def kretprobe(
        self,
        symbol: str,
        **kwargs
    ) -> Callable:
        kwargs['on_enter'] = False
        kwargs['on_return'] = True
        kwargs['offset'] = 0
        return self.kprobe(symbol, **kwargs)

    def unregister(self, target: Union[Callable, str]):
        """
        Unregister a kprobe by handle, function, or name.

        Args:
            target: The handle (returned by decorator), function, or name of the kprobe to unregister.
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
            self.logger.warning(f"No kprobes found for target {target}")
            return

        for pid in probe_ids:
            self._cleanup_probe_maps(pid)
            self._pending_kprobes.append(('unregister', pid))

        self.portal.queue_interrupt("kprobes")
