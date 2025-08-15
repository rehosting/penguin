"""
.. include:: /docs/syscalls.md
"""

from penguin import plugins, Plugin
import json
from typing import Dict, List, Any, Callable, Optional, Iterator
from hyper.consts import value_filter_type as vft
from hyper.consts import igloo_hypercall_constants as iconsts
from hyper.consts import igloo_base_hypercalls as bconsts
from hyper.portal import PortalCmd
from wrappers.ptregs_wrap import get_pt_regs_wrapper


class ValueFilter:
    """
    Represents a complex value filter for syscall arguments or return values.
    """

    def __init__(self, filter_type: int = vft.SYSCALLS_HC_FILTER_EXACT, value: int = 0,
                 min_value: int = 0, max_value: int = 0, bitmask: int = 0) -> None:
        """
        ### Initialize a ValueFilter

        **Args:**
        - `filter_type` (`int`): The type of filter.
        - `value` (`int`): The value for the filter.
        - `min_value` (`int`): The minimum value for range filters.
        - `max_value` (`int`): The maximum value for range filters.
        - `bitmask` (`int`): The bitmask for bitmask filters.
        """
        self.filter_type = filter_type
        self.value = value
        self.min_value = min_value
        self.max_value = max_value
        self.bitmask = bitmask

    @classmethod
    def exact(cls, value: int) -> "ValueFilter":
        """
        ### Create an exact match filter

        **Args:**
        - `value` (`int`): The value to match.

        **Returns:**
        `ValueFilter`: An exact match filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_EXACT, value=value)

    @classmethod
    def greater(cls, value: int) -> "ValueFilter":
        """
        ### Create a greater than filter

        **Args:**
        - `value` (`int`): The value to compare.

        **Returns:**
        `ValueFilter`: A greater than filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_GREATER, value=value)

    @classmethod
    def greater_equal(cls, value: int) -> "ValueFilter":
        """
        ### Create a greater than or equal filter

        **Args:**
        - `value` (`int`): The value to compare.

        **Returns:**
        `ValueFilter`: A greater than or equal filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_GREATER_EQUAL, value=value)

    @classmethod
    def less(cls, value: int) -> "ValueFilter":
        """
        ### Create a less than filter

        **Args:**
        - `value` (`int`): The value to compare.

        **Returns:**
        `ValueFilter`: A less than filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_LESS, value=value)

    @classmethod
    def less_equal(cls, value: int) -> "ValueFilter":
        """
        ### Create a less than or equal filter

        **Args:**
        - `value` (`int`): The value to compare.

        **Returns:**
        `ValueFilter`: A less than or equal filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_LESS_EQUAL, value=value)

    @classmethod
    def not_equal(cls, value: int) -> "ValueFilter":
        """
        ### Create a not equal filter

        **Args:**
        - `value` (`int`): The value to compare.

        **Returns:**
        `ValueFilter`: A not equal filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_NOT_EQUAL, value=value)

    @classmethod
    def range(cls, min_value: int, max_value: int) -> "ValueFilter":
        """
        ### Create a range filter

        **Args:**
        - `min_value` (`int`): The minimum value.
        - `max_value` (`int`): The maximum value.

        **Returns:**
        `ValueFilter`: A range filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_RANGE,
                   min_value=min_value, max_value=max_value)

    @classmethod
    def success(cls) -> "ValueFilter":
        """
        ### Create a success filter (>= 0)

        **Returns:**
        `ValueFilter`: A success filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_SUCCESS)

    @classmethod
    def error(cls) -> "ValueFilter":
        """
        ### Create an error filter (< 0)

        **Returns:**
        `ValueFilter`: An error filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_ERROR)

    @classmethod
    def bitmask_set(cls, bitmask: int) -> "ValueFilter":
        """
        ### Create a bitmask set filter

        **Args:**
        - `bitmask` (`int`): The bitmask to set.

        **Returns:**
        `ValueFilter`: A bitmask set filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_BITMASK_SET,
                   bitmask=bitmask)

    @classmethod
    def bitmask_clear(cls, bitmask: int) -> "ValueFilter":
        """
        ### Create a bitmask clear filter

        **Args:**
        - `bitmask` (`int`): The bitmask to clear.

        **Returns:**
        `ValueFilter`: A bitmask clear filter.
        """
        return cls(filter_type=vft.SYSCALLS_HC_FILTER_BITMASK_CLEAR,
                   bitmask=bitmask)


class SyscallPrototype:
    """
    Represents syscall metadata, including argument types and names.
    """

    def __init__(self, name: str,
                 args: Optional[List[Any]] = None, unknown_args: bool = False) -> None:
        """
        ### Initialize a SyscallPrototype

        **Args:**
        - `name` (`str`): The syscall name.
        - `args` (`Optional[List[Any]]`): List of argument type/name pairs.
        - `unknown_args` (`bool`): Whether the arguments are unknown.
        """
        # Store the name as the primary identifier
        self.name = name
        self.types = []
        self.names = []
        self.args = args
        self.unknown_args = unknown_args
        if args:
            for i, j in args:
                self.types.append(i)
                self.names.append(j)
        self.nargs = len(self.types)

    def __repr__(self) -> str:
        """
        ### Return a string representation of the SyscallPrototype

        **Returns:**
        `str`: String representation.
        """
        return f"<SyscallPrototype name='{self.name}' nargs={self.nargs}>"


class Syscalls(Plugin):
    """
    Plugin that provides an interface to monitor and intercept system calls.
    Uses the portal's interrupt mechanism to handle registration and event delivery.
    """

    def __init__(self) -> None:
        """
        ### Initialize the Syscalls plugin

        Registers with portal and sets up syscall metadata.
        """
        self.outdir = self.get_arg("outdir")

        # Map hook pointers to callbacks
        # Maps hook pointers to (on_all, callback_func) tuples
        self.hooks: Dict[int, tuple] = {}

        # Track function -> hook_ptr and name -> hook_ptr for easier lookup
        self._func_to_hook_ptr = {}  # Maps functions to hook pointers
        self._name_to_hook_ptr = {}  # Maps function names to hook pointers

        # Get portal plugin
        self.portal = plugins.portal

        # Syscall type information - using dictionary for fast name-based
        # lookups
        self.syscall_info_table: Dict[str, SyscallPrototype] = {}
        self.missing_syscalls: List[SyscallPrototype] = []
        self.verified_unknown_syscalls: set = set()
        self.table_initialized = False
        self.hooks = {}
        self.hook_info = {}
        self.saved_syscall_events = {}

        # Register with portal's interrupt handler system
        self.portal.register_interrupt_handler(
            "syscalls", self._syscall_interrupt_handler)

        # Register handlers for syscall setup and events
        self.panda.hypercall(bconsts.IGLOO_HYP_SETUP_SYSCALL)(
            self._setup_syscall_handler)

        # Register syscall enter/return hypercalls
        self.panda.hypercall(iconsts.IGLOO_HYP_SYSCALL_ENTER)(
            self._syscall_enter_event)
        self.panda.hypercall(iconsts.IGLOO_HYP_SYSCALL_RETURN)(
            self._syscall_return_event)

        # Add a queue for pending hook registrations
        self._pending_hooks = []
        self._syscall_event = self.portal.wrap(self._syscall_event)

    def _setup_syscall_handler(self, cpu: int) -> None:
        """
        ### Handler for setting up syscall definitions

        **Args:**
        - `cpu` (`int`): CPU id.

        **Returns:**
        `None`
        """
        reg1 = self.panda.arch.get_arg(cpu, 1, convention="syscall")

        # Read the JSON string at reg1
        json_str = self.panda.read_str(cpu, reg1)
        syscall_data = json.loads(json_str)

        # Clean the syscall name
        name = syscall_data["name"]
        clean_name = self._clean_syscall_name(name)
        unknown_args = syscall_data.get("args", "") == "unknown"

        if unknown_args:
            args = []
        else:
            args = syscall_data.get("args", [])

        # Create prototype without syscall_nr
        sysinfo = SyscallPrototype(
            name=f'sys_{clean_name}',
            args=args,
            unknown_args=unknown_args
        )

        # Store by cleaned name in the hash table
        if unknown_args and clean_name in self.syscall_info_table:
            self.logger.debug(
                f"Syscall {name} is a compat syscall, skipping it for a better match")
        else:
            self.syscall_info_table[clean_name] = sysinfo
            self.logger.debug(
                f"Registered syscall {name} (cleaned: {clean_name})")

    def _clean_syscall_name(self, name: str) -> str:
        """
        ### Clean a syscall name

        Removes various prefixes and architecture-specific parts.

        **Args:**
        - `name` (`str`): The syscall name.

        **Returns:**
        `str`: Cleaned syscall name.
        """
        if name.startswith("compat_"):
            name = name[7:]
        # First remove sys_ prefix if present
        if name.startswith("sys_"):
            name = name[4:]

        # Then remove any remaining leading underscores
        name = name.lstrip("_")

        return name

    def _syscall_interrupt_handler(self) -> bool:
        """
        ### Handle interrupts from the portal for syscall hook registration

        **Returns:**
        `bool`: True if more hooks are pending, False otherwise.
        """
        # Always ensure we yield at least once so the function returns a proper
        # generator
        if not self._pending_hooks:
            self.logger.debug("No pending syscall hooks to register")
            # Yield a no-op operation to ensure this is always an iterator
            return False

        pending_hooks = self._pending_hooks[:]

        while pending_hooks:
            # Take one item from the queue
            hook_config, func = pending_hooks.pop(0)

            # Register the syscall hook
            hook_ptr = yield from self.register_syscall_hook(hook_config)
            on_all = hook_config.get("on_all", False)
            is_method = hook_config.get("is_method", False)

            # Store hook information for multiple lookup methods
            self.hooks[hook_ptr] = (on_all, func, is_method)

            # Track function to hook pointer mappings
            self._func_to_hook_ptr[func] = hook_ptr

            # Store by function name if available
            func_name = func.__name__ if hasattr(func, "__name__") else None
            if func_name:
                self._name_to_hook_ptr[func_name] = hook_ptr

    def _syscall_enter_event(self, cpu: int) -> None:
        """
        ### Handler for syscall entry events from the hypervisor

        **Args:**
        - `cpu` (`int`): CPU id.

        **Returns:**
        `None`
        """
        self._syscall_event(cpu, is_enter=True)

    def _syscall_return_event(self, cpu: int) -> None:
        """
        ### Handler for syscall return events from the hypervisor

        **Args:**
        - `cpu` (`int`): CPU id.

        **Returns:**
        `None`
        """
        self._syscall_event(cpu, is_enter=False)

    '''
    On repeated calls to the same syscall in portal we produce new
    syscall_event objects. However, it doesn't update the version of the object
    that the function has. This means that when it sets values we have a
    different object and can fail.

    So we keep the original syscall_event object in a dictionary and check if the
    sequence number is the same. If it is we use the original object.
    '''

    def _get_syscall_event(self, cpu: int, arg: int) -> Any:
        """
        ### Retrieve the syscall event object from the guest

        **Args:**
        - `cpu` (`int`): CPU id.
        - `arg` (`int`): Argument pointer.

        **Returns:**
        `Tuple[Any, bytes]`: The syscall event object and its original bytes.
        """
        sce = plugins.kffi.read_type_panda(cpu, arg, "syscall_event")
        sce.name = bytes(sce.syscall_name).decode("latin-1").rstrip("\x00")
        original = sce.to_bytes()[:]
        return sce, original

    def _get_proto(self, cpu: int, sce: Any) -> SyscallPrototype:
        """
        ### Get the syscall prototype for a given event

        **Args:**
        - `cpu` (`int`): CPU id.
        - `sce` (`Any`): Syscall event object.

        **Returns:**
        `SyscallPrototype`: The prototype for the syscall.
        """
        # Get syscall name from the event
        name = sce.name
        # Clean the syscall name
        cleaned_name = self._clean_syscall_name(name)

        # Look up the prototype by cleaned name directly using hash table (O(1)
        # lookup)
        proto = self.syscall_info_table.get(cleaned_name)

        # If not found, try removing architecture prefix
        if not proto:
            # Try removing everything up to and including the first underscore
            if '_' in cleaned_name:
                arch_stripped_name = cleaned_name.split('_', 1)[1]
                proto = self.syscall_info_table.get(arch_stripped_name)

                if proto:
                    self.logger.debug(
                        f"Found syscall after removing architecture prefix: {cleaned_name} → {arch_stripped_name}")

        # If still not found, create a new generic prototype with unknown args
        if not proto:
            # Generate generic argument names (unknown1, unknown2, etc.)
            generic_args = []
            for i in range(6):  # Most syscalls have 6 or fewer args
                arg_name = f"unknown{i+1}"
                generic_args.append(("int", arg_name))

            # Create new prototype with the appropriate name and generic args
            proto = SyscallPrototype(
                name=f'sys_{cleaned_name}',
                args=generic_args
            )

            # Add to our table for future lookups
            self.syscall_info_table[cleaned_name] = proto
            self.logger.error(
                f"Syscall {name} not registered {cleaned_name=}, created generic prototype with {len(generic_args)} args")

        return proto

    def _resolve_syscall_callback(self, f, is_method, hook_ptr=None):
        """
        Resolve and bind the function or method for a syscall event.
        If a method is resolved, update self.hooks[hook_ptr] to store the bound method.
        Returns the callable (already bound if needed), or None on error.
        """
        if is_method and hasattr(f, '__qualname__') and '.' in f.__qualname__:
            class_name = f.__qualname__.split('.')[0]
            method_name = f.__qualname__.split('.')[-1]
            try:
                instance = getattr(plugins, class_name)
                if instance and hasattr(instance, method_name):
                    bound_method = getattr(instance, method_name)
                    # Patch the hook_info to store the bound method for future calls
                    if hook_ptr is not None and hook_ptr in self.hooks:
                        on_all, _, is_method_flag = self.hooks[hook_ptr] if len(self.hooks[hook_ptr]) == 3 else (*self.hooks[hook_ptr], False)
                        self.hooks[hook_ptr] = (on_all, bound_method, False)
                    return bound_method
                else:
                    self.logger.error(
                        f"Could not find method {method_name} on instance for {f.__qualname__}")
                    return None
            except AttributeError:
                self.logger.error(
                    f"Could not find instance for class {class_name} from {f.__qualname__}")
                return None
        else:
            return f

    def _syscall_event(self, cpu: int, is_enter: Optional[bool] = None) -> Any:
        """
        ### Handle a syscall event, dispatching to the registered callback

        **Args:**
        - `cpu` (`int`): CPU id.
        - `is_enter` (`Optional[bool]`): True if entry event, False if return event.

        **Returns:**
        `Any`: The result of the callback.
        """
        arg = self.panda.arch.get_arg(cpu, 1, convention="syscall")

        sce, original = self._get_syscall_event(cpu, arg)
        hook_ptr = sce.hook.address
        if hook_ptr not in self.hooks:
            self.logger.error(
                f"Syscall event with hook pointer {hook_ptr:#x} not registered")
            return
        proto = self._get_proto(cpu, sce)

        # Unpack hook information - now includes is_method flag
        hook_info = self.hooks[hook_ptr]
        if len(hook_info) == 3:
            on_all, f, is_method = hook_info
        else:
            # Backward compatibility for old format
            on_all, f = hook_info
            is_method = False
        pt_regs_raw = yield from plugins.kffi.read_type(
            sce.regs.address, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)
        args = None
        if on_all or proto is None or sce.argc == 0:
            args = (pt_regs, proto, sce)
        else:
            sysargs = [sce.args[i] for i in range(sce.argc)]
            args = (pt_regs, proto, sce, *sysargs)

        # Use the new helper to resolve the function to call
        fn_to_call = self._resolve_syscall_callback(f, is_method, hook_ptr)
        result = fn_to_call(*args)
        if isinstance(result, Iterator):
            result = yield from result
        new = sce.to_bytes()
        if original != new:
            yield from plugins.mem.write_bytes(arg, new)
        return result

    def register_syscall_hook(
            self, hook_config: Dict[str, Any]) -> Iterator[int]:
        """
        ### Register a syscall hook with the kernel using the portal

        **Args:**
        - `hook_config` (`Dict[str, Any]`): Hook configuration dictionary.

        **Returns:**
        `Iterator[int]`: Yields the hook pointer.
        """
        # Clone the hook config for internal storage and ensure it has enabled
        # flag
        sch = plugins.kffi.new("syscall_hook")

        sch.enabled = True
        sch.on_enter = hook_config.get("on_enter", False)
        sch.on_return = hook_config.get("on_return", False)
        sch.on_all = hook_config.get("on_all", False)
        sch.enabled = hook_config.get("enabled", True)

        if hook_config.get("name", None):
            name = hook_config.get("name", "")
            to_write = name.encode('latin-1') + b'\0'
            for i, j in enumerate(to_write):
                sch.name[i] = j
        else:
            sch.name[0] = 0
        if hook_config.get("procname", None):
            sch.comm_filter_enabled = True
            # Ensure procname is never None
            procname = hook_config.get("procname", "") or ""
            to_write = procname.encode('latin-1') + b'\0'
            for i, j in enumerate(to_write):
                sch.comm_filter[i] = j
        else:
            sch.comm_filter_enabled = False

        # Handle complex argument filtering
        arg_filters = hook_config.get("arg_filters", [])
        if arg_filters is None:
            arg_filters = []

        for i in range(6):  # IGLOO_SYSCALL_MAXARGS
            if i < len(arg_filters) and arg_filters[i] is not None:
                arg_filter = arg_filters[i]
                if type(arg_filter).__name__ == 'ValueFilter':
                    # Complex filter
                    sch.arg_filters[i].enabled = True
                    sch.arg_filters[i].type = arg_filter.filter_type
                    sch.arg_filters[i].value = arg_filter.value
                    sch.arg_filters[i].min_value = arg_filter.min_value
                    sch.arg_filters[i].max_value = arg_filter.max_value
                    sch.arg_filters[i].bitmask = arg_filter.bitmask
                elif isinstance(arg_filter, (int, float)):
                    # Simple exact match for backward compatibility
                    sch.arg_filters[i].enabled = True
                    sch.arg_filters[i].type = vft.SYSCALLS_HC_FILTER_EXACT
                    sch.arg_filters[i].value = int(arg_filter)
                    sch.arg_filters[i].min_value = 0
                    sch.arg_filters[i].max_value = 0
                    sch.arg_filters[i].bitmask = 0
            else:
                # No filter for this argument
                sch.arg_filters[i].enabled = False
                sch.arg_filters[i].type = vft.SYSCALLS_HC_FILTER_EXACT
                sch.arg_filters[i].value = 0
                sch.arg_filters[i].min_value = 0
                sch.arg_filters[i].max_value = 0
                sch.arg_filters[i].bitmask = 0

        if hook_config.get("pid_filter", None):
            sch.pid_filter_enabled = True
            sch.filter_pid = hook_config.get("pid_filter")
        else:
            sch.pid_filter_enabled = False

        # Handle complex return value filtering
        retval_filter = hook_config.get("retval_filter", None)
        if retval_filter is not None:
            if type(retval_filter).__name__ == 'ValueFilter':
                # Complex filter
                sch.retval_filter.enabled = True
                sch.retval_filter.type = retval_filter.filter_type
                sch.retval_filter.value = retval_filter.value
                sch.retval_filter.min_value = retval_filter.min_value
                sch.retval_filter.max_value = retval_filter.max_value
                sch.retval_filter.bitmask = retval_filter.bitmask
            elif isinstance(retval_filter, (int, float)):
                # Simple exact match for backward compatibility
                sch.retval_filter.enabled = True
                sch.retval_filter.type = vft.SYSCALLS_HC_FILTER_EXACT
                sch.retval_filter.value = int(retval_filter)
                sch.retval_filter.min_value = 0
                sch.retval_filter.max_value = 0
                sch.retval_filter.bitmask = 0
        else:
            sch.retval_filter.enabled = False
            sch.retval_filter.type = vft.SYSCALLS_HC_FILTER_EXACT
            sch.retval_filter.value = 0
            sch.retval_filter.min_value = 0
            sch.retval_filter.max_value = 0
            sch.retval_filter.bitmask = 0

        as_bytes = sch.to_bytes()

        # Send to kernel via portal
        result = yield PortalCmd("register_syscall_hook", size=len(as_bytes), data=as_bytes)
        self.hook_info[result] = hook_config
        return result

    def syscall(
        self,
        name_or_pattern: Optional[str] = None,
        on_enter: Optional[bool] = None,
        on_return: Optional[bool] = None,
        comm_filter: Optional[str] = None,
        arg_filters: Optional[List[Any]] = None,
        pid_filter: Optional[int] = None,
        retval_filter: Optional[Any] = None,
        enabled: bool = True
    ) -> Callable:
        """
        ### Decorator for registering syscall callbacks

        **Args:**
        - `name_or_pattern` (`Optional[str]`): Syscall name or pattern.
        - `on_enter` (`Optional[bool]`): Register for entry events.
        - `on_return` (`Optional[bool]`): Register for return events.
        - `comm_filter` (`Optional[str]`): Process name filter.
        - `arg_filters` (`Optional[List[Any]]`): Argument filters.
        - `pid_filter` (`Optional[int]`): PID filter.
        - `retval_filter` (`Optional[Any]`): Return value filter.
        - `enabled` (`bool`): Whether the hook is enabled.

        **Returns:**
        `Callable`: Decorator function.
        """
        def decorator(func):
            # Parse pattern if provided in the hsyscall format
            syscall_name = ""
            on_all = False
            on_unknown = False
            hook_on_enter = on_enter
            hook_on_return = on_return

            if name_or_pattern and isinstance(name_or_pattern, str):
                # Check if using the hsyscall-style pattern
                if name_or_pattern.startswith("on_"):
                    parts = name_or_pattern.split('_')

                    # Handle different pattern formats
                    if len(parts) >= 3:
                        # Format: on_sys_NAME_enter/return or
                        # on_all/unknown_sys_enter/return
                        if parts[1] == "all" and len(
                                parts) >= 4 and parts[2] == "sys":
                            on_all = True
                            syscall_name = ""
                            hook_on_enter = parts[3] == "enter"
                            hook_on_return = parts[3] == "return"
                        elif parts[1] == "unknown" and len(parts) >= 4 and parts[2] == "sys":
                            on_unknown = True
                            syscall_name = ""
                            hook_on_enter = parts[3] == "enter"
                            hook_on_return = parts[3] == "return"
                        elif parts[1] == "sys" and len(parts) >= 4:
                            # Format: on_sys_NAME_enter/return
                            # Handle case where syscall name itself contains underscores
                            # Last part is enter/return, everything between
                            # "sys" and that is the syscall name
                            last_part = parts[-1]
                            if last_part in ["enter", "return"]:
                                hook_on_enter = last_part == "enter"
                                hook_on_return = last_part == "return"
                                # Combine all middle parts for the syscall name
                                syscall_name = "_".join(parts[2:-1])
                            else:
                                # If it doesn't end with enter/return, treat
                                # the whole thing as name_enter
                                syscall_name = "_".join(parts[2:])
                                hook_on_enter = True
                                hook_on_return = False
                    else:
                        # Fallback to treating the input as a syscall name
                        syscall_name = name_or_pattern
                else:
                    # If it doesn't start with on_, treat it as a syscall name
                    syscall_name = name_or_pattern
            else:
                # Use the provided values for name, on_enter, on_return
                syscall_name = name_or_pattern if name_or_pattern else ""
                if syscall_name == "all":
                    on_all = True
                    syscall_name = ""
                elif syscall_name == "unknown":
                    on_unknown = True
                    syscall_name = ""

            # Ensure at least one of hook_on_enter or hook_on_return is True
            if not (hook_on_enter or hook_on_return):
                hook_on_enter = True  # Default to entry if neither is specified

            # Detect if this is a method by checking if it has __self__ (bound method)
            # or if it's being called on a class (unbound method during class
            # definition)
            is_method = hasattr(func, '__self__') or (
                hasattr(func, '__qualname__') and '.' in func.__qualname__)

            # Create hook configuration
            hook_config = {
                "name": syscall_name,
                "on_enter": hook_on_enter,
                "on_return": hook_on_return,
                "on_all": on_all,
                "on_unknown": on_unknown,
                "procname": comm_filter,  # Use comm_filter instead of procname
                "arg_filters": arg_filters,  # Now supports complex filtering
                "enabled": enabled,
                "callback": func,
                "pid_filter": pid_filter,
                "retval_filter": retval_filter,  # Now supports complex filtering
                "is_method": is_method,  # Store method detection result
            }
            # Add to pending hooks and queue interrupt
            self._pending_hooks.append((hook_config, func))
            self.portal.queue_interrupt("syscalls")
            return func

        return decorator

    def disable_syscall(self, callback_or_name: Any) -> Iterator[bool]:
        """
        ### Disables a registered syscall hook

        **Args:**
        - `callback_or_name` (`Any`): The callback function or its name to disable.

        **Returns:**
        `Iterator[bool]`: Yields True if hook was found and disabled, False otherwise.
        """
        hook_ptr = None

        # Check if we got a function object
        if callable(callback_or_name):
            # First try direct lookup
            if callback_or_name in self._func_to_hook_ptr:
                hook_ptr = self._func_to_hook_ptr[callback_or_name]
            else:
                # Try to find by function name
                func_name = callback_or_name.__name__ if hasattr(
                    callback_or_name, "__name__") else None
                if func_name and func_name in self._name_to_hook_ptr:
                    hook_ptr = self._name_to_hook_ptr[func_name]
                else:
                    # Try to find by function in callbacks
                    for ptr, hook_info in self.hooks.items():
                        func = hook_info[1] if len(hook_info) >= 2 else None
                        if func == callback_or_name:
                            hook_ptr = ptr
                            break

        # Check if we got a string (function name)
        elif isinstance(callback_or_name, str):
            if callback_or_name in self._name_to_hook_ptr:
                hook_ptr = self._name_to_hook_ptr[callback_or_name]
            else:
                # Try to find by scanning all registered callbacks
                for ptr, hook_info in self.hooks.items():
                    func = hook_info[1] if len(hook_info) >= 2 else None
                    if func and hasattr(
                            func, "__name__") and func.__name__ == callback_or_name:
                        hook_ptr = ptr
                        break

        # If we found the hook, disable it
        if hook_ptr and hook_ptr in self.hooks:
            # Create disable command
            disable_cmd = plugins.kffi.new("syscall_disable_cmd")
            disable_cmd.hook = hook_ptr
            disable_cmd.enable = False

            # Send to kernel via portal
            cmd_bytes = disable_cmd.to_bytes()
            result = yield PortalCmd("syscall_enable", size=len(cmd_bytes), data=cmd_bytes)

            if result:
                self.logger.debug(
                    f"Successfully disabled syscall hook: {hook_ptr:#x}")
                return True
            else:
                self.logger.warning(
                    f"Failed to disable syscall hook: {hook_ptr:#x}")
                return False
        else:
            self.logger.warning(
                f"Syscall hook not found for {callback_or_name}")
            return False

    def enable_syscall(self, callback_or_name: Any) -> Iterator[bool]:
        """
        ### Enables a previously disabled syscall hook

        **Args:**
        - `callback_or_name` (`Any`): The callback function or its name to enable.

        **Returns:**
        `Iterator[bool]`: Yields True if hook was found and enabled, False otherwise.
        """
        hook_ptr = None

        # Check if we got a function object
        if callable(callback_or_name):
            # First try direct lookup
            if callback_or_name in self._func_to_hook_ptr:
                hook_ptr = self._func_to_hook_ptr[callback_or_name]
            else:
                # Try to find by function name
                func_name = callback_or_name.__name__ if hasattr(
                    callback_or_name, "__name__") else None
                if func_name and func_name in self._name_to_hook_ptr:
                    hook_ptr = self._name_to_hook_ptr[func_name]
                else:
                    # Try to find by function in callbacks
                    for ptr, hook_info in self.hooks.items():
                        func = hook_info[1] if len(hook_info) >= 2 else None
                        if func == callback_or_name:
                            hook_ptr = ptr
                            break

        # Check if we got a string (function name)
        elif isinstance(callback_or_name, str):
            if callback_or_name in self._name_to_hook_ptr:
                hook_ptr = self._name_to_hook_ptr[callback_or_name]
            else:
                # Try to find by scanning all registered callbacks
                for ptr, hook_info in self.hooks.items():
                    func = hook_info[1] if len(hook_info) >= 2 else None
                    if func and hasattr(
                            func, "__name__") and func.__name__ == callback_or_name:
                        hook_ptr = ptr
                        break

        # If we found the hook, enable it
        if hook_ptr and hook_ptr in self.hooks:
            # Create enable command
            enable_cmd = plugins.kffi.new("syscall_disable_cmd")
            enable_cmd.hook = hook_ptr
            enable_cmd.enable = True

            # Send to kernel via portal
            cmd_bytes = enable_cmd.to_bytes()
            result = yield PortalCmd("syscall_enable", size=len(cmd_bytes), data=cmd_bytes)

            if result:
                self.logger.debug(
                    f"Successfully enabled syscall hook: {hook_ptr:#x}")
                return True
            else:
                self.logger.warning(
                    f"Failed to enable syscall hook: {hook_ptr:#x}")
                return False
        else:
            self.logger.warning(
                f"Syscall hook not found for {callback_or_name}")
            return False

    def get_syscall_info_by_name(
            self, name: str) -> Optional[SyscallPrototype]:
        """
        ### Look up syscall prototype information by name

        Automatically cleans the name.

        **Args:**
        - `name` (`str`): The syscall name (may include prefixes or architecture-specific parts).

        **Returns:**
        `Optional[SyscallPrototype]`: The prototype information if found, else None.
        """
        clean_name = self._clean_syscall_name(name)
        return self.syscall_info_table.get(clean_name)
