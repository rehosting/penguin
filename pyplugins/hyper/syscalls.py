from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
import json
from typing import Dict, List, Any
from hyper.consts import *

SYSCALL_HC_KNOWN_MAGIC = 0x1234


class SyscallPrototype:
    """Represents syscall metadata"""

    def __init__(self, name, args=None, unknown_args=False):
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

    def __repr__(self):
        return f"<SyscallPrototype name='{self.name}' nargs={self.nargs}>"


class Syscalls(PyPlugin):
    """
    Plugin that provides an interface to monitor and intercept system calls.
    Uses the portal's interrupt mechanism to handle registration.
    """

    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.syscalls")
        # if self.get_arg_bool("verbose"):
        # self.logger.setLevel("DEBUG")

        # Map hook_ids to callbacks
        self.hooks: Dict[int, Dict[str, Any]] = {}
        self.hook_id_counter = 1

        # Get portal plugin
        self.portal = plugins.portal

        # Syscall type information - using dictionary for fast name-based lookups
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
        self.panda.hypercall(IGLOO_HYP_SETUP_SYSCALL)(
            self._setup_syscall_handler)

        # Register syscall enter/return hypercalls
        self.panda.hypercall(IGLOO_HYP_SYSCALL_ENTER)(
            self._syscall_enter_event)
        self.panda.hypercall(IGLOO_HYP_SYSCALL_RETURN)(
            self._syscall_return_event)

        # Add a queue for pending hook registrations
        self._pending_hooks = []

    def _setup_syscall_handler(self, cpu):
        """Handler for setting up syscall definitions"""
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

    def _clean_syscall_name(self, name):
        """
        Clean a syscall name by removing various prefixes:
        1. First remove 'sys_' prefix
        2. Then remove any leading underscores
        3. Then remove architecture-specific prefixes
        """
        if name.startswith("compat_"):
            name = name[7:]
        # First remove sys_ prefix if present
        if name.startswith("sys_"):
            name = name[4:]

        # Then remove any remaining leading underscores
        name = name.lstrip("_")

        return name

    def _syscall_interrupt_handler(self):
        """
        Handle interrupts from the portal for syscall hook registration.
        This function processes one pending syscall hook registration item.

        Returns:
            bool: True if more hooks are pending, False otherwise
        """
        # Always ensure we yield at least once so the function returns a proper generator
        if not self._pending_hooks:
            self.logger.debug("No pending syscall hooks to register")
            # Yield a no-op operation to ensure this is always an iterator
            return False

        pending_hooks = self._pending_hooks[:]

        while pending_hooks:
            # Take one item from the queue
            hook_config, func = pending_hooks.pop(0)

            # Register the syscall hook
            hook_id = yield from self.register_syscall_hook(hook_config)
            on_all = hook_config.get("on_all", False)
            self.hooks[hook_id] = (on_all, func)

    def _syscall_enter_event(self, cpu):
        """
        Handler for syscall entry events from the hypervisor.
        """
        self._syscall_event(cpu, is_enter=True)

    def _syscall_return_event(self, cpu):
        """
        Handler for syscall return events from the hypervisor.
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

    def _get_syscall_event(self, cpu, sequence, arg):
        saved_sce_info = self.saved_syscall_events.get(cpu, None)
        if saved_sce_info:
            saved_sc, saved_sequence, original = saved_sce_info
            if saved_sequence == sequence:
                return saved_sc, original
        sce = plugins.kffi.read_type_panda(cpu, arg, "syscall_event")
        sce.name = bytes(sce.syscall_name).decode("latin-1").rstrip("\x00")
        original = sce.to_bytes()[:]
        self.saved_syscall_events[cpu] = (sce, sequence, original)
        return sce, original

    def _get_proto(self, cpu, sce):
        # Get syscall name from the event
        name = sce.name
        # Clean the syscall name
        cleaned_name = self._clean_syscall_name(name)

        # Look up the prototype by cleaned name directly using hash table (O(1) lookup)
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

    def _syscall_event(self, cpu, is_enter=None):
        sequence = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        arg = self.panda.arch.get_arg(cpu, 2, convention="syscall")

        sce, original = self._get_syscall_event(cpu, sequence, arg)
        id_ = sce.id
        if id_ not in self.hooks:
            self.logger.debug(f"Syscall event {id_} not registered")
            return
        proto = self._get_proto(cpu, sce)

        on_all, f = self.hooks[id_]

        # If we're handling all syscalls or we don't have prototype info,
        # just call the function with the standard arguments
        if on_all or proto is None or sce.argc == 0:
            f(cpu, proto, sce)
        else:
            sysargs = [sce.args[i] for i in range(sce.argc)]
            # Call the function with standard arguments plus syscall arguments
            f(cpu, proto, sce, *sysargs)

        new = sce.to_bytes()
        if original != new:
            self.panda.virtual_memory_write(cpu, arg, new)

    def register_syscall_hook(self, hook_config):
        """
        Register a syscall hook with the kernel using the portal.
        """
        # Clone the hook config for internal storage and ensure it has enabled flag
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
        if hook_config.get("filter_args", None):
            sch.filter_args_enabled = True
            for i, arg in enumerate(hook_config.get("filter_args", [])):
                if arg is None:
                    sch.filter_arg[i] = False
                else:
                    sch.filter_arg[i] = True
                    sch.arg_filter[i] = arg
        else:
            sch.filter_args_enabled = False

        if hook_config.get("pid_filter", None):
            sch.pid_filter_enabled = True
            sch.pid_filter = hook_config.get("pid_filter")
        else:
            sch.pid_filter_enabled = False

        as_bytes = sch.to_bytes()

        # Send to kernel via portal
        result = yield ("syscall_reg", as_bytes)
        self.hook_info[result] = hook_config
        return result

    def syscall(self, name_or_pattern=None, enter=None, return_val=None,
                comm_filter=None, arg_filter=None, pid_filter=None, enabled=True):
        """
        Decorator for registering syscall callbacks.

        Args:
            name_or_pattern: Either a syscall name (e.g., "open", "read") or a pattern
                            like "on_sys_write_enter", "on_all_sys_return", etc.
                            If a pattern is provided, other arguments like enter/return_val are ignored.
            enter: True to call on syscall entry (ignored if pattern is used)
            return_val: True to call on syscall return (ignored if pattern is used)
            comm_filter: Process name filter
            arg_filter: List of argument values to filter on
            enabled: Whether the hook is enabled initially

        Returns:
            Decorator function
        """
        def decorator(func):
            # Parse pattern if provided in the hsyscall format
            syscall_name = ""
            on_all = False
            on_unknown = False
            on_enter = enter
            on_return = return_val

            if name_or_pattern and isinstance(name_or_pattern, str):
                # Check if using the hsyscall-style pattern
                if name_or_pattern.startswith("on_"):
                    parts = name_or_pattern.split('_')

                    # Handle different pattern formats
                    if len(parts) >= 3:
                        # Format: on_sys_NAME_enter/return or on_all/unknown_sys_enter/return
                        if parts[1] == "all" and len(parts) >= 4 and parts[2] == "sys":
                            on_all = True
                            syscall_name = ""
                            on_enter = parts[3] == "enter"
                            on_return = parts[3] == "return"
                        elif parts[1] == "unknown" and len(parts) >= 4 and parts[2] == "sys":
                            on_unknown = True
                            syscall_name = ""
                            on_enter = parts[3] == "enter"
                            on_return = parts[3] == "return"
                        elif parts[1] == "sys" and len(parts) >= 4:
                            # Format: on_sys_NAME_enter/return
                            # Handle case where syscall name itself contains underscores
                            # Last part is enter/return, everything between "sys" and that is the syscall name
                            last_part = parts[-1]
                            if last_part in ["enter", "return"]:
                                on_enter = last_part == "enter"
                                on_return = last_part == "return"
                                # Combine all middle parts for the syscall name
                                syscall_name = "_".join(parts[2:-1])
                            else:
                                # If it doesn't end with enter/return, treat the whole thing as name_enter
                                syscall_name = "_".join(parts[2:])
                                on_enter = True
                                on_return = False
                    else:
                        # Fallback to treating the input as a syscall name
                        syscall_name = name_or_pattern
                else:
                    # If it doesn't start with on_, treat it as a syscall name
                    syscall_name = name_or_pattern
            else:
                # Use the provided values for name, enter, return_val
                syscall_name = name_or_pattern if name_or_pattern else ""
                if syscall_name == "all":
                    on_all = True
                    syscall_name = ""
                elif syscall_name == "unknown":
                    on_unknown = True
                    syscall_name = ""

            # Ensure at least one of on_enter or on_return is True
            if not (on_enter or on_return):
                on_enter = True  # Default to entry if neither is specified

            # Create hook configuration
            hook_config = {
                "name": syscall_name,
                "on_enter": on_enter,
                "on_return": on_return,
                "on_all": on_all,
                "on_unknown": on_unknown,
                "procname": comm_filter,  # Use comm_filter instead of procname
                "filter_args": arg_filter,
                "enabled": enabled,
                "callback": func,
                "pid_filter": pid_filter,
            }
            # Add to pending hooks and queue interrupt
            self._pending_hooks.append((hook_config, func))
            self.portal.queue_interrupt("syscalls")
            return func

        return decorator
