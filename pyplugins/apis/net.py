from penguin import Plugin, plugins
from typing import Optional, List, Iterator, Generator, Set, Dict
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop


class Netdevs(Plugin):
    def __init__(self):
        self._pending_netdevs = []
        self._netdevs = {}
        self._netdev_structs = {}  # name -> net_device pointer
        self._exist_ok = {}  # name -> bool

        self._netdev_ops = self._build_netdev_ops_lookup()
        plugins.portal.register_interrupt_handler(
            "netdevs", self._netdevs_interrupt_handler)

        netdevs = self.get_arg("conf").get("netdevs", [])
        for nd in netdevs:
            self.register_netdev(nd)

        # self.panda.hypercall(iconsts.IGLOO_NET_SETUP)(plugins.portal.wrap(self._net_setup))
        self._packet_queue = []  # List of (name, buf)

    def _is_function_pointer(self, attr) -> bool:
        """Check if an attribute is a function pointer."""
        return (hasattr(attr, "_subtype_info") and
                attr._subtype_info.get("kind") == "function")

    def _get_ops_functions(self, struct_name: str) -> Dict[str, Optional[str]]:
        """
        Inspect a top-level struct (eg. "net_device") and return a mapping:
        - function_name -> None            (direct function pointer on top-level struct)
        - function_name -> 'ops_struct'    (function pointer belonging to an ops struct)
        """
        lookup: Dict[str, Optional[str]] = {}
        try:
            sample = plugins.kffi.new(struct_name)
        except Exception as e:
            self.logger.debug(f"Failed to instantiate {struct_name}: {e}")
            return lookup

        # Collect top-level function pointers
        top_funcs: Set[str] = set()
        seen_ops: Set[str] = set()

        for mem in dir(sample):
            if mem.startswith("_") or not hasattr(sample, mem):
                continue
            try:
                attr = getattr(sample, mem)
            except Exception:
                continue

            # Direct function pointer on the top-level struct
            if self._is_function_pointer(attr):
                top_funcs.add(mem)
                continue

            # Try to determine if this member points to an *_ops struct
            attr_type_str = str(type(attr))
            ops_struct_name = None

            # Prefer attribute name if it ends with _ops (common pattern)
            if mem.endswith("_ops"):
                ops_struct_name = mem
            else:
                # Fallback: try to extract from the type string
                ops_struct_name = self._extract_ops_struct_name(attr_type_str)

            if not ops_struct_name or ops_struct_name in seen_ops:
                continue

            # Instantiate the ops struct and enumerate its function pointers
            try:
                ops_sample = plugins.kffi.new(ops_struct_name)
            except Exception:
                # Could not instantiate this ops struct; skip it
                continue

            funcs: Set[str] = set()
            for of in dir(ops_sample):
                if of.startswith("_") or not hasattr(ops_sample, of):
                    continue
                try:
                    ofattr = getattr(ops_sample, of)
                except Exception:
                    continue
                if self._is_function_pointer(ofattr):
                    funcs.add(of)

            if funcs:
                for f in funcs:
                    lookup[f] = ops_struct_name
                seen_ops.add(ops_struct_name)

        # Finally map top-level functions to None
        for f in top_funcs:
            lookup[f] = None

        return lookup

    def _build_netdev_ops_lookup(self) -> Dict[str, Optional[str]]:
        """
        Build a lookup mapping function_name -> ops_struct_name (or None) by inspecting
        the top-level 'net_device' structure and its *_ops sub-structures.
        """
        try:
            return self._get_ops_functions("net_device")
        except Exception as e:
            self.logger.debug(f"Failed to build netdev ops lookup: {e}")
            return {}

    def _extract_ops_struct_name(self, attr_str: str) -> Optional[str]:
        """Extract ops struct name from type string."""
        import re
        match = re.search(r'(\w*_ops)', attr_str)
        return match.group(1) if match else None

    def _net_setup(self, name, dev_ptr):
        netdev_class = self._netdevs.get(name, self._netdevs.get("*", None))
        if netdev_class is None:
            return
        netdev = yield from plugins.kffi.read_type(dev_ptr, "net_device")

        if hasattr(netdev_class, "setup"):
            fn_ret = netdev_class.setup(name, netdev)
            if isinstance(fn_ret, Iterator):
                fn_ret = yield from fn_ret

    def lookup_netdev(self, name: str) -> Generator[PortalCmd, Optional[int], Optional[int]]:
        """
        Look up a network device by name using the portal.
        Returns the pointer to net_device struct or None if not found.
        """
        buf = name.encode("latin-1", errors="ignore") + b"\0"
        result = yield PortalCmd(hop.HYPER_OP_NETDEV_LOOKUP, 0, len(buf), None, buf)
        if result == 0 or result is None:
            self.logger.debug(f"Netdev '{name}' not found (kernel returned 0)")
            return None
        self.logger.debug(f"Netdev '{name}' found at {result:#x}")
        return result

    def register_netdev(self, name: str, backing_class: Optional[Plugin] = None, exist_ok: bool = False):
        '''
        Register a network device with the given name.
        '''
        if name not in self._netdevs and name not in self._pending_netdevs:
            plugins.portal.queue_interrupt("netdevs")
            if name != "*":
                self._pending_netdevs.append(name)
        self._exist_ok[name] = exist_ok
        if backing_class:
            self._netdevs[name] = backing_class

    def _register_netdevs(self, names: List[str]) -> Iterator[int]:
        """
        Build a NUL-terminated buffer of interface names and send to kernel.
        New portal implementation registers a single device per hypercall and
        returns a non-zero pointer on success (or zero/False on failure).
        Call the hypercall once per name and return the number of successful
        registrations.
        """
        # New implementation: kernel returns pointer to net_device struct on success, 0/null on failure
        if not names:
            return 0

        for name in names:
            buf = name.encode("latin-1", errors="ignore") + b"\0"
            result = yield PortalCmd(hop.HYPER_OP_NETDEV_REGISTER, 0, len(buf), None, buf)
            is_up = yield from self.set_netdev_state(name, True)
            if not is_up:
                self.logger.error(f"Failed to set netdev '{name}' UP state")

            if result == 0 or result is None:
                if self._exist_ok.get(name, False) or self._exist_ok.get("*", False):
                    result = yield from self.lookup_netdev(name)
                    if result == 0 or result is None:
                        self.logger.error(f"Failed to register or look up '{name}'")
                        return
                else:
                    self.logger.error(f"Failed to register netdev '{name}' (kernel returned 0)")
                    return
            self._netdev_structs[name] = result
            yield from self._net_setup(name, result)

    def _netdevs_interrupt_handler(self) -> Iterator[bool]:
        """
        Process pending network device registrations and queued packet sends.
        """
        # Process pending network device registrations. Generator-style like _uprobe_interrupt_handler.
        # Processes each pending (name, backing_class) and attempts kernel registration.
        if not self._pending_netdevs:
            return False

        pending = self._pending_netdevs[:]

        while pending:
            name = pending.pop(0)
            yield from self._register_netdevs([name])
            self._pending_netdevs.remove(name)

        # No more pending registrations or packets
        return False

    def set_netdev_state(self, name: str, up: bool) -> Generator[PortalCmd, Optional[int], Optional[bool]]:
        """
        Set the state (up/down) of a network device.
        Returns True if successful, False otherwise.
        """
        buf = name.encode("latin-1", errors="ignore") + b"\0"
        requested_state = 1 if up else 0
        result = yield PortalCmd(hop.HYPER_OP_NETDEV_SET_STATE, 0, requested_state, None, buf)
        if result == requested_state:
            self.logger.debug(f"Netdev '{name}' state set to {requested_state}")
            return True
        else:
            self.logger.error(f"Failed to set netdev '{name}' state to {requested_state}")
            return False

    def get_netdev_state(self, name: str) -> Generator[PortalCmd, Optional[int], Optional[bool]]:
        """
        Get the state (up/down) of a network device.
        Returns True if up, False if down, or None if not found.
        """
        buf = name.encode("latin-1", errors="ignore") + b"\0"
        result = yield PortalCmd(hop.HYPER_OP_NETDEV_GET_STATE, 0, len(buf), None, buf)
        if result is None:
            self.logger.error(f"Failed to get state for netdev '{name}'")
            return None
        state = bool(result)
        self.logger.debug(f"Netdev '{name}' state is {'up' if state else 'down'}")
        return state
