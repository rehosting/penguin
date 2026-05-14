from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop
from typing import List, Dict, Generator, Optional, Tuple
# Assuming SysctlFile is added to base models to mirror ProcFile
from hyperfile.models.base import SysctlFile


class Sysctl(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self._pending_sysctls: List[Tuple[str, SysctlFile]] = []
        self._sysctls: Dict[str, SysctlFile] = {}
        plugins.portal.register_interrupt_handler(
            "sysctl", self._sysctl_interrupt_handler)

    def _get_custom_handler(self, sysctl_file: SysctlFile):
        """
        Check if the user overrode the default proc_handler.
        Returns a generator for the KFFI callback pointer if overridden, else None.
        """
        base = SysctlFile
        meth = getattr(sysctl_file, "proc_handler", None)
        base_meth = getattr(base, "proc_handler", None)

        # Use __code__ to compare function implementations
        if (
            meth is not None and base_meth is not None
            and hasattr(meth, "__code__") and hasattr(base_meth, "__code__")
            and meth.__code__ is not base_meth.__code__
        ):
            kffi = plugins.kffi
            ctl_table_type = kffi.ffi.get_type("struct ctl_table")
            op_signature = None

            if ctl_table_type and hasattr(ctl_table_type, "fields") and "proc_handler" in ctl_table_type.fields:
                member_type = ctl_table_type.fields["proc_handler"].type_info

                # Function pointers are stored as pointers to functions.
                # We must unwrap the pointer layer so kffi sees the raw function signature.
                if member_type and member_type.get("kind") == "pointer":
                    op_signature = member_type.get("subtype")
                else:
                    op_signature = member_type

            return kffi.callback(meth, func_type=op_signature)
        return None

    def register(self, sysctl_file: SysctlFile, path: Optional[str] = None):
        return self.register_sysctl(sysctl_file, path)

    def register_sysctl(self, sysctl_file: SysctlFile, path: Optional[str] = None):
        """
        Register a SysctlFile for later portal registration.
        """
        raw_path = path if path else getattr(sysctl_file, "PATH", None)
        if not raw_path:
            raise ValueError("SysctlFile must define PATH or define it in register_sysctl")
        sysctl_file.PATH = raw_path
        plugins.netdevs.ensure_netdev_from_path(sysctl_file.full_path)

        fname = sysctl_file.fs_relative_path

        # ENFORCE SINGLE REGISTRATION
        if fname in self._sysctls:
            raise ValueError(
                f"Cannot register '{fname}': A sysctl is already registered at this path.")

        # Add to interrupt queue
        # Check against tuple (fname, sysctl_file)
        if not any(f == fname for f, _ in self._pending_sysctls):
            plugins.portal.queue_interrupt("sysctl")
            self._pending_sysctls.append((fname, sysctl_file))
        self._sysctls[fname] = sysctl_file

    def _split_sysctl_path(self, path: str):
        """
        Split a sysctl path into (dir_path, entry_name).
        If no directory, dir_path is '' (root).
        """
        path = path.strip("/")
        if "/" in path:
            parent, fname = path.rsplit("/", 1)
            return parent, fname
        else:
            return "", path

    def _is_customized(self, sysctl_file: SysctlFile) -> bool:
        base = SysctlFile
        # Check if any of the three logic points are overridden
        for name in ["read", "write", "proc_handler"]:
            meth = getattr(sysctl_file, name, None)
            base_meth = getattr(base, name, None)
            if meth and base_meth and meth.__code__ is not base_meth.__code__:
                return True
        return False

    def _register_sysctls(self, sysctls: List[Tuple[str, SysctlFile]]) -> Generator[int, None, None]:
        # Calculate the offset of sysctl_entry in proc_inode relative to vfs_inode
        # This is used by the driver for safe VFS-based mutation.
        kffi = plugins.kffi
        proc_inode_type = kffi.ffi.get_type("struct proc_inode")
        sysctl_entry_offset = 0
        if proc_inode_type and "sysctl_entry" in proc_inode_type.fields and "vfs_inode" in proc_inode_type.fields:
            sysctl_entry_offset = proc_inode_type.fields["sysctl_entry"].offset - proc_inode_type.fields["vfs_inode"].offset
        for fname, sysctl_file in sysctls:
            dir_path, entry_name = self._split_sysctl_path(fname)

            # If any VFS-style or raw handler is present, we use the unified handler
            handler_ptr = 0
            if self._is_customized(sysctl_file):
                # Look up the struct ctl_table definition in dwarffi
                ctl_table_type = kffi.ffi.get_type("struct ctl_table")
                op_signature = None

                # Dynamically extract the proc_handler signature to ensure correct argument packing
                if ctl_table_type and hasattr(ctl_table_type, "fields") and "proc_handler" in ctl_table_type.fields:
                    member_type = ctl_table_type.fields["proc_handler"].type_info

                    if member_type and member_type.get("kind") == "pointer":
                        op_signature = member_type.get("subtype")
                    else:
                        op_signature = member_type

                # We always wrap the unified proc_handler entry point using the discovered signature
                handler_ptr = yield from kffi.callback(sysctl_file.proc_handler, func_type=op_signature)

            init_data = {
                "dir_path": dir_path.encode("latin-1", errors="ignore"),
                "entry_name": entry_name.encode("latin-1", errors="ignore"),
                "initial_value": getattr(sysctl_file, "INITIAL_VALUE", ""),
                "mode": getattr(sysctl_file, "MODE", 0o644),
                "maxlen": getattr(sysctl_file, "MAXLEN", 256),
                "handler": handler_ptr,
                "sysctl_entry_offset": sysctl_entry_offset
            }

            req = kffi.new("struct portal_sysctl_create_req", init_data)
            req_bytes = bytes(req)

            result = yield PortalCmd(
                hop.HYPER_OP_SYSCTL_CREATE_FILE,
                0,
                len(req_bytes),
                None,
                req_bytes
            )

            # Since we now return HYPER_RESP_READ_NUM, result will be > 0 on success
            if result is None or result <= 0:
                self.logger.error(f"Failed to register sysctl '{fname}'")
                continue
            self.logger.debug(
                f"Registered sysctl '{fname}' with kernel (id={result})")

    def _sysctl_interrupt_handler(self) -> Generator[bool, None, bool]:
        """
        Process pending sysctl registrations.
        """
        # Ensure pending network devices are registered first so that dynamic
        # interfaces (like br0) create their native sysctls before we try to mutate/create them.
        if getattr(plugins, "netdevs", None) and plugins.netdevs._pending_netdevs:
            yield from plugins.netdevs._netdevs_interrupt_handler()

        if not self._pending_sysctls:
            return False

        pending = self._pending_sysctls[:]
        while pending:
            sysctl_node = pending.pop(0)
            yield from self._register_sysctls([sysctl_node])
            self._pending_sysctls.remove(sysctl_node)
        return False
