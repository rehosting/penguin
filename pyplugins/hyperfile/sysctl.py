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

        # Snapshot restore: {fname -> [tramp_id, tramp_addr]} for the custom
        # proc_handler wired into each guest sysctl node. The node survives
        # savevm but the host tramp_id->callback map is lost on a cross-process
        # -loadvm; on restore we re-bind rather than re-create (re-creating would
        # double-register at the guest, and the install drain never runs on a
        # -loadvm boot anyway). Only customized sysctls have a handler.
        self._ops_tramps: Dict[str, list] = {}
        self._restored_ops_tramps: Dict[str, list] = {}

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

    def _proc_handler_signature(self):
        """Extract the DWARF signature for ctl_table.proc_handler (the subtype
        behind the function-pointer member), or None. Pure metadata lookup -- no
        guest I/O -- so it is safe to call from on_restore."""
        ctl_table_type = plugins.kffi.ffi.get_type("struct ctl_table")
        if not (ctl_table_type and hasattr(ctl_table_type, "fields")
                and "proc_handler" in ctl_table_type.fields):
            return None
        member_type = ctl_table_type.fields["proc_handler"].type_info
        if member_type and member_type.get("kind") == "pointer":
            return member_type.get("subtype")
        return member_type

    def _rebind_ops(self, fname: str, sysctl_file: SysctlFile) -> bool:
        """Re-bind a surviving sysctl node's custom proc_handler after a restore.
        Returns True if the node had a persisted trampoline and was re-bound."""
        tramp = self._restored_ops_tramps.pop(fname, None)
        if not tramp:
            return False
        tid, taddr = tramp
        plugins.kffi.rebind_callback(
            sysctl_file.proc_handler, tid, taddr,
            func_type=self._proc_handler_signature())
        self._ops_tramps[fname] = tramp  # keep for a subsequent re-save
        self.logger.info(
            f"Re-bound sysctl '{fname}' proc_handler to the surviving guest node "
            "after snapshot restore (no re-create)")
        return True

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

        # Reject paths that cannot be safely registered as sysctls. These mostly
        # come from auto-generated pseudofile models that scrape binary strings
        # and emit bogus /proc/sys/* entries. Registering them is at best useless
        # and at worst fatal: on older guest kernels (e.g. 4.10) asking the kernel
        # to create a ctl_table under a filesystem-backed node such as
        # /proc/sys/fs/binfmt_misc fails and then panics in the registration
        # cleanup path. Skip them here rather than handing them to the guest; the
        # igloo driver enforces the same invariant as a backstop.
        reason = self._reject_reason(fname)
        if reason is not None:
            self.logger.warning(
                f"Skipping sysctl registration for '{fname}': {reason}")
            return

        # ENFORCE SINGLE REGISTRATION
        if fname in self._sysctls:
            raise ValueError(
                f"Cannot register '{fname}': A sysctl is already registered at this path.")

        self._sysctls[fname] = sysctl_file

        # Restore fast-path: the guest node for this sysctl survived the snapshot,
        # so re-installing it would double-register at the guest (and the install
        # drain never runs on a -loadvm boot anyway). If a custom handler for this
        # path was captured before the snapshot, just re-bind it and skip the
        # queue. Covers owners that re-register after load_state (e.g. from a
        # hypercall handler this boot won't re-fire, like core_pattern_guard).
        if fname in self._restored_ops_tramps:
            self._rebind_ops(fname, sysctl_file)
            return

        # Add to interrupt queue
        # Check against tuple (fname, sysctl_file)
        if not any(f == fname for f, _ in self._pending_sysctls):
            plugins.portal.queue_interrupt("sysctl")
            self._pending_sysctls.append((fname, sysctl_file))

    # Subtrees of /proc/sys that are not sysctls at all but separate
    # filesystems mounted there (binfmt_misc is the canonical example). The
    # guest kernel will not let us register a ctl_table inside them, and on old
    # kernels the failed attempt panics. Modeling them as sysctls is always wrong.
    _NON_SYSCTL_SUBTREES = ("fs/binfmt_misc",)

    def _reject_reason(self, fname: str) -> Optional[str]:
        """
        Return a human-readable reason if ``fname`` (a sysctl-root-relative path
        such as ``net/ipv4/ip_forward``) must not be registered as a sysctl, or
        None if it is acceptable.
        """
        rel = fname.strip("/")
        if not rel:
            return "empty sysctl path"
        components = rel.split("/")
        if any(c == "" for c in components):
            # e.g. an embedded "//" produces an empty path component, which the
            # kernel cannot turn into a ctl_dir.
            return "path contains an empty component"
        for subtree in self._NON_SYSCTL_SUBTREES:
            if rel == subtree or rel.startswith(subtree + "/"):
                return f"/proc/sys/{subtree} is a mounted filesystem, not a sysctl"
        return None

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
                # We always wrap the unified proc_handler entry point using the
                # discovered signature so argument packing is correct.
                handler_ptr = yield from kffi.callback(
                    sysctl_file.proc_handler,
                    func_type=self._proc_handler_signature())

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
            # Record the custom proc_handler trampoline now that it's wired, so a
            # later snapshot restore can re-bind it to the surviving guest node.
            if self._is_customized(sysctl_file):
                fn = sysctl_file.proc_handler
                tid = kffi.get_callback_id(fn)
                taddr = kffi._tramp_addresses.get(fn)
                if tid is not None and taddr is not None:
                    self._ops_tramps[fname] = [int(tid), int(taddr)]

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

        # Honor the portal's per-window install budget (see portal docstring).
        while self._pending_sysctls and plugins.portal.take_install_budget():
            sysctl_node = self._pending_sysctls.pop(0)
            yield from self._register_sysctls([sysctl_node])
        if self._pending_sysctls:
            plugins.portal.queue_interrupt("sysctl")
        return False

    # --- snapshot / restore ------------------------------------------------ #
    def save_state(self):
        """Persist the per-sysctl custom-handler trampolines so a restore can
        re-bind the surviving guest nodes. The SysctlFile objects and their
        proc_handlers are re-created by their owners on the restore boot; only
        the guest ids/addrs need carrying. Returns None when nothing custom is
        registered."""
        return {"ops_tramps": self._ops_tramps} if self._ops_tramps else None

    def load_state(self, data) -> None:
        """Phase one: stash the saved trampoline map. Re-binding happens in
        on_restore (owners that re-register in __init__) and in register_sysctl
        (owners that re-register later, e.g. core_pattern_guard from a hypercall
        handler this boot won't re-fire)."""
        if not data:
            return
        self._restored_ops_tramps = {
            fname: list(v) for fname, v in data.get("ops_tramps", {}).items()
        }

    def on_restore(self, tag: str) -> None:
        """Re-bind every already-registered sysctl (owners that re-registered in
        their __init__) to its surviving guest node. Sysctls whose owner
        re-registers later are handled inline by register_sysctl."""
        for fname, sysctl_file in list(self._sysctls.items()):
            if fname in self._restored_ops_tramps:
                self._rebind_ops(fname, sysctl_file)
