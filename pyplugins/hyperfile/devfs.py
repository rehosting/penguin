from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop
from typing import List, Dict, Generator, Optional, Tuple
from hyperfile.models.base import DevFile


class Devfs(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self._pending_devfs: List[Tuple[str, DevFile, int, int]] = []
        self._devfs: Dict[str, DevFile] = {}

        # Cache for directory IDs (path -> id). Root "" is ID 0.
        self._dev_dirs: Dict[str, int] = {"": 0}

        # Snapshot restore: {fname -> {op_name -> [tramp_id, tramp_addr]}} for the
        # host ops callbacks wired into each guest device node. The node (and the
        # ops pointers it holds) survives savevm, but the host tramp_id->callback
        # map is lost on a cross-process -loadvm; on restore we re-bind rather
        # than re-create. Populated at registration, persisted by save_state.
        self._ops_tramps: Dict[str, Dict[str, list]] = {}
        self._restored_ops_tramps: Dict[str, Dict[str, list]] = {}

        plugins.portal.register_interrupt_handler(
            "devfs", self._hyperdevfs_interrupt_handler)
        self._is_32bit = self.panda.bits == 32

    def _get_overridden_methods(self, devfs_file: DevFile) -> Dict[str, callable]:
        base = DevFile
        overridden = {}
        for name in [
            "open", "read", "read_iter", "write", "write_iter", "lseek", "release", "poll",
            "ioctl", "compat_ioctl", "mmap", "get_unmapped_area",
            "flush", "fsync", "fasync", "lock"
        ]:
            meth = getattr(devfs_file, name, None)
            base_meth = getattr(base, name, None)
            # Check if method is overridden (different code object)
            if (
                meth is not None and base_meth is not None
                and hasattr(meth, "__code__") and hasattr(base_meth, "__code__")
                and meth.__code__ is not base_meth.__code__
            ):
                overridden[name] = meth
        '''
        compat_ioctl runs on 64-bit systems in a 32-bit context
        We auto-register it for 64-bit systems if they don't override it
        '''
        if not self._is_32bit:
            if "ioctl" in overridden and "compat_ioctl" not in overridden:
                overridden["compat_ioctl"] = overridden["ioctl"]
        return overridden

    def _op_signature(self, name: str):
        """Extract the DWARF function signature for igloo_dev_ops member ``name``
        (the subtype behind the function-pointer member), or None. Pure metadata
        lookup -- no guest I/O -- so it is safe to call from on_restore."""
        dev_ops_type = plugins.kffi.ffi.get_type("struct igloo_dev_ops")
        if not dev_ops_type or name not in dev_ops_type.members:
            return None
        member_type = dev_ops_type.members[name].type_info
        # Function pointers are stored as pointers to functions; unwrap the
        # pointer layer so kffi sees the raw function signature.
        if member_type and member_type.get("kind") == "pointer":
            return member_type.get("subtype")
        return member_type

    def _make_ops_struct(self, devfs_file: DevFile):
        """
        Build an igloo_dev_ops struct with function pointers for only the overridden methods,
        extracting the exact function signature from DWARF metadata.
        """
        kffi = plugins.kffi
        overridden = self._get_overridden_methods(devfs_file)

        # Build the initialization dictionary dynamically
        init_data = {}
        for name, fn in overridden.items():
            # Register the callback with the explicit signature found in DWARF
            init_data[name] = yield from kffi.callback(fn, func_type=self._op_signature(name))

        return kffi.new("struct igloo_dev_ops", init_data)

    def _capture_ops_tramps(self, fname: str, devfs_file: DevFile) -> None:
        """Record {op_name -> [tramp_id, tramp_addr]} for the host ops callbacks
        of a just-registered device, so a later snapshot restore can re-bind the
        surviving guest ops pointers to fresh handlers (see on_restore)."""
        kffi = plugins.kffi
        tramps = {}
        for name, fn in self._get_overridden_methods(devfs_file).items():
            tid = kffi.get_callback_id(fn)
            taddr = kffi._tramp_addresses.get(fn)
            if tid is not None and taddr is not None:
                tramps[name] = [int(tid), int(taddr)]
        if tramps:
            self._ops_tramps[fname] = tramps

    def _rebind_ops(self, fname: str, devfs_file: DevFile) -> bool:
        """Re-bind a surviving device node's host ops callbacks after a restore.
        Returns True if the node had persisted trampolines and was re-bound."""
        methods = self._restored_ops_tramps.pop(fname, None)
        if not methods:
            return False
        kffi = plugins.kffi
        overridden = self._get_overridden_methods(devfs_file)
        for name, (tid, taddr) in methods.items():
            fn = overridden.get(name)
            if fn is None:
                continue
            kffi.rebind_callback(fn, tid, taddr, func_type=self._op_signature(name))
        # Keep it available for a subsequent re-save.
        self._ops_tramps[fname] = methods
        self.logger.info(
            f"Re-bound devfs '{fname}' ops to the surviving guest node after "
            "snapshot restore (no re-create)")
        return True

    def register(self, devfs_file: DevFile, path: Optional[str] = None, major: Optional[int] = None, minor: Optional[int] = None):
        return self.register_devfs(devfs_file, path, major, minor)

    def register_devfs(self, devfs_file: DevFile, path: Optional[str] = None, major: Optional[int] = None, minor: Optional[int] = None):
        """
        Register a DevFile for later portal registration.
        """
        raw_path = path if path else getattr(devfs_file, "PATH", None)
        if not raw_path:
            raise ValueError("DevFile must define PATH or define it in register_devfs")
        devfs_file.PATH = raw_path

        plugins.netdevs.ensure_netdev_from_path(devfs_file.full_path)

        fname = devfs_file.fs_relative_path

        major_num = major if major is not None else getattr(devfs_file, "MAJOR", -1)
        minor_num = minor if minor is not None else getattr(devfs_file, "MINOR", 0)

        if fname in self._devfs:
            raise ValueError(f"Cannot register '{fname}': A devfs file is already registered at this path.")

        self._devfs[fname] = devfs_file

        # Restore fast-path: the guest node for this device survived the snapshot,
        # so re-installing it would double-register at the guest (and the install
        # drain never runs on a -loadvm boot anyway). If this path was captured
        # before the snapshot, just re-bind its host ops callbacks and skip the
        # queue entirely.
        if fname in self._restored_ops_tramps:
            self._rebind_ops(fname, devfs_file)
            return

        # Check against the 4-tuple format (fname, devfs_file, major, minor)
        if not any(f == fname for f, _, _, _ in self._pending_devfs):
            plugins.portal.queue_interrupt("devfs")
            self._pending_devfs.append(
                (fname, devfs_file, major_num, minor_num))

    def _split_dev_path(self, path: str) -> Tuple[str, str]:
        """
        Splits 'a/b/c' into ('a/b', 'c'). Returns ('', 'c') if no slashes.
        """
        path = path.strip("/")
        if "/" in path:
            parent, fname = path.rsplit("/", 1)
            return parent, fname
        else:
            return "", path

    def _get_or_create_dev_dir(self, dir_path: str) -> Generator[int, None, int]:
        """
        Recursively creates directories via portal and returns the ID of the final directory.
        """
        parts = [p for p in dir_path.strip("/").split("/") if p]
        if not parts:
            return 0  # Root

        parent_id = 0
        cur_path = ""

        for part in parts:
            cur_path = cur_path + "/" + part if cur_path else part

            # Use cache if available
            if cur_path in self._dev_dirs:
                parent_id = self._dev_dirs[cur_path]
                continue

            kffi = plugins.kffi
            init_data = {
                "name": part.encode("latin-1", errors="ignore"),
                "parent_id": parent_id,
                "replace": 0
            }

            req = kffi.new("struct portal_devfs_dir_req", init_data)
            req_bytes = bytes(req)

            # Ensure HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR is defined in your hop consts
            result = yield PortalCmd(
                hop.HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR,
                0,
                len(req_bytes),
                None,
                req_bytes
            )

            if result is None or result < 0:
                raise RuntimeError(
                    f"Failed to create/lookup devfs dir '{cur_path}'")

            self._dev_dirs[cur_path] = result
            parent_id = result

        return parent_id

    def _register_devfs(self, devfs_list: List[Tuple[str, DevFile, int, int]]) -> Generator[int, None, None]:
        for fname, devfs_file, major, minor in devfs_list:

            # 1. Resolve path hierarchy
            parent_dir, file_name = self._split_dev_path(fname)

            try:
                parent_id = yield from self._get_or_create_dev_dir(parent_dir)
            except RuntimeError as e:
                self.logger.error(f"Could not register {fname}: {e}")
                continue

            # Validate final filename (should be flat now)
            if not file_name or "/" in file_name:
                self.logger.error(f"Invalid devfs device name after split: '{file_name}'")
                continue

            ops = yield from self._make_ops_struct(devfs_file)
            kffi = plugins.kffi
            mmap_phys_addr = self._mmap_phys_addr(devfs_file)
            support_mmap = any(
                (
                    getattr(devfs_file, "SUPPORT_MMAP", False),
                    mmap_phys_addr,
                )
            )

            init_data = {
                "name": file_name.encode("latin-1", errors="ignore"),
                "major": major,
                "minor": minor,
                "ops": ops,
                "replace": 1,
                # Dwarffi safely ignores keys that don't exist on the target struct,
                # entirely replacing the need for 'hasattr(req, "parent_id")' checks!
                "parent_id": parent_id,
                "size": getattr(devfs_file, "SIZE", 0),
                "mode": getattr(devfs_file, "MODE", 0o666),
                "support_mmap": 1 if support_mmap else 0,
                "is_block": 1 if getattr(devfs_file, "IS_BLOCK", False) else 0,
                "logical_block_size": getattr(devfs_file, "LOGICAL_BLOCK_SIZE", 512)
            }
            if mmap_phys_addr:
                init_data["mmap_phys_addr"] = mmap_phys_addr

            req = kffi.new("struct portal_devfs_create_req", init_data)
            req_bytes = bytes(req)

            result = yield PortalCmd(
                hop.HYPER_OP_DEVFS_CREATE_DEVICE,
                0,
                len(req_bytes),
                None,
                req_bytes
            )

            if result == 0 or result is None:
                self.logger.error(f"Failed to register devfs device '{fname}' (kernel returned 0)")
                continue

            self.logger.debug(f"Registered devfs device '{fname}' with kernel")
            # Record the host ops trampolines now that they're wired, so a later
            # snapshot restore can re-bind them to the surviving guest node.
            self._capture_ops_tramps(fname, devfs_file)

    def _mmap_phys_addr(self, devfs_file: DevFile) -> int:
        if not self._supports_default_mmap(devfs_file):
            return 0
        if "qemu_mem" not in plugins:
            return 0
        qemu_mem = plugins.get_plugin_by_name("qemu_mem")
        return qemu_mem.allocate_file(devfs_file)

    def _supports_default_mmap(self, devfs_file: DevFile) -> bool:
        return any(
            (
                getattr(devfs_file, "SUPPORT_MMAP", False),
                getattr(devfs_file, "SIZE", 0),
            )
        ) and not devfs_file._is_overridden("mmap")

    def _hyperdevfs_interrupt_handler(self) -> Generator[bool, None, bool]:
        if not self._pending_devfs:
            return False

        # Honor the portal's per-window install budget so a large batch of
        # device installs is spread across interrupt windows instead of
        # flooding the portal in one go (see portal.take_install_budget).
        while self._pending_devfs and plugins.portal.take_install_budget():
            devfs = self._pending_devfs.pop(0)
            yield from self._register_devfs([devfs])
        if self._pending_devfs:
            plugins.portal.queue_interrupt("devfs")
        return False

    # --- snapshot / restore ------------------------------------------------ #
    def save_state(self):
        """Persist the per-device host ops trampolines so a restore can re-bind
        the surviving guest nodes. The DevFile objects and their callbacks are
        re-created by their owners on the restore boot; only the guest ids/addrs
        need carrying. Returns None when nothing is registered."""
        return {"ops_tramps": self._ops_tramps} if self._ops_tramps else None

    def load_state(self, data) -> None:
        """Phase one: stash the saved trampoline map. Re-binding happens in
        on_restore (for owners that re-register in __init__) and in
        register_devfs (for owners that re-register later, e.g. from a hypercall
        handler that this boot won't re-fire)."""
        if not data:
            return
        self._restored_ops_tramps = {
            fname: {op: list(v) for op, v in methods.items()}
            for fname, methods in data.get("ops_tramps", {}).items()
        }

    def on_restore(self, tag: str) -> None:
        """Re-bind every already-registered device (owners that re-registered in
        their __init__) to its surviving guest node. Devices whose owner
        re-registers later are handled inline by register_devfs."""
        for fname, devfs_file in list(self._devfs.items()):
            if fname in self._restored_ops_tramps:
                self._rebind_ops(fname, devfs_file)
