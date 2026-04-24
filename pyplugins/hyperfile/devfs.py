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

        plugins.portal.register_interrupt_handler(
            "devfs", self._hyperdevfs_interrupt_handler)

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
        return overridden

    def _make_ops_struct(self, devfs_file: DevFile):
        """
        Build an igloo_dev_ops struct with function pointers for only the overridden methods,
        extracting the exact function signature from DWARF metadata.
        """
        kffi = plugins.kffi
        overridden = self._get_overridden_methods(devfs_file)

        # Look up the struct definition in dwarffi to extract signatures
        dev_ops_type = kffi.ffi.get_type("struct igloo_dev_ops")

        # Build the initialization dictionary dynamically
        init_data = {}
        for name, fn in overridden.items():
            op_signature = None
            if dev_ops_type and name in dev_ops_type.members:
                member_type = dev_ops_type.members[name].type_info

                # Function pointers are stored as pointers to functions.
                # We must unwrap the pointer layer so kffi sees the raw function signature.
                if member_type and member_type.get("kind") == "pointer":
                    op_signature = member_type.get("subtype")
                else:
                    op_signature = member_type

            # Register the callback with the explicit signature found in DWARF
            init_data[name] = yield from kffi.callback(fn, func_type=op_signature)

        return kffi.new("struct igloo_dev_ops", init_data)

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

        # Check against the 4-tuple format (fname, devfs_file, major, minor)
        if not any(f == fname for f, _, _, _ in self._pending_devfs):
            plugins.portal.queue_interrupt("devfs")
            self._pending_devfs.append(
                (fname, devfs_file, major_num, minor_num))

        self._devfs[fname] = devfs_file

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
                "support_mmap": 1 if getattr(devfs_file, "SUPPORT_MMAP", False) else 0,
                "is_block": 1 if getattr(devfs_file, "IS_BLOCK", False) else 0,
                "logical_block_size": getattr(devfs_file, "LOGICAL_BLOCK_SIZE", 512)
            }

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

    def _hyperdevfs_interrupt_handler(self) -> Generator[bool, None, bool]:
        if not self._pending_devfs:
            return False

        pending = self._pending_devfs[:]
        self._pending_devfs.clear()
        while pending:
            devfs = pending.pop(0)
            yield from self._register_devfs([devfs])
        return False
