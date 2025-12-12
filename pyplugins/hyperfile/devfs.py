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
        kffi = plugins.kffi
        ops = kffi.new("struct igloo_dev_ops")
        overridden = self._get_overridden_methods(devfs_file)
        for name, fn in overridden.items():
            c_fn = yield from kffi.callback(fn)
            setattr(ops, name, c_fn)
        return ops

    def register_devfs(self, devfs_file: DevFile, path: Optional[str] = None, major: Optional[int] = None, minor: Optional[int] = None):
        if path:
            fname = path
        else:
            fname = getattr(devfs_file, "PATH", None)
        devfs_file.PATH = fname
        
        if not fname:
            raise ValueError("DevFile must define PATH or define it in register_devfs")
            
        major_num = major if major is not None else getattr(devfs_file, "MAJOR", -1)
        minor_num = minor if minor is not None else getattr(devfs_file, "MINOR", 0)
        
        if fname.startswith("/dev/"):
            fname = fname[len("/dev/"):]  # Remove leading /dev/
            
        # Deduplicate registration
        if fname not in self._devfs and devfs_file not in [f for _, f, _, _ in self._pending_devfs]:
            plugins.portal.queue_interrupt("devfs")
            self._pending_devfs.append((fname, devfs_file, major_num, minor_num))
        
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
            # Reusing devfs_dir_req or similar struct defined in your kernel
            # If not defined, you might need to define it or reuse create_req carefully
            req = kffi.new("struct portal_devfs_dir_req")
            
            buf = part.encode("latin-1", errors="ignore")[:63] + b"\0"
            for j in range(len(buf)):
                req.name[j] = buf[j]
            
            req.parent_id = parent_id
            req.replace = 0
            
            req_bytes = req.to_bytes()
            
            # Ensure HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR is defined in your hop consts
            result = yield PortalCmd(
                hop.HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR,
                0,
                len(req_bytes),
                None,
                req_bytes
            )
            
            if result is None or result < 0:
                raise RuntimeError(f"Failed to create/lookup devfs dir '{cur_path}'")
            
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

            buf = file_name.encode("latin-1", errors="ignore")[:255] + b"\0"
            ops = yield from self._make_ops_struct(devfs_file)
            
            kffi = plugins.kffi
            req = kffi.new("struct portal_devfs_create_req")
            for i in range(len(buf)):
                req.name[i] = buf[i]
            
            req.major = major
            req.minor = minor
            req.ops = ops
            req.replace = 1
            
            # Set parent_id if the struct supports it (requires updated KFFI defs)
            if hasattr(req, 'parent_id'):
                req.parent_id = parent_id
            
            req_bytes = req.to_bytes()
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
            
            self.logger.info(f"Registered devfs device '{fname}' with kernel")

    def _hyperdevfs_interrupt_handler(self) -> Generator[bool, None, bool]:
        if not self._pending_devfs:
            return False

        pending = self._pending_devfs[:]
        while pending:
            devfs = pending.pop(0)
            yield from self._register_devfs([devfs])
            self._pending_devfs.remove(devfs)
        return False