from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop
from typing import List, Dict, Generator, Optional, Tuple
from hyperfile.models.base import SysFile


class Sysfs(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self._pending_sysfs: List[Tuple[str, SysFile]] = []
        self._sysfs: Dict[str, SysFile] = {}
        self._sysfs_dirs: Dict[str, int] = {}  # path -> dir id
        plugins.portal.register_interrupt_handler(
            "sysfs", self._hypersysfs_interrupt_handler)

    def _get_overridden_methods(self, sysfs_file: SysFile) -> Dict[str, callable]:
        base = SysFile
        overridden = {}
        for name in ["show", "store"]:
            meth = getattr(sysfs_file, name, None)
            base_meth = getattr(base, name, None)
            if (
                meth is not None and base_meth is not None
                and hasattr(meth, "__code__") and hasattr(base_meth, "__code__")
                and meth.__code__ is not base_meth.__code__
            ):
                overridden[name] = meth
        return overridden

    def _make_ops_struct(self, sysfs_file: SysFile):
        kffi = plugins.kffi
        ops = kffi.new("struct igloo_sysfs_ops")
        overridden = self._get_overridden_methods(sysfs_file)
        for name, fn in overridden.items():
            c_fn = yield from kffi.callback(fn)
            setattr(ops, name, c_fn)
        return ops

    def register_sysfs(self, sysfs_file: SysFile, path: Optional[str] = None, mode: int = 0o644):
        if path:
            fname = path
        else:
            fname = getattr(sysfs_file, "PATH", None)
        sysfs_file.PATH = fname
        if not fname:
            raise ValueError("SysFile must define PATH or define it in register_sysfs")
        if fname.startswith("/sys/"):
            fname = fname[len("/sys/"):]
        # Fix: _pending_sysfs contains (fname, sysfs_file, mode)
        if fname not in self._sysfs and sysfs_file not in [f for _, f, _ in self._pending_sysfs]:
            plugins.portal.queue_interrupt("sysfs")
            self._pending_sysfs.append((fname, sysfs_file, mode))
        self._sysfs[fname] = sysfs_file

    def _get_or_create_sysfs_dir(self, dir_path: str) -> Generator[int, None, int]:
        parts = [p for p in dir_path.strip("/").split("/") if p]
        if not parts:
            self._sysfs_dirs[""] = 0
            return 0
        parent_id = 0
        cur_path = ""
        for part in parts:
            cur_path = cur_path + "/" + part if cur_path else part
            if cur_path in self._sysfs_dirs:
                parent_id = self._sysfs_dirs[cur_path]
            else:
                kffi = plugins.kffi
                req = kffi.new("struct portal_sysfs_create_req")
                buf = part.encode("latin-1", errors="ignore")[:255] + b"\0"
                for j in range(len(buf)):
                    req.path[j] = buf[j]
                req.parent_id = parent_id
                req.replace = 0
                req.mode = 0o755
                req_bytes = req.to_bytes()
                result = yield PortalCmd(
                    hop.HYPER_OP_SYSFS_CREATE_OR_LOOKUP_DIR,
                    0,
                    len(req_bytes),
                    None,
                    req_bytes
                )
                if not result or result < 0:
                    raise RuntimeError(f"Failed to create/lookup sysfs dir '{cur_path}'")
                self._sysfs_dirs[cur_path] = result
                parent_id = result
        return parent_id

    def _split_sysfs_path(self, path: str):
        path = path.strip("/")
        if "/" in path:
            parent, fname = path.rsplit("/", 1)
            return parent, fname
        else:
            return "", path

    def _register_sysfs(self, sysfs_list: List[Tuple[str, SysFile, int]]) -> Generator[int, None, None]:
        for fname, sysfs_file, mode in sysfs_list:
            # Require at least one directory level (e.g., "foo/bar")
            norm_path = fname.strip("/")
            if "/" not in norm_path:
                self.logger.error(
                    f"Cannot register sysfs file '{fname}': must be in a directory (e.g., 'foo/bar')."
                )
                continue

            parent_dir, file_name = self._split_sysfs_path(fname)
            parent_id = yield from self._get_or_create_sysfs_dir(parent_dir)

            if not file_name or "/" in file_name:
                self.logger.error(f"Invalid sysfs file name: '{file_name}' from path '{fname}'")
                continue

            buf = file_name.encode("latin-1", errors="ignore")[:255] + b"\0"
            ops = yield from self._make_ops_struct(sysfs_file)
            kffi = plugins.kffi
            req = kffi.new("struct portal_sysfs_create_req")
            for i in range(len(buf)):
                req.path[i] = buf[i]
            req.ops = ops
            req.parent_id = parent_id
            req.replace = 1
            req.mode = mode
            req_bytes = req.to_bytes()
            result = yield PortalCmd(
                hop.HYPER_OP_SYSFS_CREATE_FILE,
                0,
                len(req_bytes),
                None,
                req_bytes
            )
            if result == 0 or result is None:
                self.logger.error(f"Failed to register sysfs '{fname}' (kernel returned 0)")
                continue
            self.logger.info(f"Registered sysfs '{fname}' with kernel")

    def _hypersysfs_interrupt_handler(self) -> Generator[bool, None, bool]:
        if not self._pending_sysfs:
            return False

        pending = self._pending_sysfs[:]
        while pending:
            sysfs = pending.pop(0)
            yield from self._register_sysfs([sysfs])
            self._pending_sysfs.remove(sysfs)
        return False
