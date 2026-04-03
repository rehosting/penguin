from penguin import Plugin, plugins
from hyper.portal import PortalCmd
from hyper.consts import HYPER_OP as hop
from typing import List, Dict, Generator, Optional, Tuple
from hyperfile.models.base import ProcFile


class Proc(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self._pending_procs: List[ProcFile] = []
        self._procs: Dict[str, ProcFile] = {}
        self._proc_dirs: Dict[str, int] = {}  # path -> dir id
        plugins.portal.register_interrupt_handler(
            "procfs", self._proc_interrupt_handler)

    def _get_overridden_methods(self, proc_file: ProcFile) -> Dict[str, callable]:
        """
        Return a dict of method_name: method for all methods overridden from ProcFile.
        """
        base = ProcFile
        overridden = {}
        for name in [
            "open", "read", "read_iter", "write", "lseek", "release", "poll",
            "ioctl", "compat_ioctl", "mmap", "get_unmapped_area"
        ]:
            meth = getattr(proc_file, name, None)
            base_meth = getattr(base, name, None)
            # Use __code__ to compare function implementations
            if (
                meth is not None and base_meth is not None
                and hasattr(meth, "__code__") and hasattr(base_meth, "__code__")
                and meth.__code__ is not base_meth.__code__
            ):
                overridden[name] = meth
        return overridden

    def _make_fops_struct(self, proc_file: ProcFile):
        """
        Build a file_operations struct with function pointers for only the overridden methods.
        """
        kffi = plugins.kffi
        overridden = self._get_overridden_methods(proc_file)
        
        # Build the initialization dictionary dynamically
        init_data = {}
        for name, fn in overridden.items():
            init_data[name] = yield from kffi.callback(fn)
            
        return kffi.new("struct igloo_proc_ops", init_data)

    def register_proc(self, proc_file: ProcFile, path: Optional[str] =None):
        """
        Register a ProcFile for later portal registration.
        """
        if path:
            fname = path
        else:
            fname = getattr(proc_file, "PATH", None)
        if not fname:
            raise ValueError("ProcFile must define PATH or define it in register_proc")
            
        proc_file.PATH = fname
        if fname.startswith("/proc/"):
            fname = fname[len("/proc/"):]  # Remove leading /proc/
        if fname not in self._procs and proc_file not in self._pending_procs:
            plugins.portal.queue_interrupt("procfs")
            self._pending_procs.append((fname, proc_file))
        self._procs[fname] = proc_file

    def _get_or_create_proc_dir(self, dir_path: str) -> Generator[int, None, int]:
        """
        Create or look up a procfs directory, returning its id.
        Handles multi-level paths recursively. Root is id 0.
        """
        parts = [p for p in dir_path.strip("/").split("/") if p]
        if not parts:
            self._proc_dirs[""] = 0
            return 0
            
        # ONLY check the first directory component (root-level /proc/ entries)
        first_dir = parts[0]
        if first_dir.isdigit() or first_dir == "self":
            self.logger.error(f"Cannot create reserved procfs directory: '/proc/{first_dir}'")
            raise RuntimeError(f"Reserved procfs path component: {first_dir}")

        parent_id = 0
        cur_path = ""
        for part in parts:
            cur_path = cur_path + "/" + part if cur_path else part
            if cur_path in self._proc_dirs:
                parent_id = self._proc_dirs[cur_path]
            else:
                kffi = plugins.kffi
                
                # Dwarffi natively handles null-termination and bounds truncation for byte arrays
                init_data = {
                    "path": part.encode("latin-1", errors="ignore"),
                    "parent_id": parent_id,
                    "replace": 0
                }
                
                req = kffi.new("struct portal_procfs_create_req", init_data)
                req_bytes = bytes(req)
                
                # Now parent_id is passed for each level
                result = yield PortalCmd(
                    hop.HYPER_OP_PROCFS_CREATE_OR_LOOKUP_DIR,
                    0,
                    len(req_bytes),
                    None,
                    req_bytes
                )
                if not result or result < 0:
                    raise RuntimeError(f"Failed to create/lookup proc dir '{cur_path}'")
                self._proc_dirs[cur_path] = result
                parent_id = result
        return parent_id

    def _split_proc_path(self, path: str):
        """
        Split a procfs path into (parent_dir, file_name).
        If no directory, parent_dir is '' (root).
        """
        path = path.strip("/")
        if "/" in path:
            parent, fname = path.rsplit("/", 1)
            return parent, fname
        else:
            return "", path

    def _register_procs(self, procs: List[Tuple[str, ProcFile]]) -> Generator[int, None, None]:
        """
        Register proc files with the kernel via portal.
        """
        for fname, proc in procs:
            # Split the path to isolate the very first directory or file
            parts = [p for p in fname.strip("/").split("/") if p]
            
            # Only block if the root-most proc element is 'self' or a digit
            if parts and (parts[0] == "self" or parts[0].isdigit()):
                self.logger.error(
                    f"Cannot register special procfs path '/proc/{fname.strip('/')}': not supported."
                )
                continue

            parent_dir, file_name = self._split_proc_path(fname)
            
            # Gracefully handle failures to create directories
            try:
                parent_id = yield from self._get_or_create_proc_dir(parent_dir)
            except RuntimeError as e:
                self.logger.error(f"Skipping proc registration for '{fname}': {e}")
                continue

            # Validate file name
            if not file_name or "/" in file_name:
                self.logger.error(f"Invalid proc file name: '{file_name}' from path '{fname}'")
                continue

            fops = yield from self._make_fops_struct(proc)
            kffi = plugins.kffi
            
            init_data = {
                "path": file_name.encode("latin-1", errors="ignore"),
                "fops": fops,
                "size": getattr(proc, "SIZE", 0),
                "mode": getattr(proc, "MODE", 0o444),
                "parent_id": parent_id,
                "replace": 1
            }
            
            req = kffi.new("struct portal_procfs_create_req", init_data)
            req_bytes = bytes(req)
            
            result = yield PortalCmd(
                hop.HYPER_OP_PROCFS_CREATE_FILE,
                0,
                len(req_bytes),
                None,
                req_bytes
            )
            if result == 0 or result is None:
                self.logger.error(f"Failed to register proc '{fname}' (kernel returned 0)")
                continue
            self.logger.info(f"Registered proc '{fname}' with kernel")

    def _proc_interrupt_handler(self) -> Generator[bool, None, bool]:
        """
        Process pending proc registrations.
        """
        if not self._pending_procs:
            return False

        pending = self._pending_procs[:]
        while pending:
            proc = pending.pop(0)
            yield from self._register_procs([proc])
            self._pending_procs.remove(proc)
        return False