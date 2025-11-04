import os
import io
from typing import Any, Dict, Optional, IO
from penguin import Plugin
from ratarmountcore.mountsource.factory import open_mount_source
from ratarmountcore.mountsource import MountSource, FileInfo


class StaticFS(Plugin):
    _fs_tar: str
    _config: Dict[str, Any]
    _fs_dir: str
    _fs: MountSource
    _static_files: Dict[str, Dict[str, Any]]
    _exists_cache: Dict[str, bool]
    _fileinfo_cache: Dict[str, Optional[FileInfo]]

    def __init__(self) -> None:
        self._fs_tar = self.get_arg("fs")
        self._config = self.get_arg("conf")
        self._fs_dir = os.path.dirname(os.path.abspath(self._fs_tar))
        self._fs = open_mount_source(self._fs_tar, lazyMounting=True)
        self._static_files = self._config.get("static_files", {}).get("root", {})
        self._exists_cache = {}
        self._fileinfo_cache = {}

    def _normalize_path(self, path: str) -> str:
        # Ensure leading slash for ratarmountcore
        norm_path = os.path.normpath(path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        return norm_path

    def exists(self, path: str) -> bool:
        norm_path = self._normalize_path(path)
        if norm_path in self._exists_cache:
            return self._exists_cache[norm_path]
        # Check static_files first
        if norm_path in self._static_files:
            self._exists_cache[norm_path] = True
            self._fileinfo_cache[norm_path] = None  # Not applicable for static files
            return True
        # Fallback to ratarmountcore
        try:
            fileInfo = self._fs.lookup(norm_path)
            exists = fileInfo is not None
            self._exists_cache[norm_path] = exists
            self._fileinfo_cache[norm_path] = fileInfo
            return exists
        except Exception:
            self._exists_cache[norm_path] = False
            self._fileinfo_cache[norm_path] = None
            return False

    def open(self, path: str) -> Optional[IO[bytes]]:
        norm_path = self._normalize_path(path)
        if not self.exists(norm_path):
            return None
        # Check static_files first
        if norm_path in self._static_files:
            action = self._static_files[norm_path]
            if action.get("type") == "inline_file":
                contents = action.get("contents", "").encode()
                return io.BytesIO(contents)
            elif action.get("type") == "host_file":
                host_path = action.get("host_path")
                try:
                    return open(host_path, "rb")
                except Exception:
                    return None
            # For other types, not supported for open
            return None
        fileInfo = self._fileinfo_cache.get(norm_path)
        if fileInfo is not None:
            try:
                return self._fs.open(fileInfo, buffering=0)
            except Exception:
                return None
        return None

    def read(self, path: str, size: int, offset: int = 0) -> Optional[bytes]:
        norm_path = self._normalize_path(path)
        if not self.exists(norm_path):
            return None
        # Check static_files first
        if norm_path in self._static_files:
            action = self._static_files[norm_path]
            if action.get("type") == "inline_file":
                contents = action.get("contents", "").encode()
                return contents[offset:offset+size]
            elif action.get("type") == "host_file":
                host_path = action.get("host_path")
                try:
                    with open(host_path, "rb") as f:
                        f.seek(offset)
                        return f.read(size)
                except Exception:
                    return None
            return None
        fileInfo = self._fileinfo_cache.get(norm_path)
        if fileInfo is not None:
            try:
                return self._fs.read(fileInfo, size, offset)
            except Exception:
                return None
        return None

    def list_xattr(self, path: str) -> list[str]:
        norm_path = self._normalize_path(path)
        if not self.exists(norm_path):
            return []
        if norm_path in self._static_files:
            # No xattrs for static files
            return []
        fileInfo = self._fileinfo_cache.get(norm_path)
        if fileInfo is not None:
            try:
                return self._fs.list_xattr(fileInfo)
            except Exception:
                return []
        return []

    def get_xattr(self, path: str, key: str) -> Optional[bytes]:
        norm_path = self._normalize_path(path)
        if not self.exists(norm_path):
            return None
        if norm_path in self._static_files:
            # No xattrs for static files
            return None
        fileInfo = self._fileinfo_cache.get(norm_path)
        if fileInfo is not None:
            try:
                return self._fs.get_xattr(fileInfo, key)
            except Exception:
                return None
        return None

    def statfs(self, path: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns a dictionary with keys named like the POSIX statvfs struct.
        For static files, returns default values.
        For ratarmountcore files, delegates to the underlying mount source.
        """
        norm_path = self._normalize_path(path) if path is not None else "/"
        if norm_path in self._static_files:
            # Return default statfs for static files
            return {"f_bsize": 512, "f_namemax": 255}
        try:
            return self._fs.statfs()
        except Exception:
            return {"f_bsize": 512, "f_namemax": 255}

    def list(self, path: str) -> Optional[list[str]]:
        norm_path = self._normalize_path(path)
        # Collect static files under this directory
        static_entries = []
        prefix = norm_path if norm_path.endswith("/") else norm_path + "/"
        plen = len(prefix)
        for p in self._static_files:
            if p.startswith(prefix):
                sub = p[plen:].split("/", 1)[0]
                if sub and sub not in static_entries:
                    static_entries.append(sub)
        # Fallback to ratarmountcore
        try:
            fs_entries = self._fs.list(norm_path)
            if isinstance(fs_entries, dict):
                fs_entries = list(fs_entries.keys())
            elif fs_entries is None:
                fs_entries = []
            else:
                fs_entries = list(fs_entries)
        except Exception:
            fs_entries = []
        # Merge and deduplicate
        return sorted(set(static_entries) | set(fs_entries))

    def list_mode(self, path: str) -> Optional[Dict[str, int]]:
        norm_path = self._normalize_path(path)
        result: Dict[str, int] = {}
        # Static files
        prefix = norm_path if norm_path.endswith("/") else norm_path + "/"
        plen = len(prefix)
        for p, action in self._static_files.items():
            if p.startswith(prefix):
                sub = p[plen:].split("/", 1)[0]
                if sub and sub not in result:
                    # Try to get mode from action, fallback to 0
                    mode = action.get("mode", 0)
                    result[sub] = mode
        # Fallback to ratarmountcore
        try:
            fs_modes = self._fs.list_mode(norm_path)
            if isinstance(fs_modes, dict):
                for k, v in fs_modes.items():
                    result[k] = v
        except Exception:
            pass
        return result if result else None
