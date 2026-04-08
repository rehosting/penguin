import os
import io
import stat
from typing import Any, Dict, Optional, IO, Tuple
from penguin import Plugin
from ratarmountcore.mountsource.factory import open_mount_source
from ratarmountcore.mountsource import MountSource, FileInfo


class StaticFS(Plugin):
    _fs_tar: str
    _config: Dict[str, Any]
    _fs_dir: str
    _fs: MountSource
    _exists_cache: Dict[str, bool]
    _fileinfo_cache: Dict[str, Optional[FileInfo]]

    def __init__(self) -> None:
        self._fs_tar = self.get_arg("fs")
        self._config = self.get_arg("conf")
        self._fs_dir = os.path.dirname(os.path.abspath(self._fs_tar))
        self._fs = open_mount_source(self._fs_tar, lazyMounting=True, openMode='ro')
        self._exists_cache = {}
        self._fileinfo_cache = {}

    def _normalize_path(self, path: str) -> str:
        # Ensure leading slash for ratarmountcore
        norm_path = os.path.normpath(path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        return norm_path

    def _resolve_path(self, path: str, max_depth: int = 40) -> Tuple[Optional[str], Optional[FileInfo]]:
        """
        Resolves symlinks in both static_files and ratarmountcore up to a max_depth limit.
        Returns a tuple of the resolved path and its FileInfo (if applicable).
        """
        norm_path = self._normalize_path(path)

        for _ in range(max_depth):
            # Check static files first (they take precedence)
            static_action = self._config.get("static_files", {}).get(norm_path)
            if static_action:
                if static_action.get("type") == "symlink":
                    link_target = static_action.get("target")
                    if not link_target:
                        return None, None  # Invalid symlink
                    if link_target.startswith("/"):
                        norm_path = self._normalize_path(link_target)
                    else:
                        norm_path = self._normalize_path(os.path.join(os.path.dirname(norm_path), link_target))
                    continue   # Follow the symlink defined in config
                else:
                    return norm_path, None  # Found a concrete static file

            # Lookup with cache for ratarmountcore
            if norm_path not in self._fileinfo_cache:
                try:
                    self._fileinfo_cache[norm_path] = self._fs.lookup(norm_path)
                except Exception:
                    self._fileinfo_cache[norm_path] = None

            fileInfo = self._fileinfo_cache[norm_path]

            if fileInfo is None:
                return None, None

            # If the file is a ratarmountcore symlink, resolve the target
            if stat.S_ISLNK(fileInfo.mode) and fileInfo.linkname:
                link_target = fileInfo.linkname
                if link_target.startswith("/"):
                    norm_path = self._normalize_path(link_target)
                else:
                    norm_path = self._normalize_path(os.path.join(os.path.dirname(norm_path), link_target))
                continue
            else:
                return norm_path, fileInfo

        return None, None  # Symlink loop detected

    def exists(self, path: str) -> bool:
        norm_path = self._normalize_path(path)
        if norm_path in self._exists_cache:
            return self._exists_cache[norm_path]

        resolved_path, _ = self._resolve_path(path)
        exists = resolved_path is not None
        self._exists_cache[norm_path] = exists
        return exists

    def get_size(self, path: str) -> Optional[int]:
        """
        Returns the size of the file in bytes without opening it.
        """
        resolved_path, fileInfo = self._resolve_path(path)
        if not resolved_path:
            return None

        # Check static_files first
        if resolved_path in self._config.get("static_files", {}):
            action = self._config["static_files"][resolved_path]
            if action.get("type") == "inline_file":
                contents = action.get("contents", b"")
                if isinstance(contents, str):
                    contents = contents.encode()
                return len(contents)
            elif action.get("type") == "host_file":
                host_path = action.get("host_path")
                try:
                    return os.path.getsize(host_path)
                except Exception:
                    return None
            return 0

        # Use the resolved FileInfo
        if fileInfo is not None:
            return fileInfo.size
        return None

    def open(self, path: str) -> Optional[IO[bytes]]:
        resolved_path, fileInfo = self._resolve_path(path)
        if not resolved_path:
            return None

        # Check static_files first
        if resolved_path in self._config.get("static_files", {}):
            action = self._config["static_files"][resolved_path]
            if action.get("type") == "inline_file":
                contents = action.get("contents", b"")
                if isinstance(contents, str):
                    contents = contents.encode()
                return io.BytesIO(contents)
            elif action.get("type") == "host_file":
                host_path = action.get("host_path")
                try:
                    return open(host_path, "rb")
                except Exception:
                    return None
            # For other types, not supported for open
            return None
        if fileInfo is not None:
            try:
                return self._fs.open(fileInfo, buffering=0)
            except Exception:
                return None
        return None

    def read(self, path: str, size: int, offset: int = 0) -> Optional[bytes]:
        resolved_path, fileInfo = self._resolve_path(path)
        if not resolved_path:
            return None
        # Check static_files first
        if resolved_path in self._config.get("static_files", {}):
            action = self._config["static_files"][resolved_path]
            if action.get("type") == "inline_file":
                contents = action.get("contents", b"")
                if isinstance(contents, str):
                    contents = contents.encode()
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
        if fileInfo is not None:
            try:
                return self._fs.read(fileInfo, size, offset)
            except Exception:
                return None
        return None

    def list_xattr(self, path: str) -> list[str]:
        resolved_path, fileInfo = self._resolve_path(path)
        if not resolved_path or resolved_path in self._config.get("static_files", {}):
            return []
        if fileInfo is not None:
            try:
                return self._fs.list_xattr(fileInfo)
            except Exception:
                return []
        return []

    def get_xattr(self, path: str, key: str) -> Optional[bytes]:
        resolved_path, fileInfo = self._resolve_path(path)
        if not resolved_path or resolved_path in self._config.get("static_files", {}):
            return None
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
        if norm_path in self._config.get("static_files", {}):
            # Return default statfs for static files
            return {"f_bsize": 512, "f_namemax": 255}
        try:
            return self._fs.statfs()
        except Exception:
            return {"f_bsize": 512, "f_namemax": 255}

    def list(self, path: str) -> Optional[list[str]]:
        resolved_path, _ = self._resolve_path(path)
        target_path = resolved_path if resolved_path else self._normalize_path(path)
        static_entries = []
        prefix = target_path if target_path.endswith("/") else target_path + "/"
        plen = len(prefix)
        for p in self._config.get("static_files", {}):
            if p.startswith(prefix):
                sub = p[plen:].split("/", 1)[0]
                if sub and sub not in static_entries:
                    static_entries.append(sub)
        # Fallback to ratarmountcore
        try:
            fs_entries = self._fs.list(target_path)
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
        resolved_path, _ = self._resolve_path(path)
        target_path = resolved_path if resolved_path else self._normalize_path(path)
        result: Dict[str, int] = {}
        # Static files
        prefix = target_path if target_path.endswith("/") else target_path + "/"
        plen = len(prefix)
        for p, action in self._config.get("static_files", {}).items():
            if p.startswith(prefix):
                sub = p[plen:].split("/", 1)[0]
                if sub and sub not in result:
                    # Try to get mode from action, fallback to 0
                    mode = action.get("mode", 0)
                    result[sub] = mode
        # Fallback to ratarmountcore
        try:
            fs_modes = self._fs.list_mode(target_path)
            if isinstance(fs_modes, dict):
                for k, v in fs_modes.items():
                    result[k] = v
        except Exception:
            pass
        return result if result else None

    def uninit(self):
        """
        Cleanly closes the underlying MountSource and forces a disk sync.
        """
        if self._fs:
            fs = self._fs
            self._fs = None
            fs.close()
