import os
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class GenerateMissingDirs(ConfigPatcherPlugin):
    TARGET_DIRECTORIES: list[str] = [
        "/proc",
        "/etc_ro",
        "/tmp",
        "/var",
        "/run",
        "/sys",
        "/root",
        "/tmp/var",
        "/tmp/media",
        "/tmp/etc",
        "/tmp/var/run",
        "/tmp/home",
        "/tmp/home/root",
        "/tmp/mnt",
        "/tmp/opt",
        "/tmp/www",
        "/var/run",
        "/var/lock",
        "/usr/bin",
        "/usr/sbin",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.missing_dirs"
        self.enabled = True

    @staticmethod
    def _resolve_path(d: str, symlinks: dict, depth: int = 0) -> str:
        parts = d.split("/")
        for i in range(len(parts), 1, -1):
            sub_path = "/".join(parts[:i])
            if sub_path in symlinks:
                if depth > 10 or d == symlinks[sub_path]:
                    logger.warning(f"Symlink loop detected for {d}")
                    return d
                return GenerateMissingDirs._resolve_path(
                    d.replace(sub_path, symlinks[sub_path], 1), symlinks, depth=depth+1
                )
        if not d.startswith("/"):
            d = "/" + d

        if d in symlinks:
            if depth > 10 or d == symlinks[d]:
                logger.warning(f"Symlink loop detected for {d}")
                return d
            else:
                return GenerateMissingDirs._resolve_path(symlinks[d], symlinks, depth=depth+1)

        return d

    def generate(self, patches: dict) -> dict:
        from .tar_helper import TarHelper
        symlinks = TarHelper.get_symlink_members(self.fs_archive)
        archive_files = {member.name[1:] for member in TarHelper.get_all_members(self.fs_archive)}
        result = defaultdict(dict)

        for d in self.TARGET_DIRECTORIES:
            resolved_path = self._resolve_path(d, symlinks)
            if ".." in resolved_path.split("/"):
                resolved_path = os.path.normpath(resolved_path)

            if ".." in resolved_path.split("/"):
                logger.debug("Skipping directory with .. in path: " + resolved_path)
                continue

            while resolved_path.endswith("/"):
                resolved_path = resolved_path[:-1]

            if resolved_path == ".":
                continue

            if resolved_path.endswith("/."):
                resolved_path = resolved_path[:-2]

            for i in range(1, len(resolved_path.split("/"))):
                parent = "/".join(resolved_path.split("/")[:i])
                if parent in symlinks:
                    logger.debug(
                        f"Skipping {resolved_path} because parent {parent} is a symlink"
                    )
                    continue

            while "/./" in resolved_path:
                resolved_path = resolved_path.replace("/./", "/")
            while "//" in resolved_path:
                resolved_path = resolved_path.replace("//", "/")
            while resolved_path.endswith("/"):
                resolved_path = resolved_path[:-1]

            if resolved_path in archive_files:
                continue
            if any([resolved_path in p[0].get('static_files', {}).keys() for p in patches.values()]):
                continue

            path_parts = resolved_path.split("/")
            for i in range(1, len(path_parts) + 1):
                subdir = "/".join(path_parts[:i])
                if subdir not in archive_files:
                    result['static_files'][subdir] = {
                        "type": "dir",
                        "mode": 0o755,
                    }
        return result
