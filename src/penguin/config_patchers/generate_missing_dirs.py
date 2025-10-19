from . import PatchGenerator
from collections import defaultdict
from penguin import getColoredLogger
from penguin.helpers.tar_helper import TarHelper
import os

logger = getColoredLogger("penguin.config_patchers")

class GenerateMissingDirs(PatchGenerator):
    '''
    Examine the fs archive to identify missing directories
    We ignore the extracted filesystem because we want to
    ensure symlinks are handled correctly
    '''
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

    def __init__(self, archive_path: str, archive_files: list) -> None:
        self.patch_name = "static.missing_dirs"
        self.enabled = True
        self.archive_path = archive_path
        self.archive_files = {member.name[1:] for member in archive_files}

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
            # We resolved a symlink to another symlink, need to recurse
            # XXX: What if our resolved path contains a symlink earlier in the path TODO
            if depth > 10 or d == symlinks[d]:
                logger.warning(f"Symlink loop detected for {d}")
                return d
            else:
                # Recurse
                return GenerateMissingDirs._resolve_path(symlinks[d], symlinks, depth=depth+1)

        return d

    def generate(self, patches: dict) -> dict:
        # XXX: Do we want to operate on archives to ensure symlinks behave as expected?
        symlinks = TarHelper.get_symlink_members(self.archive_path)
        result = defaultdict(dict)

        for d in self.TARGET_DIRECTORIES:
            # It's not already in there, add it as a world-readable directory
            # Handle symlinks. If we have a directory like /tmp/var and /tmp is a symlink to /asdf, we want to make /asdf/var

            resolved_path = self._resolve_path(d, symlinks)
            # Try handling ../s by resolving the path
            if ".." in resolved_path.split("/"):
                resolved_path = os.path.normpath(resolved_path)

            if ".." in resolved_path.split("/"):
                logger.debug("Skipping directory with .. in path: " + resolved_path)
                continue

            while resolved_path.endswith("/"):
                resolved_path = resolved_path[:-1]

            # Check if this directory looks like / - it might be ./ or something else
            if resolved_path == ".":
                continue

            # Guestfs gets mad if there's a /. in the path
            if resolved_path.endswith("/."):
                resolved_path = resolved_path[:-2]

            # Look at each parent directory, is it a symlink?
            for i in range(1, len(resolved_path.split("/"))):
                parent = "/".join(resolved_path.split("/")[:i])
                if parent in symlinks:
                    logger.debug(
                        f"Skipping {resolved_path} because parent {parent} is a symlink"
                    )
                    continue

            # Clean up the path
            while "/./" in resolved_path:
                resolved_path = resolved_path.replace("/./", "/")
            while "//" in resolved_path:
                resolved_path = resolved_path.replace("//", "/")
            while resolved_path.endswith("/"):
                resolved_path = resolved_path[:-1]

            # If this path is in the archive OR any existing patches, skip
            # Note we're ignoring the enabled flag of patches
            if resolved_path in self.archive_files:
                continue
            if any([resolved_path in p[0].get('static_files', {}).keys() for p in patches.values()]):
                continue

            # Add path and parents (as necessary)
            path_parts = resolved_path.split("/")
            # If any parts are just .//
            for i in range(1, len(path_parts) + 1):
                subdir = "/".join(path_parts[:i])
                if subdir not in self.archive_files:
                    result['static_files'][subdir] = {
                        "type": "dir",
                        "mode": 0o755,
                    }
        return result
