"""
Static file patches: create missing/referenced directories and files, delete
unwanted files.
"""

import os
import re

from collections import defaultdict

from penguin import getColoredLogger
from penguin.config_patchers import FileHelper, TarHelper
from penguin.init_plugin import InitContext, InitPlugin

logger = getColoredLogger("penguin.init.static_files")


class GenerateMissingDirs(InitPlugin):
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

    patch_name = "static.missing_dirs"
    order = 150
    consumes_patches = True  # skips dirs already provided by other patches

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

    def patch(self, ctx: InitContext) -> dict:
        self.archive_files = {member.name[1:] for member in ctx.archive_files}
        patches = ctx.patches_snapshot()

        # XXX: Do we want to operate on archives to ensure symlinks behave as expected?
        symlinks = TarHelper.get_symlink_members(str(ctx.fs_archive))
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
            for i in range(1, len(path_parts) + 1):
                subdir = "/".join(path_parts[:i])

                # FIX: Skip if subdir is empty (caused by the leading slash)
                if not subdir:
                    continue

                if subdir not in self.archive_files:
                    result['static_files'][subdir] = {
                        "type": "dir",
                        "mode": 0o755,
                    }
        return result


class GenerateReferencedDirs(InitPlugin):
    '''
    FirmAE "Boot mitigation": find path strings in binaries, make their directories
    if they don't already exist.
    '''
    patch_name = "static.binary_paths"
    order = 160

    def patch(self, ctx: InitContext) -> dict:
        result = defaultdict(dict)
        for f in FileHelper.find_executables(
            str(ctx.extracted_fs), {"/bin", "/sbin", "/usr/bin", "/usr/sbin"},
            index=ctx.file_index,
        ):
            # For things that look like binaries, find unique strings that look like paths
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^(/var|/etc|/tmp)(.+)([^\\/]+)$"))
            ):
                if any([x in dest for x in ["%s", "%c", "%d", "/tmp/services"]]):
                    # Ignore these paths, printf format strings aren't real directories to create
                    # Not sure what /tmp/services is or where we got that from?
                    continue
                result["static_files"][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result


class GenerateShellMounts(InitPlugin):
    """
    Ensure we have /mnt/* directories referenced by shell scripts.
    """
    patch_name = "static.shell_script_mounts"
    order = 170
    consumes_patches = True  # skips dirs already provided by other patches

    def patch(self, ctx: InitContext) -> dict:
        self.extract_dir = str(ctx.extracted_fs)
        self.existing = {member.name[1:] for member in ctx.archive_files}
        patches = ctx.patches_snapshot()
        result = defaultdict(dict)

        for f in FileHelper.find_shell_scripts(self.extract_dir, index=ctx.file_index):
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^/mnt/[a-zA-Z0-9._/]+$"))
            ):
                if not dest.endswith("/"):
                    dest = os.path.dirname(dest)
                    # We're making the directory in which the file we saw referenced
                    # will be

                # Does this file exist in the filesystem or in any existing patches?
                if dest in self.existing:
                    continue
                if any([dest in p[0].get('static_files', {}).keys() for p in patches.values()]):
                    continue

                # Try resolving the dest (to handle symlinks more correctly than the existing check)
                if FileHelper.exists(self.extract_dir, dest):
                    # Directory already exists - don't clobber!
                    continue

                result['static_files'][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result


class GenerateMissingFiles(InitPlugin):
    '''
    Ensure we have /bin/sh, /etc/TZ, /var/run/nvramd.pid, and localhost in /etc/hosts.
    '''
    patch_name = "static.missing_files"
    order = 180

    def patch(self, ctx: InitContext) -> dict:
        self.extract_dir = str(ctx.extracted_fs)
        # Firmadyne/FirmAE mitigation, ensure these 3 files always exist
        # Note including /bin/sh here means we'll add it if it's missing and as a symlink to /igloo/utils/busybox
        # this is similar to how we can shim an (existing) /bin/sh to point to /igloo/utils/busybox but here we
        # only add it if it's missing
        result = defaultdict(dict)

        model = {
            # Ensure /bin/sh exists if not already present
            "/bin/sh": {
                "type": "symlink",
                "target": "/igloo/utils/busybox"
            },

            # Set timezone to EST
            "/etc/TZ": {
                "type": "inline_file",
                "contents": "EST5EDT",
                "mode": 0o755,
            },

            # Needed for Ralink and D-Link
            # See https://github.com/firmadyne/libnvram/blob/e33692277d475d61a03e0772efeef5c829872f34/nvram.c#L189
            "/var/run/nvramd.pid": {
                "type": "inline_file",
                "contents": "",
                "mode": 0o644,
            },
        }

        for fname, data in model.items():
            if not os.path.isfile(os.path.join(self.extract_dir, fname[1:])):
                result['static_files'][fname] = data

        # Ensure we have an entry for localhost in /etc/hosts. So long as we have an /etc/ directory
        hosts = ""
        if os.path.isfile(os.path.join(self.extract_dir, "etc/hosts")):
            with open(os.path.join(self.extract_dir, "etc/hosts"), "r") as f:
                hosts = f.read()

        # if '127.0.0.1 localhost' not in hosts:
        # Regex with whitespace and newlines
        if not re.search(r"^127\.0\.0\.1\s+localhost\s*$", hosts, re.MULTILINE):
            if len(hosts) and not hosts.endswith("\n"):
                hosts += "\n"
            hosts += "127.0.0.1 localhost\n"

            result["static_files"]["/etc/hosts"] = {
                "type": "inline_file",
                "contents": hosts,
                "mode": 0o755,
            }
        return result


class DeleteFiles(InitPlugin):
    '''
    Delete some files we don't want.
    '''
    patch_name = "static.delete_files"
    order = 190

    def patch(self, ctx: InitContext) -> dict:
        self.extract_dir = str(ctx.extracted_fs)
        result = defaultdict(dict)
        # Delete some files that we don't want. securetty is general, limits shell access.
        # 'sys_resetbutton' is some FW-specific hack from FirmAE

        # TODO: does securetty matter if our root shell is disabled?
        for f in ["/etc/securetty", "/etc/scripts/sys_resetbutton"]:
            if os.path.isfile(os.path.join(self.extract_dir, f[1:])):
                result["static_files"][f] = {
                    "type": "delete",
                }
        return result
