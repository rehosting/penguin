from collections import defaultdict
import os
import stat
from penguin import getColoredLogger
logger = getColoredLogger("penguin.config_patchers")

class ShimBinaries:
    '''
    Identify binaries in the guest FS that we want to shim
    and add symlinks to go from guest bin -> igloo bin
    into our config.
    '''

    def __init__(self, files):
        self.files = files

    def make_shims(self, shim_targets: dict[str, str]) -> dict:
        result = defaultdict(dict)
        for fname in self.files:
            path = fname.path.lstrip('.')  # Trim leading .
            basename = os.path.basename(path)

            if path.startswith("/igloo/utils/"):
                raise ValueError(
                    "Unexpected /igloo/utils present in input filesystem archive"
                )

            # It's a guest file/symlink. If it's one of our targets and executable, we want to shim!
            if not (fname.isfile() or fname.issym()) or not fname.mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                # Skip if it's not a file or non-executable
                continue

            # Is the current file one we want to shim?
            if basename in shim_targets:
                logger.debug(f"making shim for {basename}, full path: {path}, fname.path: {fname.path}")
                result["static_files"][path] = {
                    "type": "shim",
                    "target": f"/igloo/utils/{shim_targets[basename]}",
                }
        return result
