import os
import stat
from collections import defaultdict
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class ShimBinaries:
    def __init__(self, files):
        self.files = files

    def make_shims(self, shim_targets: dict[str, str]) -> dict:
        result = defaultdict(dict)
        for fname in self.files:
            path = fname.name[1:] #.path.lstrip('.')
            basename = os.path.basename(path)

            if path.startswith("/igloo/utils/"):
                raise ValueError(
                    "Unexpected /igloo/utils present in input filesystem archive"
                )

            if not (fname.isfile() or fname.issym()) or not fname.mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                continue

            if basename in shim_targets:
                logger.debug(f"making shim for {basename}, full path: {path}")
                result["static_files"][path] = {
                    "type": "shim",
                    "target": f"/igloo/utils/{shim_targets[basename]}",
                }
        return result
