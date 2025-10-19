from . import PatchGenerator
import os
from collections import defaultdict
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from penguin.arch import arch_filter

class LibInjectSymlinks(PatchGenerator):
    '''
    Detect the ABI of all libc.so files and place a symlink in the same
    directory to lib_inject of the same ABI.
    '''
    def __init__(self, filesystem_root_path: str) -> None:
        self.enabled = True
        self.patch_name = 'lib_inject.core'
        self.filesystem_root_path = filesystem_root_path

    def generate(self, patches: dict) -> dict:
        libc_paths = []
        result = defaultdict(dict)

        # Walk through the filesystem root to find all "libc.so" files
        for root, dirs, files in os.walk(self.filesystem_root_path):
            for filename in files:
                if filename.startswith("libc.so"):
                    libc_paths.append(Path(os.path.join(root, filename)))

        # Iterate over the found libc.so files to generate symlinks based on ABI
        for p in libc_paths:
            if not os.path.isfile(p) or (os.path.islink(p) and not os.path.exists(p)):
                # Skip broken symlinks
                continue

            with open(p, 'rb') as file:
                try:
                    e = ELFFile(file)
                except ELFError:
                    # Not an ELF. It could be, for example, a GNU ld script.
                    continue

                # Assume `arch_filter` is a function that extracts the ABI from an ELF file.
                abi = arch_filter(e).abi

            # Ensure dest starts with a /
            dest = Path("/") / \
                p.relative_to(self.filesystem_root_path).parent / \
                "lib_inject.so"

            result["static_files"][str(dest)] = {
                "type": "symlink",
                "target": f"/igloo/lib_inject_{abi}.so",
            }

        if len(result.get("static_files", [])):
            # LD_PRELOAD if we set any symlinks
            result["env"] = {"LD_PRELOAD": "lib_inject.so"}

        return result
