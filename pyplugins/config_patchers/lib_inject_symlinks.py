import os
from collections import defaultdict
from pathlib import Path
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from penguin.arch import arch_filter
from penguin.static_plugin import ConfigPatcherPlugin

class LibInjectSymlinks(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = 'lib_inject.core'

    def generate(self, patches: dict) -> dict:
        libc_paths = []
        result = defaultdict(dict)

        for root, dirs, files in os.walk(self.extracted_fs):
            for filename in files:
                if filename.startswith("libc.so"):
                    libc_paths.append(Path(os.path.join(root, filename)))

        for p in libc_paths:
            if not os.path.isfile(p) or (os.path.islink(p) and not os.path.exists(p)):
                continue

            with open(p, 'rb') as file:
                try:
                    e = ELFFile(file)
                except ELFError:
                    continue

                abi = arch_filter(e).abi

            dest = Path("/") / \
                p.relative_to(self.extracted_fs).parent / \
                "lib_inject.so"

            result["static_files"][str(dest)] = {
                "type": "symlink",
                "target": f"/igloo/lib_inject_{abi}.so",
            }

        if len(result.get("static_files", [])):
            result["env"] = {"LD_PRELOAD": "lib_inject.so"}

        return result
