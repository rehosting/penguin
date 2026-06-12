"""
lib_inject patches: libc symlinks by ABI and shim aliases driven by exported
library symbols.
"""

import os

from collections import defaultdict
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from penguin import getColoredLogger
from penguin.arch import arch_filter
from penguin.defaults import (
    default_lib_aliases,
    default_libinject_string_introspection,
)
from penguin.init_plugin import InitContext, InitPlugin

logger = getColoredLogger("penguin.init.lib_inject")


class LibInjectSymlinks(InitPlugin):
    '''
    Detect the ABI of all libc.so files and place a symlink in the same
    directory to lib_inject of the same ABI.
    '''
    patch_name = 'lib_inject.core'
    order = 100

    def patch(self, ctx: InitContext) -> dict:
        self.filesystem_root_path = str(ctx.extracted_fs)
        libc_paths = []
        result = defaultdict(dict)

        # Find all "libc.so" files in the shared file index
        for entry in ctx.file_index.entries:
            if entry.name.startswith("libc.so"):
                libc_paths.append(Path(entry.path))

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


class LibInjectStringIntrospection(InitPlugin):
    '''
    Add LibInject aliases for string introspection (e.g., for comparison detection).
    For each method we see in the filesystem that's in our list of shim targets, add the shim
    '''
    patch_name = 'lib_inject.string_introspection'
    order = 110

    def patch(self, ctx: InitContext) -> dict:
        library_info = self.plugins.LibrarySymbols.library_info
        aliases = {}
        for _, exported_syms in library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_libinject_string_introspection:
                    aliases[sym] = default_libinject_string_introspection[sym]

        return {'lib_inject': {'aliases': aliases}}


class LibInjectTailoredAliases(InitPlugin):
    '''
    Set default aliases in libinject based on library analysis. If one of the defaults
    is present in a library, we'll add it to the libinject alias list
    '''
    patch_name = 'lib_inject.dynamic_models'
    order = 120

    def patch(self, ctx: InitContext) -> dict | None:
        library_info = self.plugins.LibrarySymbols.library_info
        self.unmodeled = set()
        aliases = {}

        # Only copy values from our defaults if we see that same symbol exported
        for _, exported_syms in library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_lib_aliases:
                    aliases[sym] = default_lib_aliases[sym]
                elif "nvram" in sym and sym not in self.unmodeled:
                    self.unmodeled.add(sym)

        if len(self.unmodeled):
            logger.info(f"Detected {len(self.unmodeled)} unmodeled symbols around nvram. You may wish to create libinject models for these:")
            for sym in self.unmodeled:
                logger.info(f"\t{sym}")

        if len(aliases):
            return {'lib_inject': {'aliases': aliases}}


class LibInjectFixedAliases(InitPlugin):
    '''
    Set all aliases in libinject from our defaults.
    '''
    patch_name = 'lib_inject.fixed_models'
    order = 130
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
        return {'lib_inject': {'aliases': default_lib_aliases}}
