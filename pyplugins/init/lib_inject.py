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
    atheros_broadcom,
    default_lib_aliases,
    default_libinject_string_introspection,
    generic_lib_aliases,
    ralink,
    realtek,
    zyxel_or_edimax,
)
from penguin.init_plugin import InitContext, InitPlugin

logger = getColoredLogger("penguin.init.lib_inject")


def _exported_alias_subset(library_info: dict, table: dict[str, str]) -> dict[str, str]:
    """
    The subset of ``table`` whose symbols the target actually exports (per
    LibrarySymbols) -- the same exported-symbol filter the tailored-alias patch
    applies, factored out for reuse by the per-SDK patches.
    """
    aliases: dict[str, str] = {}
    for _, exported_syms in library_info.get("symbols", {}).items():
        for sym in exported_syms:
            if sym in table:
                aliases[sym] = table[sym]
    return aliases


def _sdk_alias_patch(plugin: InitPlugin, table: dict[str, str]) -> dict | None:
    """
    Body shared by the per-SDK alias patches: the SDK group's aliases
    intersected with the target's exported symbols, wrapped as a lib_inject
    patch -- or ``None`` when the target exports none of them, so the candidate
    only materializes for plausibly-relevant targets.
    """
    aliases = _exported_alias_subset(plugin.plugins.LibrarySymbols.library_info, table)
    return {'lib_inject': {'aliases': aliases}} if aliases else None


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
    Set generic (non-SDK) libinject aliases based on library analysis. If one of
    the generic defaults is present in a library, we'll add it to the libinject
    alias list. SDK-specific alias groups are handled separately, as disabled
    per-SDK candidate patches (see the Sdk*Aliases classes below).
    '''
    patch_name = 'lib_inject.dynamic_models'
    order = 120

    def patch(self, ctx: InitContext) -> dict | None:
        library_info = self.plugins.LibrarySymbols.library_info
        self.unmodeled = set()
        aliases = {}

        # Only copy values from our generic defaults if we see that same symbol
        # exported. A symbol that is modeled only in an SDK group is neither
        # emitted here (it lives in a disabled per-SDK candidate) nor flagged as
        # unmodeled -- hence the unmodeled check is against the full union.
        for _, exported_syms in library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in generic_lib_aliases:
                    aliases[sym] = generic_lib_aliases[sym]
                elif "nvram" in sym and sym not in default_lib_aliases \
                        and sym not in self.unmodeled:
                    self.unmodeled.add(sym)

        if len(self.unmodeled):
            logger.info(f"Detected {len(self.unmodeled)} unmodeled symbols around nvram. You may wish to create libinject models for these:")
            for sym in self.unmodeled:
                logger.info(f"\t{sym}")

        if len(aliases):
            return {'lib_inject': {'aliases': aliases}}


# Per-SDK lib_inject alias candidates. Each SDK's alias group is emitted as its
# own named patch, DISABLED by default: a profile bundle is a candidate in the
# config search (a togglable vertex), not a fact baked into the initial config.
# The bundle only materializes when the target exports the SDK's symbols.

class SdkAtherosBroadcomAliases(InitPlugin):
    '''Atheros/Broadcom SDK nvram shims (nvram_nget/nvram_nset/...).'''
    patch_name = 'sdk.atheros_broadcom'
    order = 125
    enabled = False

    def patch(self, ctx: InitContext) -> dict | None:
        return _sdk_alias_patch(self, atheros_broadcom)


class SdkRealtekAliases(InitPlugin):
    '''Realtek RTL819x SDK apmib shims (apmib_get/apmib_set).'''
    patch_name = 'sdk.realtek'
    order = 125
    enabled = False

    def patch(self, ctx: InitContext) -> dict | None:
        return _sdk_alias_patch(self, realtek)


# NOTE: Netgear ACOS graduated from a bare alias group into a full SDK profile
# (pyplugins/init/profiles/netgear_acos.yaml + NetgearAcosProfile), which owns
# the sdk.netgear_acos patch and carries the WAN_ith_CONFIG_GET alias in its
# bundle alongside the ACOS nvram defaults. Hence no SdkNetgearAcosAliases here.


class SdkZyxelOrEdimaxAliases(InitPlugin):
    '''Zyxel/Edimax SDK nvram/envram shims (nvram_*_adv, envram_*).'''
    patch_name = 'sdk.zyxel_or_edimax'
    order = 125
    enabled = False

    def patch(self, ctx: InitContext) -> dict | None:
        return _sdk_alias_patch(self, zyxel_or_edimax)


class SdkRalinkAliases(InitPlugin):
    '''Ralink/MediaTek APSoC SDK nvram shims (nvram_bufget/nvram_bufset).'''
    patch_name = 'sdk.ralink'
    order = 125
    enabled = False

    def patch(self, ctx: InitContext) -> dict | None:
        return _sdk_alias_patch(self, ralink)


class LibInjectFixedAliases(InitPlugin):
    '''
    Set all aliases in libinject from our defaults.
    '''
    patch_name = 'lib_inject.fixed_models'
    order = 130
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
        return {'lib_inject': {'aliases': default_lib_aliases}}
