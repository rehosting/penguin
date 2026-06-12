"""
NVRAM default-value patches: recovered from libraries, config files, and
Firmadyne/FirmAE expert defaults.
"""

import os

from penguin import getColoredLogger
from penguin.config_patchers import NvramHelper
from penguin.init_plugin import InitContext, InitPlugin

logger = getColoredLogger("penguin.init.nvram")


class NvramLibraryRecovery(InitPlugin):
    '''
    During static analysis the LibrarySymbols class collected
    key->value mappings from libraries exporting some common nvram
    defaults symbols ("Nvrams", "router_defaults") - add these to our
    nvram config if we have any.

    TODO: if we find multiple nvram source files here, we should generate multiple patches.
    Then we should consider these during search. For now we just take non-conflicting values
    from largest to smallest source files. More realistic might be to try each file individually.
    '''
    patch_name = "nvram.01_library"
    order = 300

    def patch(self, ctx: InitContext) -> dict | None:
        sources = self.plugins.LibrarySymbols.library_info.get("nvram", {})
        if not len(sources):
            return

        # Sources is source filename -> key -> value
        # First we want to sort sources from most to least keys
        sorted_sources = sorted(sources.items(), key=lambda x: len(x[1]), reverse=True)

        nvram_defaults = {}
        for source, nvram in sorted_sources:
            for key, value in nvram.items():
                if key not in nvram_defaults:
                    nvram_defaults[key] = value

        if len(nvram_defaults):
            return {'nvram': nvram_defaults}


class NvramConfigRecovery(InitPlugin):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults
    """
    patch_name = "nvram.02_config_paths"
    order = 290

    def patch(self, ctx: InitContext) -> dict | None:
        result = NvramHelper.nvram_config_analysis(str(ctx.extracted_fs), True)
        if len(result):
            return {'nvram': result}


class NvramConfigRecoveryWild(InitPlugin):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults.
    This version relaxes the search to allow for basename matches instead of full path
    matches.
    """
    patch_name = "nvram.03_config_paths_basename"
    order = 280

    def patch(self, ctx: InitContext) -> dict | None:
        result = NvramHelper.nvram_config_analysis(
            str(ctx.extracted_fs), False, index=ctx.file_index
        )
        if len(result):
            return {'nvram': result}


class NvramDefaults(InitPlugin):
    """
    Add default nvram values from Firmadyne and FirmAE
    """
    patch_name = "nvram.04_defaults"
    order = 270

    def patch(self, ctx: InitContext) -> dict | None:
        result = NvramHelper._get_default_nvram_values()
        if len(result):
            return {'nvram': result}


class NvramFirmAEFileSpecific(InitPlugin):
    """
    Apply FW-specific nvram patches based on presence of hardcoded strings in files from FirmAE.
    """
    FIRMAE_TARGETS: dict[str, list[tuple[str, str]]] = {
        "./sbin/rc": [("ipv6_6to4_lan_ip", "2002:7f00:0001::")],
        "./lib/libacos_shared.so": [("time_zone_x", "0")],
        "./sbin/acos_service": [("rip_enable", "0")],
        "./usr/sbin/httpd": [
            ("rip_multicast", "0"),
            ("bs_trustedip_enable", "0"),
            ("filter_rule_tbl", ""),
        ],
    }

    patch_name = "nvram.05_firmae_file_specific"
    order = 260

    def patch(self, ctx: InitContext) -> dict | None:
        self.fs_path = str(ctx.extracted_fs)
        result = {}

        # For each key in static_targets, check if the query is in the file
        # TODO: Should we be operating on an archive to better handle symlinks?
        for key, queries in self.FIRMAE_TARGETS.items():
            if not os.path.isfile(os.path.join(self.fs_path, key[1:])):
                continue

            try:
                with open(os.path.join(self.fs_path, key[1:]), "rb") as f:
                    for query, _ in queries:
                        # Check if query is in file
                        if query.encode() in f.read():
                            result[key] = query
            except Exception as e:
                # Not sure what kind of errors we could encounter here, missing files? perms?
                logger.error(f"Failed to read {key} for nvram key check: {e}")

        if len(result):
            return {'nvram': result}
