from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import default_lib_aliases
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class LibInjectJITAliases(ConfigPatcherPlugin):
    depends_on = ['LibrarySymbols']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = 'lib_inject.jit_models'

    def generate(self, patches: dict) -> dict | None:
        library_info = self.prior_results.get('LibrarySymbols', {})
        aliases = {}

        for _, exported_syms in library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if "nvram" in sym and sym not in default_lib_aliases:
                    if "_get" in sym:
                        target = "libinject_nvram_get"
                    elif "_set" in sym:
                        target = "libinject_nvram_get"
                    else:
                        target = "libinject_ret_0"
                    aliases[sym] = target
                    logger.info(f"\tJIT mapping {sym} -> {target}")

        if len(aliases):
            return {'lib_inject': {'aliases': aliases}}
