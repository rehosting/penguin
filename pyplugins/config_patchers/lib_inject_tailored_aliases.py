from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import default_lib_aliases
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class LibInjectTailoredAliases(ConfigPatcherPlugin):
    depends_on = ['LibrarySymbols']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = 'lib_inject.dynamic_models'
        self.unmodeled = set()

    def generate(self, patches: dict) -> dict | None:
        library_info = self.prior_results.get('LibrarySymbols', {})
        aliases = {}

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
