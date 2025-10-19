from . import PatchGenerator
from penguin.defaults import default_lib_aliases
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers.libinject_tailored_aliases")

class LibInjectTailoredAliases(PatchGenerator):
    '''
    Set default aliases in libinject based on library analysis. If one of the defaults
    is present in a library, we'll add it to the libinject alias list
    '''

    def __init__(self, library_info: dict) -> None:
        self.enabled = True
        self.patch_name = 'lib_inject.dynamic_models'
        self.library_info = library_info
        self.unmodeled = set()

    def generate(self, patches: dict) -> dict | None:
        aliases = {}

        # Only copy values from our defaults if we see that same symbol exported
        for _, exported_syms in self.library_info.get("symbols", {}).items():
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
