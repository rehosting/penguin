from . import PatchGenerator

class NvramLibraryRecovery(PatchGenerator):
    '''
    During static analysis the LibrarySymbols class collected
    key->value mappings from libraries exporting some common nvram
    defaults symbols ("Nvrams", "router_defaults") - add these to our
    nvram config if we have any.

    TODO: if we find multiple nvram source files here, we should generate multiple patches.
    Then we should consider these during search. For now we just take non-conflicting values
    from largest to smallest source files. More realistic might be to try each file individually.
    '''

    def __init__(self, library_info):
        self.library_info = library_info
        self.patch_name = "nvram.01_library"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        sources = self.library_info.get("nvram", {})
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
