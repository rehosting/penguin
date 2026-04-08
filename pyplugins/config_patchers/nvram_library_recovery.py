from penguin.static_plugin import ConfigPatcherPlugin

class NvramLibraryRecovery(ConfigPatcherPlugin):
    depends_on = ['LibrarySymbols']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "nvram.01_library"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        library_info = self.prior_results.get('LibrarySymbols', {})
        sources = library_info.get("nvram", {})
        if not len(sources):
            return

        sorted_sources = sorted(sources.items(), key=lambda x: len(x[1]), reverse=True)

        nvram_defaults = {}
        for source, nvram in sorted_sources:
            for key, value in nvram.items():
                if key not in nvram_defaults:
                    nvram_defaults[key] = value

        if len(nvram_defaults):
            return {'nvram': nvram_defaults}
