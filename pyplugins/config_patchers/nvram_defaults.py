from penguin.static_plugin import ConfigPatcherPlugin

class NvramDefaults(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "nvram.04_defaults"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        from .nvram_helper import NvramHelper
        result = NvramHelper._get_default_nvram_values()
        if len(result):
            return {'nvram': result}
