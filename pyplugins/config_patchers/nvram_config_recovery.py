from penguin.static_plugin import ConfigPatcherPlugin

class NvramConfigRecovery(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "nvram.02_config_paths"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        from .nvram_helper import NvramHelper
        result = NvramHelper.nvram_config_analysis(self.extracted_fs, True)
        if len(result):
            return {'nvram': result}
