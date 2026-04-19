from penguin.static_plugin import ConfigPatcherPlugin

class NvramConfigRecoveryWild(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "nvram.03_config_paths_basename"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        from .nvram_helper import NvramHelper
        result = NvramHelper.nvram_config_analysis(self.extracted_fs, False)
        if len(result):
            return {'nvram': result}
