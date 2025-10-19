from .patch_generator import PatchGenerator
from .nvram_helper import NvramHelper

class NvramConfigRecovery(PatchGenerator):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults
    """
    def __init__(self, extract_dir: str) -> None:
        self.extract_dir = extract_dir
        self.patch_name = "nvram.02_config_paths"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        result = NvramHelper.nvram_config_analysis(self.extract_dir, True)
        if len(result):
            return {'nvram': result}
